import { createHash } from "node:crypto";
import { appendFile, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { readFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";

import { canonicalize } from "../../src/core";
import { PACKAGE_NAME } from "./package-stage.mjs";
import { buildReport, sanitize } from "./report.mjs";
import { runMatrix } from "./runner.mjs";
import { DEFAULT_IO, countingListener, createRuntimeDeps, v1ConfigPreload } from "./runtime.mjs";

// Composition tests for the real runtime wiring with every external boundary
// faked: no process is spawned, no socket is opened, no host or provider runs.

const created: string[] = [];
afterEach(async () => {
  for (const dir of created.splice(0)) await rm(dir, { recursive: true, force: true });
});
const sha = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
const PASSWORD = `rh-${"A".repeat(43)}`;
const CHALLENGE = 'Basic realm="Secure Area"';
const BASIC = `Basic ${Buffer.from(`opencode:${PASSWORD}`).toString("base64")}`;

function npmTarball(): Buffer {
  const files: Record<string, string> = { "package.json": JSON.stringify({ name: PACKAGE_NAME, version: "0.1.0" }), "dist/index.js": "export default {};\n" };
  const parts: Buffer[] = [];
  for (const [name, text] of Object.entries(files)) {
    const data = Buffer.from(text);
    const h = Buffer.alloc(512);
    h.write(`package/${name}`, 0, 100);
    h.write("0000644\0", 100);
    h.write(data.length.toString(8).padStart(11, "0") + "\0", 124);
    h.write("        ", 148);
    h.write("0", 156);
    h.write("ustar\0", 257);
    h.write("00", 263);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    parts.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

type Launch = { role: string; argv: string[]; env: Record<string, string>; cwd: string; pgid: number };
type Options = {
  family?: "v1" | "v2";
  version?: string;
  versionStdout?: string;
  versionExit?: number;
  versionHang?: boolean;
  versionSpawnError?: boolean;
  providerToken?: (real: string) => string;
  hostHandler?: (url: URL, init: { headers?: Record<string, string> }) => Response | Promise<Response>;
  stopResult?: (role: string) => Record<string, unknown>;
  probe?: (argv: string[], context: { providerToken: string }) => string;
  registryConnections?: number;
  timing?: Record<string, number>;
  simulate?: boolean;
  packageSpec?: { name: string; version: string; spec: string };
  gates?: { allocate?: Promise<unknown>; providerPort?: Promise<unknown>; identity?: Promise<unknown> };
  onListen?: (args: unknown[]) => void;
  machServices?: string[];
  /**
   * Use the short synthetic canary root SYNTHETIC_CANARY_ROOT so the actual canary socket path
   * passes the (still enabled) Darwin 103-byte guard. Its directory operations go through the
   * injected io.canaryFs seam and are redirected into an owned backing directory inside the
   * launcher-isolated root; nothing is created at the synthetic path itself.
   */
  shortCanary?: boolean;
  /** Make one listen call fail (returns the error to throw), to exercise partial acquisition. */
  listenFailure?: (args: unknown[]) => Error | undefined;
  /** Per-listener close behavior; the returned promise is the close confirmation. */
  closeBehavior?: (args: unknown[]) => Promise<void> | void;
  /** The provider never writes its port file (startup timeout). */
  providerNeverReady?: boolean;
  /** The provider's owned launcher exits at once with this result, without writing its port file. */
  providerExit?: { code: number | null; signal: string | null };
  /** The provider spawn rejects with this error (nothing is acquired). */
  providerSpawnError?: Error;
  /** Wraps the provider's owned handle (for example to make evidence recording fail). */
  providerHandle?: (handle: Record<string, unknown>) => Record<string, unknown>;
  /** Makes stopGroup reject for a role. */
  stopReject?: (role: string) => Error | undefined;
  /** Replaces the raw stopGroup result for a role. */
  stopResultRaw?: (role: string, base: Record<string, unknown>) => unknown;
};

const SYNTHETIC_CANARY_ROOT = "/fixture/c";

/**
 * Canary filesystem seam for the synthetic root: only paths at or under SYNTHETIC_CANARY_ROOT are
 * accepted, and each is redirected to the same relative path under `backing` (an owned directory
 * inside the isolated root). Any other path is refused, so nothing reaches the real /fixture.
 */
function redirectedCanaryFs(backing: string) {
  const ops: Array<[string, string]> = [];
  const toBacking = (path: string) => {
    if (path !== SYNTHETIC_CANARY_ROOT && !path.startsWith(`${SYNTHETIC_CANARY_ROOT}/`)) throw new Error(`canary fs refused a path outside the synthetic root: ${path}`);
    return join(backing, path.slice(SYNTHETIC_CANARY_ROOT.length));
  };
  const fs = {
    mkdtemp: async (prefix: string) => {
      ops.push(["mkdtemp", prefix]);
      const real = await mkdtemp(toBacking(prefix));
      return join(SYNTHETIC_CANARY_ROOT, relative(backing, real));
    },
    writeFile: async (path: string, data: string) => {
      ops.push(["writeFile", path]);
      await writeFile(toBacking(path), data);
    },
    rm: async (path: string, options: { recursive?: boolean; force?: boolean }) => {
      ops.push(["rm", path]);
      await rm(toBacking(path), options);
    },
  };
  return { ops, fs };
}

async function harness(opts: Options = {}) {
  const base = await realpath(await mkdtemp(join(tmpdir(), "rh-runtime-")));
  created.push(base);
  const staging = join(base, "staging");
  await mkdir(staging);
  const tarball = npmTarball();
  await writeFile(join(staging, "pkg.tgz"), tarball);
  await writeFile(join(staging, "node"), "node");
  await writeFile(join(staging, "opencode"), "binary");
  const family = opts.family ?? "v1";
  const id = family === "v2" ? "v2" : "v1-floor";
  const version = family === "v2" ? "2.0.28" : "1.18.29";
  const canaryBacking = join(base, "canary-backing");
  const canary = opts.shortCanary ? redirectedCanaryFs(canaryBacking) : null;
  const manifest = {
    runRoot: join(base, "runs"),
    canaryRoot: opts.shortCanary ? SYNTHETIC_CANARY_ROOT : join(base, "canary"),
    tarball: { path: join(staging, "pkg.tgz"), sha256: sha(tarball) },
    sandbox: { machServices: opts.machServices ?? [] },
    reviewedContracts: { "hosts.versionArgv": { review: "r", value: ["--version"] } },
    v2: { providers: { fake: { baseURL: "{providerBaseURL}" } }, model: "fake/fake-model", dependencyRegions: ["cache/opencode/npm"] },
    rows: [{ id, cache: family === "v2" ? { root: "{XDG_CACHE_HOME}/opencode", specDir: `${PACKAGE_NAME}@0.1.0`, generation: "0" } : { root: "{XDG_CACHE_HOME}/opencode", specDir: `${PACKAGE_NAME}@latest` } }],
  };
  await mkdir(opts.shortCanary ? canaryBacking : manifest.canaryRoot);
  const verified = {
    node: { path: join(staging, "node") },
    packageSpec: opts.packageSpec ?? { name: PACKAGE_NAME, version: "0.1.0", spec: `${PACKAGE_NAME}@0.1.0` },
    rows: [{ id, binary: { path: join(staging, "opencode") } }],
    roots: { runRoot: manifest.runRoot, canaryRoot: manifest.canaryRoot },
  };

  const launches: Launch[] = [];
  const stops: Array<{ role: string; pgid: number }> = [];
  const requests: Array<{ url: string; auth: string | undefined; method: string; redirect?: string }> = [];
  const lineage: number[][] = [];
  const listeners: Array<{ args: unknown[]; closes: number }> = [];
  let next = 100;
  const roleOf = (argv: string[]) =>
    argv.some((a) => a.endsWith("fake-provider.mjs")) ? "provider" : argv.some((a) => a.endsWith("probe.mjs")) ? "probe" : argv.includes("--version") ? "version" : "host";
  const roles = new Map<number, string>();
  const providerConfigs: string[] = [];
  const providerTokens: string[] = [];

  const supervisor = {
    async spawnOwned(command: string, args: string[], options: { env: Record<string, string>; cwd: string; stdio: unknown[] }) {
      const argv = [command, ...args];
      const role = roleOf(argv);
      if (role === "version" && opts.versionSpawnError) throw Object.assign(new Error(`spawn ${command} ENOENT`), { code: "ENOENT" });
      if (role === "provider" && opts.providerSpawnError) throw opts.providerSpawnError;
      const pgid = (next += 1);
      roles.set(pgid, role);
      launches.push({ role, argv, env: options.env, cwd: options.cwd, pgid });
      if (role === "provider") {
        providerConfigs.push(args[args.indexOf("--config") + 1]);
        providerTokens.push(JSON.parse(readFileSync(providerConfigs.at(-1)!, "utf8")).identityToken);
        const portFile = args[args.indexOf("--port-file") + 1];
        if (opts.providerNeverReady || opts.providerExit) {
          // no port file: the provider never reports readiness
        } else if (opts.gates?.providerPort) void opts.gates.providerPort.then(() => writeFile(portFile, "41000"));
        else await writeFile(portFile, "41000");
      }
      if (role === "probe") {
        const providerToken = providerConfigs.length > 0 ? JSON.parse(readFileSync(providerConfigs.at(-1)!, "utf8")).identityToken : "";
        writeSync(options.stdio[1] as number, opts.probe ? opts.probe(argv, { providerToken }) : JSON.stringify({ completed: true, op: argv.at(-2), outcome: "allowed" }));
      }
      if (role === "version") writeSync(options.stdio[1] as number, opts.versionStdout ?? (family === "v2" ? `opencode v${opts.version ?? version}\n` : `${opts.version ?? version}\n`));
      const exited =
        role === "probe"
          ? Promise.resolve({ code: 0, signal: null })
          : role === "version" && !opts.versionHang
            ? Promise.resolve({ code: opts.versionExit ?? 0, signal: null })
            : role === "provider" && opts.providerExit
              ? Promise.resolve(opts.providerExit)
              : new Promise(() => {});
      const handle = { pid: pgid, pgid, child: null, exited };
      return role === "provider" && opts.providerHandle ? opts.providerHandle(handle) : handle;
    },
    async stopGroup(pgid: number) {
      const role = roles.get(pgid)!;
      stops.push({ role, pgid });
      const rejection = opts.stopReject?.(role);
      if (rejection) throw rejection;
      const base = { pgid, termSent: true, killSent: false, aliveAfter: false, unsafe: false, ...(opts.stopResult?.(role) ?? {}) };
      return opts.stopResultRaw ? opts.stopResultRaw(role, base) : base;
    },
    async stopAll() {
      return [];
    },
    async removeRootIfSafe(root: string, { lineagePids }: { lineagePids: () => Promise<number[]> }) {
      lineage.push(await lineagePids());
      await rm(root, { recursive: true, force: true });
    },
  };

  let ports = 41000;
  let token = 0;
  const io = {
    allocatePort: async () => {
      if (opts.gates?.allocate) await opts.gates.allocate;
      return (ports += 1);
    },
    listen: async (args: unknown[]) => {
      const failure = opts.listenFailure?.(args);
      if (failure) throw failure;
      const entry = {
        args,
        closes: 0,
        close() {
          entry.closes += 1;
          return opts.closeBehavior?.(args);
        },
        state: { connections: args[0] === 41003 ? (opts.registryConnections ?? 0) : 0 },
        address: { port: 50000 + (ports += 1) },
      };
      listeners.push(entry);
      opts.onListen?.(args);
      return entry;
    },
    randomToken: () => `tok${String((token += 1)).padStart(9, "0")}`,
    generatePassword: () => PASSWORD,
    ...(canary ? { canaryFs: canary.fs } : {}),
    transport: async (url: string, init: { method: string; headers?: Record<string, string>; redirect?: string }) => {
      const parsed = new URL(url);
      requests.push({ url, auth: init.headers?.authorization, method: init.method, redirect: init.redirect });
      if (parsed.pathname === "/__rh/identity") {
        if (opts.gates?.identity) await opts.gates.identity;
        const config = JSON.parse(await readFile(providerConfigs.at(-1)!, "utf8"));
        return new Response(JSON.stringify({ token: opts.providerToken ? opts.providerToken(config.identityToken) : config.identityToken }), { status: 200 });
      }
      if (opts.hostHandler) return opts.hostHandler(parsed, init);
      if (init.headers?.authorization !== BASIC) return new Response(null, { status: 401, headers: { "www-authenticate": CHALLENGE } });
      return new Response("[]", { status: 200 });
    },
  };

  const timing = { startupMs: 300, connectMs: 100, askMs: 50, debugRecordMs: 20, completionMs: 50, settleMs: 1, pollMs: 5, probeMs: 200, inventoryMs: 50, ...(opts.timing ?? {}) };
  const deps = createRuntimeDeps({ manifest, verified, supervisor, realHome: "/Users/someone", timing, io });
  const row = { id, family, version };
  const fixture = await deps.createFixture(row);
  return { deps, row, fixture, launches, stops, requests, lineage, manifest, providerConfigs, listeners, canaryOps: canary?.ops ?? [], canaryBacking, providerTokens };
}

describe("runtime composition: prepare and the offline recipe", () => {
  it("writes fixture commands, the source-derived V1 preload, the registry tripwire, the candidate profile, and stages the package", async () => {
    const { deps, row, fixture } = await harness();
    await deps.prepare(fixture, row);

    const configDir = join(fixture.xdg.XDG_CONFIG_HOME, "opencode");
    for (const [name, text] of Object.entries(v1ConfigPreload("1.18.29"))) expect(await readFile(join(configDir, name), "utf8")).toBe(text);
    expect(JSON.parse(await readFile(join(configDir, "package-lock.json"), "utf8")).packages[""].dependencies).toEqual({ "@opencode-ai/plugin": "1.18.29" });
    expect(await readdir(join(configDir, "node_modules"))).toEqual([]);
    expect(await readFile(join(fixture.home, ".npmrc"), "utf8")).toBe("registry=http://127.0.0.1:41003/\n");
    const profile = await readFile(join(fixture.run, "profile.sb"), "utf8");
    for (const port of [41001, 41002, 41003]) expect(profile).toContain(`localhost:${port}`);
    expect(profile).toMatch(/^\(version 1\)\n\(deny default\)/);
    const execs = [...profile.matchAll(/\(allow process-exec \(literal "([^"]+)"\)\)/g)].map((match) => match[1]);
    expect(execs).toHaveLength(8);
    expect(execs).toEqual(
      expect.arrayContaining([join(fixture.bin, "rh-probe"), join(fixture.bin, "rh-sleep"), "/bin/sh", "/bin/mv", "/bin/sleep", "/bin/bash", expect.stringMatching(/staging\/opencode$/), expect.stringMatching(/staging\/node$/)]),
    );
    expect(profile).not.toMatch(/process-exec[^\n]*subpath/);
    const staged = join(fixture.xdg.XDG_CACHE_HOME, "opencode", "packages", `${PACKAGE_NAME}@latest`, "node_modules", PACKAGE_NAME, "package.json");
    expect(JSON.parse(await readFile(staged, "utf8")).name).toBe(PACKAGE_NAME);
    expect(await deps.tripwire(fixture, row, "prepare")).toMatchObject({ forbidden: [], registryConnections: 0 });
  });

  it("the per-step tripwire compares against an immutable baseline: a mutation stays reported at every later step", async () => {
    const { deps, row, fixture } = await harness();
    await deps.prepare(fixture, row);
    await writeFile(join(fixture.xdg.XDG_CONFIG_HOME, "opencode", "package-lock.json"), "{}");
    await mkdir(join(fixture.xdg.XDG_CONFIG_HOME, "opencode", "node_modules", "left-pad"));
    const first = await deps.tripwire(fixture, row, "pilot-ask-once");
    expect(first.forbidden).toEqual(expect.arrayContaining(["changed xdg/config/opencode/package-lock.json", "added xdg/config/opencode/node_modules/left-pad"]));
    const second = await deps.tripwire(fixture, row, "next");
    expect(second.forbidden).toEqual(first.forbidden);

    const tripped = await harness({ registryConnections: 2 });
    await tripped.deps.prepare(tripped.fixture, tripped.row);
    expect((await tripped.deps.tripwire(tripped.fixture, tripped.row, "prepare")).forbidden.join()).toMatch(/registry tripwire received 2/);
    expect((await tripped.deps.tripwire(tripped.fixture, tripped.row, "later")).forbidden.join()).toMatch(/registry tripwire received 2/);
  });

  it("monitors fixture HOME/.npm, the HOME/.npmrc registry, and the original staged package content", async () => {
    const { deps, row, fixture } = await harness();
    await deps.prepare(fixture, row);
    await mkdir(join(fixture.home, ".npm", "_cacache"), { recursive: true });
    await writeFile(join(fixture.home, ".npmrc"), "registry=https://registry.npmjs.org/\n");
    const stagedFile = join(fixture.xdg.XDG_CACHE_HOME, "opencode", "packages", `${PACKAGE_NAME}@latest`, "node_modules", PACKAGE_NAME, "dist", "index.js");
    await writeFile(stagedFile, "export default { tampered: true };\n");
    const result = await deps.tripwire(fixture, row, "pilot-ask-once");
    expect(result.forbidden).toEqual(
      expect.arrayContaining([
        "added home/.npm",
        "changed home/.npmrc",
        `changed xdg/cache/opencode/packages/${PACKAGE_NAME}@latest/node_modules/${PACKAGE_NAME}/dist/index.js`,
      ]),
    );
  });

  it("allows runtime writes outside dependency regions (database, logs, state)", async () => {
    const { deps, row, fixture } = await harness();
    await deps.prepare(fixture, row);
    await mkdir(join(fixture.xdg.XDG_DATA_HOME, "opencode"), { recursive: true });
    await writeFile(join(fixture.xdg.XDG_DATA_HOME, "opencode", "opencode.db"), "db");
    await mkdir(join(fixture.xdg.XDG_STATE_HOME, "opencode"), { recursive: true });
    await writeFile(join(fixture.xdg.XDG_STATE_HOME, "opencode", "kv.json"), "{}");
    await mkdir(join(fixture.xdg.XDG_CACHE_HOME, "opencode", "log"), { recursive: true });
    await writeFile(join(fixture.xdg.XDG_CACHE_HOME, "opencode", "log", "host.log"), "log");
    await writeFile(join(fixture.logs, "audit.log"), "{}\n");
    expect((await deps.tripwire(fixture, row, "pilot-ask-once")).forbidden).toEqual([]);
    expect(await deps.finalIntegrity(fixture, row)).toMatchObject({ ok: true, problems: [] });
  });
});

describe("runtime composition: final integrity after shutdown", () => {
  it("fails on a mutation that happened after the last step (for example during shutdown)", async () => {
    const { deps, row, fixture } = await harness();
    await deps.prepare(fixture, row);
    expect((await deps.tripwire(fixture, row, "pilot-ask-once")).forbidden).toEqual([]);
    await writeFile(join(fixture.xdg.XDG_CONFIG_HOME, "opencode", "package.json"), "{}");
    const result = await deps.finalIntegrity(fixture, row);
    expect(result.ok).toBe(false);
    expect(result.problems.join()).toMatch(/changed xdg\/config\/opencode\/package\.json/);
  });

  it("fails when the staged package content no longer matches the original tarball", async () => {
    const { deps, row, fixture } = await harness();
    await deps.prepare(fixture, row);
    await rm(join(fixture.xdg.XDG_CACHE_HOME, "opencode", "packages", `${PACKAGE_NAME}@latest`, "node_modules", PACKAGE_NAME, "dist", "index.js"));
    expect((await deps.finalIntegrity(fixture, row)).problems.join()).toMatch(/staged package: missing staged file: dist\/index\.js/);
  });

  it.each([
    ["missing", (path: string) => rm(path)],
    ["corrupt", (path: string) => writeFile(path, "{}")],
  ])("fails (so the root is retained) when the expected baseline evidence is %s", async (_label, damage) => {
    const { deps, row, fixture } = await harness();
    await deps.prepare(fixture, row);
    await damage(join(fixture.evidence, "dependency-baseline.json"));
    const result = await deps.finalIntegrity(fixture, row);
    expect(result.ok).toBe(false);
    expect(result.problems.join()).toMatch(/baseline evidence/);
    await expect(deps.tripwire(fixture, row, "x")).resolves.toMatchObject({ forbidden: [expect.stringMatching(/baseline evidence/)] });
  });

  it("reports an explicit skip (not a pass claim) when prepare never produced a baseline", async () => {
    const { deps, row, fixture } = await harness();
    expect(await deps.finalIntegrity(fixture, row)).toEqual({ ok: true, skipped: "no baseline: prepare did not complete", problems: [] });
  });
});

describe("runtime composition: sandboxed version probe", () => {
  it("runs the reviewed version argv under the sandbox and compares it to the row version", async () => {
    const { deps, row, fixture, launches } = await harness();
    await deps.prepare(fixture, row);
    expect(await deps.versionProbe(fixture, row)).toEqual({ ok: true, expected: "1.18.29\n", observed: "1.18.29\n" });
    const version = launches.find((launch) => launch.role === "version")!;
    expect(version.argv).toEqual(["/usr/bin/sandbox-exec", "-f", join(fixture.run, "profile.sb"), expect.stringMatching(/staging\/opencode$/), "--version"]);
  });

  it("reports a wrong version", async () => {
    const { deps, row, fixture } = await harness({ version: "1.18.34" });
    await deps.prepare(fixture, row);
    expect(await deps.versionProbe(fixture, row)).toMatchObject({ ok: false, observed: "1.18.34\n" });
  });

  it.each([
    ["v1", "1.18.29", true],
    ["v1", "1.18.29\n", true],
    ["v1", "1.18.29\n\n", false],
    ["v1", " 1.18.29\n", false],
    ["v1", "1.18.29 \n", false],
    ["v1", "v1.18.29\n", false],
    ["v1", "1.18.29\nwarning: update available\n", false],
    ["v1", "1.18.290\n", false],
    ["v1", "", false],
    ["v2", "opencode v2.0.28\n", true],
    ["v2", "opencode v2.0.28", true],
    ["v2", "2.0.28\n", false],
    ["v2", "opencode 2.0.28\n", false],
    ["v2", "opencode v2.0.28\r\n", false],
    ["v2", "opencode v2.0.28\nopencode v2.0.28\n", false],
  ] as const)("%s: whole stdout %j accepted = %s (no trim, no first line, no substring)", async (family, stdout, accepted) => {
    const { deps, row, fixture } = await harness({ family, versionStdout: stdout });
    await deps.prepare(fixture, row);
    expect(await deps.versionProbe(fixture, row)).toMatchObject({ ok: accepted });
  });

  it("fails a version probe that times out, after stopping its owned group, even with matching output", async () => {
    const { deps, row, fixture, stops } = await harness({ versionHang: true });
    await deps.prepare(fixture, row);
    const started = Date.now();
    expect(await deps.versionProbe(fixture, row)).toMatchObject({ ok: false, observed: expect.stringMatching(/^\(timeout\) 1\.18\.29\n$/) });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(stops.map((stop) => stop.role)).toEqual(["version"]);
  });

  it("surfaces a version probe spawn error as a failure (never a pass)", async () => {
    const { deps, row, fixture, launches } = await harness({ versionSpawnError: true });
    await deps.prepare(fixture, row);
    await expect(deps.versionProbe(fixture, row)).rejects.toThrow(/ENOENT/);
    expect(launches.filter((launch) => launch.role === "version")).toEqual([]);
  });

  it("fails a version probe that exits nonzero even with matching output", async () => {
    const { deps, row, fixture } = await harness({ versionExit: 1 });
    await deps.prepare(fixture, row);
    expect(await deps.versionProbe(fixture, row)).toMatchObject({ ok: false, observed: expect.stringMatching(/exit 1/) });
  });
});

describe("runtime composition: host launch, identity, and teardown", () => {
  it("launches the host sandboxed with the source-verified argv and a fixture-only password, and verifies the auth challenge before any control request", async () => {
    const { deps, row, fixture, launches, requests, providerTokens } = await harness();
    await deps.prepare(fixture, row);
    // The fake host answers the identity route but its event stream never opens.
    // The fake host's /event answers 200 without SSE events, so the executor never sees server.connected.
    await expect(deps.scenario(fixture, row, "pilot-ask-once")).rejects.toThrow(/event stream did not connect/);
    const host = launches.find((launch) => launch.role === "host")!;
    expect(host.argv).toEqual(["/usr/bin/sandbox-exec", "-f", join(fixture.run, "profile.sb"), expect.stringMatching(/staging\/opencode$/), "serve", "--hostname", "127.0.0.1", "--port", "41002"]);
    expect(host.env.OPENCODE_SERVER_PASSWORD).toBe(PASSWORD);
    expect(host.cwd).toBe(fixture.project);
    const hostRequests = requests.filter((request) => request.url.startsWith("http://127.0.0.1:41002"));
    expect(hostRequests[0]).toMatchObject({ method: "GET", auth: undefined });
    expect(hostRequests[1]).toMatchObject({ method: "GET", auth: BASIC });
    expect(hostRequests.every((request) => request.redirect === "error")).toBe(true);
    expect(hostRequests.some((request) => request.method === "POST")).toBe(false);
    expect(deps.secrets()).toEqual([providerTokens[0], PASSWORD]); // A3: the provider identity token is a redaction secret too
  });

  it("never launches the host when the provider on the port is not this run's instance", async () => {
    const { deps, row, fixture, launches, stops } = await harness({ providerToken: () => "someone-else" });
    await deps.prepare(fixture, row);
    await expect(deps.scenario(fixture, row, "pilot-ask-once")).rejects.toThrow(/provider identity check failed/);
    expect(launches.some((launch) => launch.role === "host")).toBe(false);
    expect(stops.map((stop) => stop.role)).toEqual(["provider"]);
  });

  it("refuses a listener that does not challenge, before sending any control request", async () => {
    const { deps, row, fixture, requests, stops } = await harness({ hostHandler: () => new Response("[]", { status: 200 }) });
    await deps.prepare(fixture, row);
    await expect(deps.scenario(fixture, row, "pilot-ask-once")).rejects.toThrow(/did not challenge/);
    expect(requests.filter((request) => request.url.includes(":41002")).map((request) => request.method)).toEqual(["GET"]);
    expect(stops.map((stop) => stop.role).sort()).toEqual(["host", "provider"]);
  });

  it("bounds a hanging event-stream open", async () => {
    const { deps, row, fixture } = await harness({
      hostHandler: (url, init) =>
        url.pathname === "/event"
          ? new Promise<Response>(() => {})
          : init.headers?.authorization === BASIC
            ? new Response("[]", { status: 200 })
            : new Response(null, { status: 401, headers: { "www-authenticate": CHALLENGE } }),
    });
    await deps.prepare(fixture, row);
    const started = Date.now();
    await expect(deps.scenario(fixture, row, "pilot-ask-once")).rejects.toThrow(/did not open within 100ms/);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("surfaces a host group that survived stop as a teardown failure, keeping the original error", async () => {
    const { deps, row, fixture } = await harness({ hostHandler: () => new Response("[]", { status: 200 }), stopResult: (role) => (role === "host" ? { aliveAfter: true } : {}) });
    await deps.prepare(fixture, row);
    const error = await deps.scenario(fixture, row, "pilot-ask-once").catch((caught: Error & { stage?: string }) => caught);
    expect(error).toMatchObject({ stage: "teardown", message: expect.stringMatching(/did not challenge.*host process group \d+ survived stop/) });
  });

  it("V2: binds the provider template to the allocated port and sets the source-verified config env", async () => {
    const { deps, row, fixture, launches } = await harness({ family: "v2" });
    await deps.prepare(fixture, row);
    await expect(deps.scenario(fixture, row, "pilot-ask-once")).rejects.toThrow(/event stream/);
    const host = launches.find((launch) => launch.role === "host")!;
    expect(host.env).toMatchObject({ OPENCODE_SERVER_PASSWORD: PASSWORD, OPENCODE_CONFIG: join(fixture.root, "config", "opencode.json"), OPENCODE_DISABLE_PROJECT_CONFIG: "1" });
    const config = JSON.parse(await readFile(join(fixture.root, "config", "opencode.json"), "utf8"));
    expect(config.providers).toEqual({ fake: { baseURL: "http://127.0.0.1:41001/v1" } });
    expect(config.permissions[0]).toMatchObject({ action: "shell" });
  });
});

describe("runtime composition: preflight", () => {
  it("backstop: an over-limit actual canary socket path (gate forecast bypassed) is refused before any preflight listener, provider, or probe", async () => {
    // The default harness canary root lives under the isolated temp root, so the actual
    // <canaryRoot>/rh-canary-XXXXXX/forbidden.sock is far over 103 bytes. No gate ran here.
    const { deps, row, fixture, launches, listeners } = await harness();
    await deps.prepare(fixture, row);
    const registryOnly = listeners.map((entry) => entry.args);
    await expect(deps.preflight(fixture, row)).rejects.toThrow(/preflight refused before any listener: canary Unix socket path is \d+ UTF-8 bytes; the Darwin harness limit is 103/);
    expect(listeners.map((entry) => entry.args)).toEqual(registryOnly);
    expect(registryOnly).toEqual([[41003, "127.0.0.1"]]);
    expect(launches).toEqual([]);
  });

  it("probes controls unsandboxed and checks sandboxed, and a probe with no result is infrastructure failure", async () => {
    const { deps, row, fixture, launches } = await harness({
      shortCanary: true,
      probe: (argv, { providerToken }) => {
        const sandboxed = argv[0] === "/usr/bin/sandbox-exec";
        const [op, target] = argv.slice(-2);
        if (sandboxed && target.endsWith("canary-read")) return "";
        if (op === "http-get") return JSON.stringify({ completed: true, op, outcome: "allowed", status: 200, body: JSON.stringify({ token: providerToken }) });
        if (!sandboxed) return JSON.stringify({ completed: true, op, outcome: "allowed" });
        return JSON.stringify(target.includes("canary") || op.startsWith("connect") ? { completed: true, op, outcome: "denied", code: "EPERM" } : { completed: true, op, outcome: "allowed" });
      },
    });
    await deps.prepare(fixture, row);
    const result = await deps.preflight(fixture, row);
    expect(result.ok).toBe(false);
    expect(result.failures).toEqual([expect.stringMatching(/canary-read: probe did not complete \(no probe result\)/)]);
    const probes = launches.filter((launch) => launch.role === "probe");
    expect(probes.filter((launch) => launch.argv[0] === "/usr/bin/sandbox-exec")).toHaveLength(8);
    expect(probes.filter((launch) => launch.argv[0] !== "/usr/bin/sandbox-exec")).toHaveLength(5);
  });
});

describe("runtime composition: evidence and cleanup", () => {
  it("redacts the fixture password from collected evidence and passes recorded pids to the retention gate", async () => {
    const { deps, row, fixture, lineage } = await harness();
    await deps.prepare(fixture, row);
    await deps.scenario(fixture, row, "pilot-ask-once").catch(() => undefined);
    await writeFile(join(fixture.logs, "host.out.log"), `listening; password ${PASSWORD}\n`);
    await writeFile(join(fixture.evidence, "exec", "exec-4242.rec"), `rh-exec-v1\u00004242\u0000${fixture.home}\u0000${fixture.project}\u00001\u0000${fixture.bin}/rh-probe\u0000n\u0000`);
    const collected = await deps.collect(fixture, row);
    expect(collected.files["logs/host.out.log"]).toBe("listening; password [redacted]\n");
    expect(JSON.stringify(collected)).not.toContain(PASSWORD);
    await deps.removeRoot(fixture, row);
    expect(lineage).toEqual([[4242]]);
  });
});

describe("runtime composition: retention lineage source", () => {
  const exists = async (path: string) => readdir(path).then(() => true, () => false);

  it("retains the root when the expected execution record directory is missing after prepare", async () => {
    const { deps, row, fixture, lineage, stops } = await harness();
    await deps.prepare(fixture, row);
    await rm(join(fixture.evidence, "exec"), { recursive: true });
    await expect(deps.removeRoot(fixture, row)).rejects.toThrow(/expected execution record directory .* missing/);
    expect(await exists(fixture.root)).toBe(true);
    expect(lineage).toEqual([]);
    expect(stops).toEqual([]);
  });

  it("retains the root on a malformed record instead of filtering it out", async () => {
    const { deps, row, fixture, stops } = await harness();
    await deps.prepare(fixture, row);
    await writeFile(join(fixture.evidence, "exec", "exec-1.rec"), "garbage");
    await expect(deps.removeRoot(fixture, row)).rejects.toThrow(/malformed execution record exec-1\.rec/);
    expect(await exists(fixture.root)).toBe(true);
    expect(stops).toEqual([]);
  });

  it("retains the root on an unexpected entry in the record directory", async () => {
    const { deps, row, fixture } = await harness();
    await deps.prepare(fixture, row);
    await writeFile(join(fixture.evidence, "exec", "notes.txt"), "x");
    await expect(deps.removeRoot(fixture, row)).rejects.toThrow(/unexpected entry notes\.txt/);
    expect(await exists(fixture.root)).toBe(true);
  });

  it("treats an in-flight .tmp-<pid> record as lineage", async () => {
    const { deps, row, fixture, lineage } = await harness();
    await deps.prepare(fixture, row);
    await writeFile(join(fixture.evidence, "exec", ".tmp-777"), "rh-exec-v1");
    await deps.removeRoot(fixture, row);
    expect(lineage).toEqual([[777]]);
  });

  it("an empty record directory after prepare is legitimate (no scenario executed yet) and fabricates no records", async () => {
    const { deps, row, fixture, lineage } = await harness();
    await deps.prepare(fixture, row);
    await deps.removeRoot(fixture, row);
    expect(lineage).toEqual([[]]);
    expect(await exists(fixture.root)).toBe(false);
  });

  it("an absent record directory is legitimate only when prepare never created it", async () => {
    const { deps, row, fixture, lineage } = await harness();
    await deps.removeRoot(fixture, row);
    expect(lineage).toEqual([[]]);
  });

  it("evidence collection stays tolerant and reports a missing or malformed record source instead of throwing", async () => {
    const { deps, row, fixture } = await harness();
    await deps.prepare(fixture, row);
    await writeFile(join(fixture.evidence, "exec", "exec-1.rec"), "garbage");
    expect((await deps.collect(fixture, row)).files["evidence/exec"]).toEqual([{ malformed: "record is not NUL-terminated" }]);
    await rm(join(fixture.evidence, "exec"), { recursive: true });
    expect((await deps.collect(fixture, row)).files["evidence/exec"]).toMatchObject({ error: expect.stringMatching(/missing/) });
  });
});

// ---- socket-free simulated host for whole-pipeline composition tests ----
// The simulator answers through the injected transport and an injected SSE
// ReadableStream. It applies the REAL normalizer (src/core.ts), evaluates the
// generated config's rules (last match wins), writes the artifacts the plugin
// and fixture command would write, and emits source-faithful raw events
// (V2 local success: executed: false).
type SimOptions = { family: "v1" | "v2"; inventoryStuckActive?: boolean; dropTerminalForSession?: number; duplicateAuditForSession?: number };

function shellArgv(command: string, home: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quoted = false;
  let inToken = false;
  for (const char of command) {
    if (char === "'") {
      quoted = !quoted;
      inToken = true;
    } else if (char === " " && !quoted) {
      if (inToken) tokens.push(current);
      current = "";
      inToken = false;
    } else {
      current += char;
      inToken = true;
    }
  }
  if (inToken) tokens.push(current);
  tokens[0] = tokens[0].replace(/^~(?=\/)/, home).replace(/^\$\{HOME\}(?=\/)/, home).replace(/^\$HOME(?=\/)/, home);
  return tokens;
}

function simulator(sim: SimOptions) {
  let h: Awaited<ReturnType<typeof harness>>;
  const streams = new Set<ReadableStreamDefaultController<Uint8Array>>();
  const encoder = new TextEncoder();
  const pending = new Map<string, { sessionID: string; callID: string; canonical: string; plugin: boolean; ledger: string; sessionNumber: number }>();
  const counters = { session: 0, request: 0, pid: 9000, prompts: 0, rebuilds: 0, evt: 0 };
  const v2 = sim.family === "v2";
  const emit = (type: string, body: Record<string, unknown>) => {
    const event = v2 ? { id: `evt_${(counters.evt += 1)}`, type, data: body } : { id: `e${(counters.evt += 1)}`, type, properties: body };
    for (const controller of streams) controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
  };
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
  const configPath = () => (v2 ? join(h.fixture.root, "config", "opencode.json") : join(h.fixture.xdg.XDG_CONFIG_HOME, "opencode", "opencode.json"));
  const append = (path: string, value: unknown) => appendFile(path, `${JSON.stringify(value)}\n`);
  const toolPart = (sessionID: string, callID: string, state: Record<string, unknown>) => ({ sessionID, part: { type: "tool", sessionID, callID, tool: "bash", state } });

  async function execute(entry: { sessionID: string; callID: string; canonical: string; ledger: string; sessionNumber: number }) {
    const argv = shellArgv(entry.canonical, h.fixture.home);
    const pid = (counters.pid += 1);
    const fields = ["rh-exec-v1", String(pid), h.fixture.home, h.fixture.project, String(argv.length - 1), argv[0], ...argv.slice(1)];
    await writeFile(join(h.fixture.evidence, "exec", `exec-${pid}.rec`), `${fields.join("\0")}\0`);
    await finish(entry, v2 ? ["session.tool.success", { sessionID: entry.sessionID, id: entry.callID, executed: false }] : ["message.part.updated", toolPart(entry.sessionID, entry.callID, { status: "completed" })]);
  }

  async function finish(entry: { sessionID: string; ledger: string; sessionNumber: number }, terminal: [string, Record<string, unknown>]) {
    await append(entry.ledger, { n: 2, status: 200, kind: "final" });
    if (sim.dropTerminalForSession === entry.sessionNumber) return;
    emit(...terminal);
    emit(v2 ? "session.status" : "session.idle", v2 ? { sessionID: entry.sessionID, status: { type: "idle" } } : { sessionID: entry.sessionID });
  }

  async function runTool(sessionID: string, sessionNumber: number) {
    const config = JSON.parse(await readFile(configPath(), "utf8"));
    const providerConfigPath = h.providerConfigs.at(-1)!;
    const provider = JSON.parse(await readFile(providerConfigPath, "utf8"));
    const ledger = providerConfigPath.replace(h.fixture.run, h.fixture.evidence).replace(/\.provider\.json$/, ".provider.jsonl");
    const command: string = provider.toolCalls[0].command;
    const callID = `call_${provider.nonce}_0`;
    await append(ledger, { n: 1, status: 200, kind: "tool-call", callId: callID });
    const decl = v2 ? config.plugins?.[0] : config.plugin?.[0];
    const options = decl ? (v2 ? decl.options : decl[1]) : null;
    const canonical = options ? canonicalize(command, { roots: options.roots, expandBraceHome: options.expandBraceHome, homedir: h.fixture.home }) : command;
    if (options) {
      const record = { ts: "t", sessionID, agent: null, callID, command_node_text: canonical };
      await append(options.auditLogPath, record);
      if (sim.duplicateAuditForSession === sessionNumber) await append(options.auditLogPath, record);
    }
    const rules: Array<[string, string]> = v2 ? config.permissions.map((rule: { resource: string; effect: string }) => [rule.resource, rule.effect]) : Object.entries(config.permission.bash);
    const matches = (pattern: string) => pattern === "*" || (pattern.endsWith(" *") ? canonical.startsWith(pattern.slice(0, -1)) : canonical === pattern);
    const effect = [...rules].reverse().find(([pattern]) => matches(pattern))?.[1] ?? "ask";
    emit(v2 ? "session.tool.called" : "message.part.updated", v2 ? { sessionID, id: callID } : toolPart(sessionID, callID, { status: "running" }));
    const entry = { sessionID, callID, canonical, plugin: Boolean(options), ledger, sessionNumber };
    if (effect === "allow") return execute(entry);
    if (effect === "deny") {
      return finish(entry, v2
        ? ["session.tool.failed", { sessionID, id: callID, executed: false, error: { type: "permission.rejected", message: "Permission denied: shell" } }]
        : ["message.part.updated", toolPart(sessionID, callID, { status: "error", error: 'The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules [{"permission":"bash"}]' })]);
    }
    const requestID = `per_${(counters.request += 1)}`;
    pending.set(requestID, entry);
    if (options) await appendFile(options.debugLogPath, `t permission asked cached: requestID=${requestID} callID=${callID}\n`);
    emit(
      "permission.asked",
      v2
        ? { id: requestID, sessionID, action: "shell", resources: [canonical], source: { type: "tool", messageID: "m", id: callID } }
        : { id: requestID, sessionID, permission: "bash", patterns: [canonical], always: [], tool: { messageID: "m", callID } },
    );
  }

  async function reply(requestID: string, decision: string) {
    const entry = pending.get(requestID)!;
    pending.delete(requestID);
    emit("permission.replied", { sessionID: entry.sessionID, requestID, reply: decision });
    const config = JSON.parse(await readFile(configPath(), "utf8"));
    const decl = v2 ? config.plugins?.[0] : config.plugin?.[0];
    if (decl) await append((v2 ? decl.options : decl[1]).decisionsLogPath, { sessionID: entry.sessionID, requestID, callID: entry.callID, reply: decision });
    if (decision === "reject") {
      return finish(entry, v2
        ? ["session.tool.failed", { sessionID: entry.sessionID, id: entry.callID, executed: false, error: { type: "aborted", message: "The user declined this tool call" } }]
        : ["message.part.updated", toolPart(entry.sessionID, entry.callID, { status: "error", error: "The user rejected permission to use this specific tool call." })]);
    }
    return execute(entry);
  }

  const handler = async (url: URL, init: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => {
    if (init.headers?.authorization !== BASIC) return new Response(null, { status: 401, headers: { "www-authenticate": CHALLENGE } });
    const path = url.pathname;
    if (path === "/event" || path === "/api/event") {
      let mine: ReadableStreamDefaultController<Uint8Array>;
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          mine = controller;
          streams.add(controller);
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(v2 ? { id: "evt_0", type: "server.connected", data: {} } : { id: "e0", type: "server.connected", properties: {} })}\n\n`));
        },
      });
      init.signal?.addEventListener("abort", () => {
        streams.delete(mine);
        try {
          mine.close();
        } catch {
          // already closed
        }
      });
      return new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } });
    }
    if (init.method === "GET" && (path === "/session" || path === "/api/session")) return json([]);
    if (init.method === "POST" && (path === "/session" || path === "/api/session")) {
      const id = `ses_${(counters.session += 1)}`;
      return json(v2 ? { data: { id } } : { id });
    }
    const prompt = /^\/(?:api\/)?session\/([^/]+)\/(prompt_async|prompt)$/.exec(path);
    if (prompt) {
      counters.prompts += 1;
      const sessionNumber = counters.session;
      setTimeout(() => void runTool(prompt[1], sessionNumber), 1);
      return v2 ? json({ data: {} }) : new Response(null, { status: 204 });
    }
    const v1Reply = /^\/permission\/([^/]+)\/reply$/.exec(path);
    const v2Reply = /^\/api\/session\/[^/]+\/permission\/([^/]+)\/reply$/.exec(path);
    if (v1Reply || v2Reply) {
      const body = JSON.parse(init.body!);
      setTimeout(() => void reply((v1Reply ?? v2Reply)![1], v2 ? body.decision : body.reply), 1);
      return v2 ? new Response(null, { status: 204 }) : new Response("true", { status: 200 });
    }
    if (path === "/instance/dispose" || path === "/api/location/reload") {
      counters.rebuilds += 1;
      return v2 ? new Response(null, { status: 204 }) : new Response("true", { status: 200 });
    }
    if (path === "/api/plugin") {
      const config = JSON.parse(await readFile(configPath(), "utf8"));
      const active = sim.inventoryStuckActive || (config.plugins ?? []).length > 0;
      const target = config.plugins?.[0]?.package ?? PACKAGE_NAME;
      return json({ location: { directory: h.fixture.project }, data: active ? [{ id: "skwid138.command-normalizer", source: { type: "package", target }, features: { server: true }, state: { status: "active" } }] : [] });
    }
    return new Response("not found", { status: 404 });
  };

  return {
    counters,
    async start() {
      h = await harness({ family: sim.family, hostHandler: handler, timing: { connectMs: 300, askMs: 400, debugRecordMs: 200, completionMs: 600, settleMs: 5 } });
      await h.deps.prepare(h.fixture, h.row);
      return h;
    },
  };
}

describe("runtime composition: whole scenario pipeline through a simulated host (no sockets)", () => {
  for (const family of ["v1", "v2"] as const) {
    it(`${family}: pilot ask-once passes end to end (identity, auth, SSE, ask, debug-gated reply, execution record, terminal, idle)`, async () => {
      const sim = simulator({ family });
      const { deps, row, fixture } = await sim.start();
      const result = await deps.scenario(fixture, row, "pilot-ask-once");
      expect(result).toMatchObject({ id: "pilot-ask-once", status: "pass", problems: [] });
      if (family === "v2") {
        const terminal = result.evidence.events.find((event: { kind: string }) => event.kind === "tool-terminal");
        expect(terminal).toMatchObject({ status: "completed", providerExecuted: false });
      }
    });

    it(`${family}: tilde-allow and deny-resource pass with the source-verified outcomes`, async () => {
      const sim = simulator({ family });
      const { deps, row, fixture } = await sim.start();
      expect(await deps.scenario(fixture, row, "tilde-allow")).toMatchObject({ status: "pass" });
      expect(await deps.scenario(fixture, row, "deny-resource")).toMatchObject({ status: "pass" });
    });

    it(`${family}: lifecycle passes 1/0/1 through remove, rebuild, and restore`, async () => {
      const sim = simulator({ family });
      const { deps, row, fixture } = await sim.start();
      const result = await deps.lifecycle(fixture, row);
      expect(result).toMatchObject({ status: "pass", problems: [] });
      expect(result.phases.map((phase: { name: string }) => phase.name)).toEqual(["active", "removed", "restored"]);
      expect(sim.counters).toMatchObject({ prompts: 3, rebuilds: 2 });
    });
  }
});

describe("runtime composition: lifecycle stops at the first failure", () => {
  const config = async (fixture: { root: string }) => JSON.parse(await readFile(join(fixture.root, "config", "opencode.json"), "utf8"));

  it("a failed inventory after removal stops before any further prompt, restore, or rebuild", async () => {
    const sim = simulator({ family: "v2", inventoryStuckActive: true });
    const { deps, row, fixture } = await sim.start();
    const result = await deps.lifecycle(fixture, row);
    expect(result.status).toBe("fail");
    expect(result.problems.join()).toMatch(/removed: inventory/);
    expect(result.phases.map((phase: { name: string }) => phase.name)).toEqual(["active", "removed"]);
    expect(sim.counters).toMatchObject({ prompts: 1, rebuilds: 1 });
    expect((await config(fixture)).plugins).toEqual([]); // removed, never restored
  });

  it("a failed phase behavior stops before the next config mutation", async () => {
    const sim = simulator({ family: "v2", dropTerminalForSession: 1 });
    const { deps, row, fixture } = await sim.start();
    const result = await deps.lifecycle(fixture, row);
    expect(result.status).toBe("fail");
    expect(result.phases.map((phase: { name: string }) => phase.name)).toEqual(["active"]);
    expect(sim.counters).toMatchObject({ prompts: 1, rebuilds: 0 });
    expect((await config(fixture)).plugins).toHaveLength(1);
  });

  it("a cardinality failure (duplicate audit) stops before the next config mutation", async () => {
    const sim = simulator({ family: "v1", duplicateAuditForSession: 1 });
    const { deps, row, fixture } = await sim.start();
    const result = await deps.lifecycle(fixture, row);
    expect(result.status).toBe("fail");
    expect(result.problems.join()).toMatch(/active: expected 1 audit record/);
    expect(sim.counters).toMatchObject({ prompts: 1, rebuilds: 0 });
  });
});

describe("runtime composition: exact V2 plugin spec shared by declaration, cache key, and inventory", () => {
  const SPEC = `${PACKAGE_NAME}@0.1.0`;

  it("V2 declares, stages, and inventories the exact hash-verified spec; V1 keeps the bare @latest path", async () => {
    const v2 = await harness({ family: "v2" });
    await v2.deps.prepare(v2.fixture, v2.row);
    await v2.deps.scenario(v2.fixture, v2.row, "pilot-ask-once").catch(() => undefined);
    const config = JSON.parse(await readFile(join(v2.fixture.root, "config", "opencode.json"), "utf8"));
    expect(config.plugins[0].package).toBe(SPEC);
    const staged = join(v2.fixture.xdg.XDG_CACHE_HOME, "opencode", "npm", SPEC, "0", "node_modules", PACKAGE_NAME, "package.json");
    expect(JSON.parse(await readFile(staged, "utf8")).version).toBe("0.1.0");

    const v1 = await harness({ family: "v1" });
    await v1.deps.prepare(v1.fixture, v1.row);
    await v1.deps.scenario(v1.fixture, v1.row, "pilot-ask-once").catch(() => undefined);
    const v1Config = JSON.parse(await readFile(join(v1.fixture.xdg.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"));
    expect(v1Config.plugin[0][0]).toBe(PACKAGE_NAME);
  });

  it("V2 lifecycle inventory targets the same exact spec the declaration uses", async () => {
    const sim = simulator({ family: "v2" });
    const { deps, row, fixture } = await sim.start();
    const result = await deps.lifecycle(fixture, row);
    expect(result).toMatchObject({ status: "pass" });
    expect(result.phases[0].inventory).toEqual({ ok: true, problems: [] });
  });

  it("refuses before staging or any launch when the verified spec does not match the packed manifest", async () => {
    const { deps, row, fixture, launches } = await harness({ family: "v2", packageSpec: { name: PACKAGE_NAME, version: "0.2.0", spec: `${PACKAGE_NAME}@0.2.0` } });
    await expect(deps.prepare(fixture, row)).rejects.toThrow(/packed manifest .*does not match the gate-verified spec/);
    await expect(readdir(join(fixture.xdg.XDG_CACHE_HOME, "opencode", "npm"))).rejects.toThrow(/ENOENT/);
    expect(launches).toEqual([]);
  });

  it("refuses before staging when the tarball bytes changed after the gate", async () => {
    const { deps, row, fixture, manifest, launches } = await harness({ family: "v2" });
    await writeFile(manifest.tarball.path, "tampered");
    await expect(deps.prepare(fixture, row)).rejects.toThrow(/hash mismatch/);
    await expect(readdir(join(fixture.xdg.XDG_CACHE_HOME, "opencode", "npm"))).rejects.toThrow(/ENOENT/);
    expect(launches).toEqual([]);
  });
});

describe("runtime composition: run-wide work signal at every spawn boundary", () => {
  const deferred = () => {
    let resolve!: (value?: unknown) => void;
    const promise = new Promise((r) => (resolve = r));
    return { promise, resolve };
  };
  const tick = () => new Promise((resolve) => setTimeout(resolve, 5));

  it("expiry during a deferred prepare await: nothing is staged or launched after it resolves", async () => {
    const gate = deferred();
    const { deps, row, fixture, launches } = await harness({ gates: { allocate: gate.promise } });
    const work = new AbortController();
    deps.bindSignal(work.signal);
    const preparing = deps.prepare(fixture, row);
    await tick();
    work.abort();
    gate.resolve();
    await expect(preparing).rejects.toThrow(/work aborted/);
    await expect(readdir(join(fixture.xdg.XDG_CACHE_HOME, "opencode", "packages"))).rejects.toThrow(/ENOENT/);
    expect(launches).toEqual([]);
  });

  it("expiry while preflight waits for the provider: no probe is ever launched after the provider becomes ready", async () => {
    const gate = deferred();
    const { deps, row, fixture, launches, stops } = await harness({ shortCanary: true, gates: { providerPort: gate.promise } });
    await deps.prepare(fixture, row);
    const work = new AbortController();
    deps.bindSignal(work.signal);
    const preflight = deps.preflight(fixture, row);
    await tick();
    expect(launches.map((launch) => launch.role)).toEqual(["provider"]);
    work.abort();
    gate.resolve();
    await expect(preflight).rejects.toThrow(/work aborted/);
    await tick();
    expect(launches.map((launch) => launch.role)).toEqual(["provider"]);
    expect(stops.map((stop) => stop.role)).toEqual(["provider"]);
  });

  it("expiry during startup (deferred provider identity): the host is never launched", async () => {
    const gate = deferred();
    const { deps, row, fixture, launches } = await harness({ gates: { identity: gate.promise } });
    await deps.prepare(fixture, row);
    const work = new AbortController();
    deps.bindSignal(work.signal);
    const running = deps.scenario(fixture, row, "pilot-ask-once");
    await tick();
    work.abort();
    gate.resolve();
    await expect(running).rejects.toThrow(/work aborted/);
    expect(launches.some((launch) => launch.role === "host")).toBe(false);
  });

  it("an already-expired signal refuses the version probe spawn outright", async () => {
    const { deps, row, fixture, launches } = await harness();
    await deps.prepare(fixture, row);
    const work = new AbortController();
    work.abort();
    deps.bindSignal(work.signal);
    await expect(deps.versionProbe(fixture, row)).rejects.toThrow(/work aborted before spawn version/);
    expect(launches).toEqual([]);
  });
});

describe("runtime composition: registry tripwire listener ownership", () => {
  const registryOf = (listeners: Array<{ args: unknown[]; closes: number }>) => listeners.filter((entry) => entry.args[0] === 41003);
  const exists = async (path: string) => readdir(path).then(() => true, () => false);

  it("cancellation right after the listener is acquired (before staging/baseline) closes it exactly once", async () => {
    const work = new AbortController();
    const h = await harness({ onListen: (args) => args[0] === 41003 && work.abort() });
    h.deps.bindSignal(work.signal);
    await expect(h.deps.prepare(h.fixture, h.row)).rejects.toThrow(/work aborted/);
    expect(registryOf(h.listeners).map((entry) => entry.closes)).toEqual([1]);
    await expect(readdir(join(h.fixture.xdg.XDG_CACHE_HOME, "opencode", "packages"))).rejects.toThrow(/ENOENT/);
    await expect(readFile(join(h.fixture.evidence, "dependency-baseline.json"))).rejects.toThrow(/ENOENT/);
    await h.deps.removeRoot(h.fixture, h.row);
    expect(registryOf(h.listeners).map((entry) => entry.closes)).toEqual([1]);
    expect(await exists(h.fixture.root)).toBe(false);
  });

  it("an ordinary prepare error after the listener is acquired closes it exactly once", async () => {
    const h = await harness({ machServices: ["not a valid name!"] });
    await expect(h.deps.prepare(h.fixture, h.row)).rejects.toThrow(/unsafe Mach service/);
    expect(registryOf(h.listeners).map((entry) => entry.closes)).toEqual([1]);
    await h.deps.removeRoot(h.fixture, h.row);
    expect(registryOf(h.listeners).map((entry) => entry.closes)).toEqual([1]);
  });

  it("on the normal path the listener stays open through the run and is closed exactly once before the root is deleted", async () => {
    const h = await harness();
    await h.deps.prepare(h.fixture, h.row);
    expect(registryOf(h.listeners).map((entry) => entry.closes)).toEqual([0]);
    await h.deps.removeRoot(h.fixture, h.row);
    expect(registryOf(h.listeners).map((entry) => entry.closes)).toEqual([1]);
    await h.deps.removeRoot(h.fixture, h.row).catch(() => undefined);
    expect(registryOf(h.listeners).map((entry) => entry.closes)).toEqual([1]);
  });
});


describe("runtime composition: physical listener adapter (injected createServer; no socket is opened)", () => {
  type FakeServer = { closeCalls: number; closeCallbacks: Array<(error?: Error) => void> };
  const fakeNet = () => {
    const made: FakeServer[] = [];
    const createServer = () => {
      const server = {
        closeCalls: 0,
        closeCallbacks: [] as Array<(error?: Error) => void>,
        once: () => server,
        listen: (...args: unknown[]) => {
          queueMicrotask(args.at(-1) as () => void);
          return server;
        },
        address: () => ({ port: 50123 }),
        close: (callback: (error?: Error) => void) => {
          server.closeCalls += 1;
          server.closeCallbacks.push(callback);
          return server; // server.close() returning is NOT confirmation
        },
      };
      made.push(server);
      return server;
    };
    return { made, createServer };
  };
  const tick = () => new Promise((resolve) => setTimeout(resolve, 5));

  it("close resolves only when the server.close callback confirms, not when server.close returns", async () => {
    const net = fakeNet();
    const listener = await countingListener([0, "127.0.0.1"], { createServer: net.createServer });
    let settled = false;
    const closing = Promise.resolve(listener.close()).then(() => (settled = true));
    await tick();
    expect(net.made[0].closeCalls).toBe(1);
    expect(settled).toBe(false);
    net.made[0].closeCallbacks[0]();
    await closing;
    expect(settled).toBe(true);
  });

  it("close rejects when the server.close callback reports an error", async () => {
    const net = fakeNet();
    const listener = await countingListener([0, "127.0.0.1"], { createServer: net.createServer });
    const closing = Promise.resolve(listener.close());
    net.made[0].closeCallbacks[0](new Error("ERR_SERVER_NOT_RUNNING"));
    await expect(closing).rejects.toThrow(/ERR_SERVER_NOT_RUNNING/);
  });
});

describe("runtime composition: preflight listener ownership and cleanup (Amendment A2)", () => {
  type Entry = { args: unknown[]; closes: number };
  const preflightOf = (listeners: Entry[]) => listeners.filter((entry) => entry.args[0] !== 41003);
  const registryOf = (listeners: Entry[]) => listeners.filter((entry) => entry.args[0] === 41003);
  const isUnix = (args: unknown[]) => typeof args[0] === "string";
  const isIpv6 = (args: unknown[]) => args[1] === "::1";

  it.each([
    ["the second (IPv6)", isIpv6, 1],
    ["the third (Unix)", isUnix, 2],
  ] as const)("a failure acquiring %s preflight listener closes each previously acquired one exactly once and keeps the original error", async (_label, failing, acquiredBefore) => {
    const original = new Error("EADDRINUSE: synthetic acquisition failure");
    const { deps, row, fixture, launches, listeners } = await harness({ shortCanary: true, listenFailure: (args) => (failing(args) ? original : undefined) });
    await deps.prepare(fixture, row);
    const caught = await deps.preflight(fixture, row).catch((error: unknown) => error);
    expect(caught).toBe(original);
    expect(preflightOf(listeners).map((entry) => entry.closes)).toEqual(Array(acquiredBefore).fill(1));
    expect(registryOf(listeners).map((entry) => entry.closes)).toEqual([0]);
    expect(launches).toEqual([]);
  });
});

describe("runtime composition: preflight cleanup contract (Amendment A2)", () => {
  type Entry = { args: unknown[]; closes: number };
  const preflightOf = (listeners: Entry[]) => listeners.filter((entry) => entry.args[0] !== 41003);
  const registryOf = (listeners: Entry[]) => listeners.filter((entry) => entry.args[0] === 41003);
  const isUnix = (args: unknown[]) => typeof args[0] === "string";
  const isIpv6 = (args: unknown[]) => args[1] === "::1";
  const exists = async (path: string) => readdir(path).then(() => true, () => false);
  const tick = (ms = 5) => new Promise((resolve) => setTimeout(resolve, ms));
  const deferred = () => {
    let resolve!: () => void;
    let reject!: (error: Error) => void;
    const promise = new Promise<void>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    return { promise, resolve, reject };
  };
  /** Every check behaves as a healthy sandbox would: positives allowed, negatives denied, controls allowed. */
  const passingProbe = (argv: string[], { providerToken }: { providerToken: string }) => {
    const sandboxed = argv[0] === "/usr/bin/sandbox-exec";
    const [op, target] = argv.slice(-2);
    if (op === "http-get") return JSON.stringify({ completed: true, op, outcome: "allowed", status: 200, body: JSON.stringify({ token: providerToken }) });
    if (!sandboxed) return JSON.stringify({ completed: true, op, outcome: "allowed" });
    return JSON.stringify(target.includes("canary") || op.startsWith("connect") ? { completed: true, op, outcome: "denied", code: "EPERM" } : { completed: true, op, outcome: "allowed" });
  };

  it("full success: all three preflight listeners are acquired, confirmed closed once, the provider is stopped, and the result passes", async () => {
    const { deps, row, fixture, listeners, stops, canaryOps, canaryBacking } = await harness({ shortCanary: true, probe: passingProbe });
    await deps.prepare(fixture, row);
    const result = await deps.preflight(fixture, row);
    expect(result).toMatchObject({ ok: true, failures: [] });
    expect(preflightOf(listeners).map((entry) => entry.args)).toEqual([[0, "127.0.0.1"], [0, "::1"], [expect.stringMatching(/^\/fixture\/c\/rh-canary-[^/]{6}\/forbidden\.sock$/)]]);
    // Every canary filesystem operation went through the injected seam on the synthetic path,
    // backed by an owned directory inside the isolated root.
    const canaryDir = (preflightOf(listeners)[2].args[0] as string).replace(/\/forbidden\.sock$/, "");
    expect(canaryOps).toEqual([["mkdtemp", "/fixture/c/rh-canary-"], ["writeFile", `${canaryDir}/canary-read`]]);
    const backed = join(canaryBacking, canaryDir.slice("/fixture/c/".length));
    expect(await readFile(join(backed, "canary-read"), "utf8")).toMatch(/^canary-tok\d+\n$/);
    expect(preflightOf(listeners).map((entry) => entry.closes)).toEqual([1, 1, 1]);
    expect(stops.map((stop) => stop.role)).toEqual(["provider"]);
    const collected = await deps.collect(fixture, row);
    expect(collected.files["evidence/listeners"]).toEqual([
      { group: "registry", label: "registry tripwire", status: "open" },
      { group: "preflight", label: "preflight ipv4", status: "closed" },
      { group: "preflight", label: "preflight ipv6", status: "closed" },
      { group: "preflight", label: "preflight unix", status: "closed" },
    ]);
    expect(collected.files["evidence/cleanup-problems"]).toEqual([]);
    await deps.removeRoot(fixture, row);
    expect(registryOf(listeners).map((entry) => entry.closes)).toEqual([1]);
    expect(preflightOf(listeners).map((entry) => entry.closes)).toEqual([1, 1, 1]);
    expect(await exists(fixture.root)).toBe(false);
    expect(canaryOps.at(-1)).toEqual(["rm", canaryDir]);
    expect(await exists(backed)).toBe(false);
    expect(await readdir(canaryBacking)).toEqual([]);
  });

  it("the production canary filesystem default is exactly node:fs/promises mkdtemp, writeFile, and rm", () => {
    expect(DEFAULT_IO.canaryFs).toEqual({ mkdtemp, writeFile, rm });
    expect(DEFAULT_IO.canaryFs.mkdtemp).toBe(mkdtemp);
    expect(DEFAULT_IO.canaryFs.writeFile).toBe(writeFile);
    expect(DEFAULT_IO.canaryFs.rm).toBe(rm);
    expect(Object.isFrozen(DEFAULT_IO.canaryFs)).toBe(true);
  });

  it("the synthetic canary seam refuses any path outside the synthetic root (no fall-through to the real filesystem)", async () => {
    // Refusal happens before any filesystem call, so the backing path is never touched.
    const seam = redirectedCanaryFs(join(tmpdir(), "never-created"));
    await expect(seam.fs.writeFile("/elsewhere/escape", "x")).rejects.toThrow(/outside the synthetic root/);
    await expect(seam.fs.mkdtemp("/fixture/cc/rh-canary-")).rejects.toThrow(/outside the synthetic root/);
    await expect(seam.fs.rm("/fixture", { recursive: true })).rejects.toThrow(/outside the synthetic root/);
    expect(seam.ops).toEqual([["writeFile", "/elsewhere/escape"], ["mkdtemp", "/fixture/cc/rh-canary-"], ["rm", "/fixture"]]);
  });

  it("awaits a deferred close confirmation before preflight settles", async () => {
    const gate = deferred();
    const { deps, row, fixture } = await harness({ shortCanary: true, probe: passingProbe, closeBehavior: (args) => (isIpv6(args) ? gate.promise : undefined) });
    await deps.prepare(fixture, row);
    let settled = false;
    const running = deps.preflight(fixture, row).finally(() => (settled = true));
    await tick(30);
    expect(settled).toBe(false);
    gate.resolve();
    await expect(running).resolves.toMatchObject({ ok: true });
  });

  it("a rejecting close does not stop the other closes or the provider stop, the original error is kept, and the failure is visible and retains the root", async () => {
    const original = new Error("synthetic unix acquisition failure");
    const { deps, row, fixture, listeners, stops, launches } = await harness({
      shortCanary: true,
      listenFailure: (args) => (isUnix(args) ? original : undefined),
      closeBehavior: (args) => (args[1] === "127.0.0.1" && args[0] === 0 ? Promise.reject(new Error("ERR_SERVER_NOT_RUNNING")) : undefined),
    });
    await deps.prepare(fixture, row);
    expect(await deps.preflight(fixture, row).catch((error: unknown) => error)).toBe(original);
    expect(preflightOf(listeners).map((entry) => entry.closes)).toEqual([1, 1]);
    expect(launches).toEqual([]);
    expect(stops).toEqual([]);
    const collected = await deps.collect(fixture, row);
    expect(collected.files["evidence/cleanup-problems"]).toEqual(["preflight ipv4 listener close failed: ERR_SERVER_NOT_RUNNING"]);
    await expect(deps.removeRoot(fixture, row)).rejects.toThrow(/fixture retained: listener close not confirmed: preflight ipv4 listener close failed: ERR_SERVER_NOT_RUNNING/);
    expect(await exists(fixture.root)).toBe(true);
    expect(preflightOf(listeners).map((entry) => entry.closes)).toEqual([1, 1]); // no second attempt, no promotion
  });

  it("a timed-out close still lets the provider stop run, keeps the primary error, and leaves the listener unconfirmed even if it later rejects", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    try {
      const gate = deferred();
      const { deps, row, fixture, stops } = await harness({
        shortCanary: true,
        timing: { listenerCloseMs: 20 },
        probe: () => {
          throw new Error("synthetic probe infrastructure failure");
        },
        closeBehavior: (args) => (isUnix(args) ? gate.promise : undefined),
      });
      await deps.prepare(fixture, row);
      await expect(deps.preflight(fixture, row)).rejects.toThrow(/synthetic probe infrastructure failure/);
      expect(stops.map((stop) => stop.role)).toEqual(["provider"]);
      gate.reject(new Error("late close failure"));
      await tick(20);
      expect(unhandled).toEqual([]);
      const collected = await deps.collect(fixture, row);
      expect(collected.files["evidence/listeners"]).toContainEqual({ group: "preflight", label: "preflight unix", status: "timeout", error: "close not confirmed within 20ms" });
      await expect(deps.removeRoot(fixture, row)).rejects.toThrow(/fixture retained: .*preflight unix listener close timeout/);
      expect(await exists(fixture.root)).toBe(true);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });

  it("a close failure on an otherwise passing preflight is never reported as success", async () => {
    const { deps, row, fixture, stops } = await harness({ shortCanary: true, probe: passingProbe, closeBehavior: (args) => (isIpv6(args) ? Promise.reject(new Error("close failed")) : undefined) });
    await deps.prepare(fixture, row);
    const error = await deps.preflight(fixture, row).catch((caught: Error & { stage?: string }) => caught);
    expect(error).toMatchObject({ stage: "teardown", message: "preflight cleanup failed: preflight ipv6 listener close failed: close failed" });
    expect(stops.map((stop) => stop.role)).toEqual(["provider"]);
  });

  it("a provider that survives stop is reported as secondary evidence without masking the primary error, and every listener is still closed", async () => {
    const { deps, row, fixture, listeners } = await harness({
      shortCanary: true,
      probe: () => {
        throw new Error("synthetic probe failure");
      },
      stopResult: (role) => (role === "provider" ? { aliveAfter: true } : {}),
    });
    await deps.prepare(fixture, row);
    await expect(deps.preflight(fixture, row)).rejects.toThrow(/^synthetic probe failure$/);
    expect(preflightOf(listeners).map((entry) => entry.closes)).toEqual([1, 1, 1]);
    expect((await deps.collect(fixture, row)).files["evidence/cleanup-problems"]).toEqual([expect.stringMatching(/preflight provider process group \d+ survived stop/)]);
  });
});

describe("runtime composition: registry release follows the same close contract (Amendment A2)", () => {
  const registryOf = (listeners: Array<{ args: unknown[]; closes: number }>) => listeners.filter((entry) => entry.args[0] === 41003);
  const exists = async (path: string) => readdir(path).then(() => true, () => false);

  it("a prepare failure with a rejecting registry close keeps the prepare error, closes once, and retains the root", async () => {
    const h = await harness({ machServices: ["not a valid name!"], closeBehavior: (args) => (args[0] === 41003 ? Promise.reject(new Error("registry close failed")) : undefined) });
    await expect(h.deps.prepare(h.fixture, h.row)).rejects.toThrow(/unsafe Mach service/);
    expect((await h.deps.collect(h.fixture, h.row)).files["evidence/cleanup-problems"]).toEqual(["registry tripwire listener close failed: registry close failed"]);
    await expect(h.deps.removeRoot(h.fixture, h.row)).rejects.toThrow(/fixture retained: listener close not confirmed: registry tripwire/);
    expect(registryOf(h.listeners).map((entry) => entry.closes)).toEqual([1]);
    expect(await exists(h.fixture.root)).toBe(true);
  });

  it("removeRoot awaits the registry close confirmation before deleting, and a timeout retains the root", async () => {
    const h = await harness({ timing: { listenerCloseMs: 20 }, closeBehavior: (args) => (args[0] === 41003 ? new Promise<void>(() => {}) : undefined) });
    await h.deps.prepare(h.fixture, h.row);
    await expect(h.deps.removeRoot(h.fixture, h.row)).rejects.toThrow(/fixture retained: listener close not confirmed: registry tripwire listener close timeout/);
    expect(await exists(h.fixture.root)).toBe(true);
    expect(registryOf(h.listeners).map((entry) => entry.closes)).toEqual([1]);
  });
});

describe("runtime + runner composition: a thrown preflight failure (Amendment A2)", () => {
  const isUnix = (args: unknown[]) => typeof args[0] === "string";
  const runRow = (row: { id: string; family: string; version: string }) => ({ ...row, sourceCommit: "c", binary: { path: "/x" } });

  it("stops before the version probe and scenarios, still collects and checks final integrity, and retains the root on an unconfirmed close", async () => {
    const original = new Error("synthetic unix acquisition failure");
    const h = await harness({
      shortCanary: true,
      listenFailure: (args) => (isUnix(args) ? original : undefined),
      closeBehavior: (args) => (args[1] === "::1" ? Promise.reject(new Error("ERR_SERVER_NOT_RUNNING")) : undefined),
    });
    const result = await runMatrix({ rows: [runRow(h.row)], mode: "pilot", tarballSha256: "t", deps: h.deps, workBudgetMs: 60_000 });
    const [row] = result.rows;
    expect(row.failure).toEqual({ stage: "preflight", message: "synthetic unix acquisition failure" });
    expect(row.version).toBeNull();
    expect(row.scenarios).toEqual([]);
    expect(h.launches).toEqual([]);
    expect(row.evidence.files["evidence/listeners"]).toEqual([
      { group: "registry", label: "registry tripwire", status: "open" },
      { group: "preflight", label: "preflight ipv4", status: "closed" },
      { group: "preflight", label: "preflight ipv6", status: "failed", error: "ERR_SERVER_NOT_RUNNING" },
    ]);
    expect(row.evidence.files["evidence/cleanup-problems"]).toEqual(["preflight ipv6 listener close failed: ERR_SERVER_NOT_RUNNING"]);
    expect(row.integrity).toMatchObject({ ok: true });
    expect(row.cleanup).toMatchObject({ rootRemoved: false, error: expect.stringMatching(/fixture retained: listener close not confirmed: preflight ipv6/) });
    expect(JSON.parse(JSON.stringify(row.evidence.files["evidence/listeners"]))).toEqual(row.evidence.files["evidence/listeners"]);
  });

  it("with every close confirmed, the same thrown failure still removes the root after collect and final integrity", async () => {
    const h = await harness({ shortCanary: true, listenFailure: (args) => (isUnix(args) ? new Error("synthetic unix acquisition failure") : undefined) });
    const result = await runMatrix({ rows: [runRow(h.row)], mode: "pilot", tarballSha256: "t", deps: h.deps, workBudgetMs: 60_000 });
    const [row] = result.rows;
    expect(row.failure).toEqual({ stage: "preflight", message: "synthetic unix acquisition failure" });
    expect(row.integrity).toMatchObject({ ok: true });
    expect(row.cleanup).toMatchObject({ rootRemoved: true });
    expect(h.listeners.map((entry) => entry.closes)).toEqual([1, 1, 1]);
  });
});

describe("runtime composition: provider startup at both call sites (Amendment A3)", () => {
  const roles = (launches: Array<{ role: string }>) => launches.map((launch) => launch.role);
  const identityRequests = (requests: Array<{ url: string }>) => requests.filter((request) => request.url.endsWith("/__rh/identity"));

  it.each([
    ["exit code 0", { code: 0, signal: null }, /code 0/],
    ["a nonzero exit", { code: 1, signal: null }, /code 1/],
    ["a signal", { code: null, signal: "SIGKILL" }, /signal SIGKILL/],
  ] as const)("preflight: a provider launcher %s before readiness fails at once, runs no probe, and the owned group is still stopped", async (_label, exit, detail) => {
    const { deps, row, fixture, launches, stops } = await harness({ shortCanary: true, providerExit: exit, timing: { startupMs: 5_000 } });
    await deps.prepare(fixture, row);
    const started = Date.now();
    await expect(deps.preflight(fixture, row)).rejects.toThrow(new RegExp(`^preflight fake provider exited before reporting readiness \\(.*${detail.source}`));
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(roles(launches)).toEqual(["provider"]);
    expect(stops.map((stop) => stop.role)).toEqual(["provider"]);
  });

  it("preflight: a provider that never reports readiness times out with the existing message and runs no probe", async () => {
    const { deps, row, fixture, launches, stops } = await harness({ shortCanary: true, providerNeverReady: true });
    await deps.prepare(fixture, row);
    await expect(deps.preflight(fixture, row)).rejects.toThrow(/^preflight fake provider did not report readiness$/);
    expect(roles(launches)).toEqual(["provider"]);
    expect(stops.map((stop) => stop.role)).toEqual(["provider"]);
  });

  it.each([
    ["exit code 0", { code: 0, signal: null }],
    ["a signal", { code: null, signal: "SIGTERM" }],
  ] as const)("scenario launch: a provider launcher %s before readiness fails before any identity request or host launch", async (_label, exit) => {
    const { deps, row, fixture, launches, stops, requests } = await harness({ providerExit: exit, timing: { startupMs: 5_000 } });
    await deps.prepare(fixture, row);
    const started = Date.now();
    await expect(deps.scenario(fixture, row, "pilot-ask-once")).rejects.toThrow(/^fake provider exited before reporting readiness/);
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(identityRequests(requests)).toEqual([]);
    expect(roles(launches)).toEqual(["provider"]);
    expect(stops.map((stop) => stop.role)).toEqual(["provider"]);
  });

  it("scenario launch: a provider that never reports readiness times out before any identity request or host launch", async () => {
    const { deps, row, fixture, launches, requests } = await harness({ providerNeverReady: true });
    await deps.prepare(fixture, row);
    await expect(deps.scenario(fixture, row, "pilot-ask-once")).rejects.toThrow(/^fake provider did not report readiness$/);
    expect(identityRequests(requests)).toEqual([]);
    expect(roles(launches)).toEqual(["provider"]);
  });

  it("scenario launch: a ready provider still has its identity checked before the host is launched", async () => {
    const { deps, row, fixture, launches, requests } = await harness();
    await deps.prepare(fixture, row);
    await deps.scenario(fixture, row, "pilot-ask-once").catch(() => undefined);
    expect(identityRequests(requests)).toHaveLength(1);
    expect(roles(launches)).toEqual(["provider", "host"]);
    const identityAt = requests.findIndex((request) => request.url.endsWith("/__rh/identity"));
    const firstHost = requests.findIndex((request) => request.url.includes(":41002"));
    expect(identityAt).toBeLessThan(firstHost);
  });
});

describe("runtime composition: provider launch evidence (Amendment A3)", () => {
  type Entry = { args: unknown[]; closes: number };
  const preflightOf = (listeners: Entry[]) => listeners.filter((entry) => entry.args[0] !== 41003);
  const providerEvidence = async (h: Awaited<ReturnType<typeof harness>>) => (await h.deps.collect(h.fixture, h.row)).files["evidence/provider-launches"];
  const NINE = ["HOME", "PATH", "TMPDIR", "LANG", "SHELL", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"];

  it("captures the intended launch, the raw profile digest, the launcher's pid/pgid and exit, the startup outcome, and the raw stop", async () => {
    const h = await harness({ shortCanary: true, providerExit: { code: 1, signal: null }, timing: { startupMs: 5_000 } });
    await h.deps.prepare(h.fixture, h.row);
    const profileBytes = await readFile(join(h.fixture.run, "profile.sb"));
    await expect(h.deps.preflight(h.fixture, h.row)).rejects.toThrow(/exited before reporting readiness/);
    const launch = h.launches.find((entry) => entry.role === "provider")!;
    const evidence = await providerEvidence(h);
    expect(evidence.captureFailures).toEqual([]);
    expect(evidence.launches).toHaveLength(1);
    const [record] = evidence.launches;
    expect(record).toMatchObject({
      role: "provider",
      label: "preflight.provider",
      intended: { argv: launch.argv, cwd: h.fixture.run, env: launch.env },
      acquisition: { outcome: "acquired", pid: launch.pgid, pgid: launch.pgid },
      startup: { outcome: "exited-before-ready" },
      exit: { event: "exit", code: 1, signal: null },
      stop: { outcome: "returned", pgid: launch.pgid, termSent: true, killSent: false, aliveAfter: false, unsafe: false, alreadyGone: null },
    });
    expect(Object.keys(record.intended.env).sort()).toEqual([...NINE].sort());
    expect(record.profile).toMatchObject({ sha256: createHash("sha256").update(profileBytes).digest("hex"), bytes: profileBytes.length, digestOf: "raw profile bytes used for this launch" });
    expect(record.profile.text).toContain("<FIXTURE>");
    expect(record.profile.text).not.toContain(h.fixture.root);
    expect(JSON.stringify(record)).not.toMatch(/identityToken|tok0000/);
  });

  it("an oversized profile is a capture failure before launch: no provider spawn, every preflight listener still closed", async () => {
    const h = await harness({ shortCanary: true });
    await h.deps.prepare(h.fixture, h.row);
    await writeFile(join(h.fixture.run, "profile.sb"), Buffer.alloc(65537, 0x3b));
    await expect(h.deps.preflight(h.fixture, h.row)).rejects.toThrow(/^provider launch evidence capture failed: profile exceeds 65536 bytes$/);
    expect(h.launches).toEqual([]);
    expect(preflightOf(h.listeners).map((entry) => entry.closes)).toEqual([1, 1, 1]);
    expect(await providerEvidence(h)).toEqual({ launches: [], captureFailures: [{ label: "preflight.provider", reason: "profile exceeds 65536 bytes" }], captureFailuresDropped: 0 });
  });

  it("a rejected provider spawn is recorded without a pid, keeps the original error, and closes every listener", async () => {
    const original = Object.assign(new Error("spawn /usr/bin/sandbox-exec EACCES"), { code: "EACCES" });
    const h = await harness({ shortCanary: true, providerSpawnError: original });
    await h.deps.prepare(h.fixture, h.row);
    expect(await h.deps.preflight(h.fixture, h.row).catch((error: unknown) => error)).toBe(original);
    expect(h.stops).toEqual([]);
    expect(preflightOf(h.listeners).map((entry) => entry.closes)).toEqual([1, 1, 1]);
    const [record] = (await providerEvidence(h)).launches;
    expect(record.acquisition).toEqual({ outcome: "spawn-failed", error: { name: "Error", code: "EACCES" } });
    expect(record.stop).toBeNull();
  });

  it("an unsafe provider stop is recorded raw before the termination check; the primary error is kept and the failure is secondary", async () => {
    const h = await harness({ shortCanary: true, providerNeverReady: true, stopResult: (role) => (role === "provider" ? { aliveAfter: true, unsafe: true, killSent: true } : {}) });
    await h.deps.prepare(h.fixture, h.row);
    await expect(h.deps.preflight(h.fixture, h.row)).rejects.toThrow(/^preflight fake provider did not report readiness$/);
    const collected = await h.deps.collect(h.fixture, h.row);
    expect(collected.files["evidence/provider-launches"].launches[0].stop).toEqual({ outcome: "returned", pgid: expect.any(Number), termSent: true, killSent: true, aliveAfter: true, unsafe: true, alreadyGone: null });
    expect(collected.files["evidence/cleanup-problems"]).toEqual([expect.stringMatching(/preflight provider process group \d+ survived stop \(aliveAfter=true, unsafe=true\)/)]);
    expect(preflightOf(h.listeners).map((entry) => entry.closes)).toEqual([1, 1, 1]);
  });

  it("a rejected provider stop is recorded and reported as a bounded name/code, never its message", async () => {
    const secret = "sk-injected-secret-value-123";
    const h = await harness({ shortCanary: true, providerNeverReady: true, stopReject: (role) => (role === "provider" ? Object.assign(new Error(`stop failed ${secret}`), { code: "EPERM" }) : undefined) });
    await h.deps.prepare(h.fixture, h.row);
    await expect(h.deps.preflight(h.fixture, h.row)).rejects.toThrow(/^preflight fake provider did not report readiness$/);
    const collected = await h.deps.collect(h.fixture, h.row);
    expect(collected.files["evidence/provider-launches"].launches[0].stop).toEqual({ outcome: "rejected", error: { name: "Error", code: "EPERM" } });
    expect(collected.files["evidence/cleanup-problems"]).toEqual([expect.stringMatching(/^preflight provider process group \d+ stop rejected \(Error EPERM\)$/)]);
    expect(JSON.stringify(collected)).not.toContain(secret);
  });

  it("a post-acquisition evidence failure cannot lose the handle: the provider is still stopped and every listener closed", async () => {
    const h = await harness({
      shortCanary: true,
      providerExit: { code: 2, signal: null },
      timing: { startupMs: 5_000 },
      providerHandle: (handle) =>
        Object.defineProperty({ ...handle }, "pid", {
          get() {
            throw new Error("evidence failure after acquisition");
          },
        }),
    });
    await h.deps.prepare(h.fixture, h.row);
    await expect(h.deps.preflight(h.fixture, h.row)).rejects.toThrow(/exited before reporting readiness \(code 2/);
    expect(h.stops.map((stop) => stop.role)).toEqual(["provider"]);
    expect(preflightOf(h.listeners).map((entry) => entry.closes)).toEqual([1, 1, 1]);
    expect((await providerEvidence(h)).launches[0].acquisition).toEqual({ outcome: "acquired", evidence: "unavailable" });
  });

  it("a stop-capture failure cannot prevent cleanup: the termination check still runs and every listener is closed", async () => {
    const h = await harness({
      shortCanary: true,
      providerNeverReady: true,
      stopResultRaw: (role, base) =>
        role === "provider"
          ? Object.defineProperty({ ...base }, "killSent", {
              get() {
                throw new Error("stop evidence failure");
              },
            })
          : base,
    });
    await h.deps.prepare(h.fixture, h.row);
    await expect(h.deps.preflight(h.fixture, h.row)).rejects.toThrow(/^preflight fake provider did not report readiness$/);
    expect(h.stops.map((stop) => stop.role)).toEqual(["provider"]);
    expect(preflightOf(h.listeners).map((entry) => entry.closes)).toEqual([1, 1, 1]);
    const collected = await h.deps.collect(h.fixture, h.row);
    expect(collected.files["evidence/provider-launches"].launches[0].stop).toEqual({ outcome: "returned", evidence: "unavailable" });
    expect(collected.files["evidence/cleanup-problems"]).toEqual([]);
  });

  it("scenario and lifecycle teardown record the provider stop too (shared teardown path)", async () => {
    const h = await harness({ providerExit: { code: null, signal: "SIGABRT" }, timing: { startupMs: 5_000 } });
    await h.deps.prepare(h.fixture, h.row);
    await expect(h.deps.scenario(h.fixture, h.row, "pilot-ask-once")).rejects.toThrow(/exited before reporting readiness/);
    await expect(h.deps.lifecycle(h.fixture, h.row)).rejects.toThrow(/exited before reporting readiness/);
    const evidence = await providerEvidence(h);
    expect(evidence.launches.map((record: { label: string }) => record.label)).toEqual(["pilot-ask-once.provider", "lifecycle.provider"]);
    for (const record of evidence.launches) {
      expect(record).toMatchObject({ startup: { outcome: "exited-before-ready" }, exit: { event: "exit", code: null, signal: "SIGABRT" }, stop: { outcome: "returned", aliveAfter: false } });
    }
  });
});

describe("runtime + runner + report: the final serialized report leaks no credentials (Amendment A3)", () => {
  const SECRET = "sk-injected-secret-value-123";
  const runRow = (row: { id: string; family: string; version: string }) => ({ ...row, sourceCommit: "c", binary: { path: "/x" } });
  const passingProbe = (argv: string[], { providerToken }: { providerToken: string }) => {
    const sandboxed = argv[0] === "/usr/bin/sandbox-exec";
    const [op, target] = argv.slice(-2);
    if (op === "http-get") return JSON.stringify({ completed: true, op, outcome: "allowed", status: 200, body: JSON.stringify({ token: providerToken }) });
    if (!sandboxed) return JSON.stringify({ completed: true, op, outcome: "allowed" });
    return JSON.stringify(target.includes("canary") || op.startsWith("connect") ? { completed: true, op, outcome: "denied", code: "EPERM" } : { completed: true, op, outcome: "allowed" });
  };
  const finalReport = async (h: Awaited<ReturnType<typeof harness>>) => {
    const result = await runMatrix({ rows: [runRow(h.row)], mode: "pilot", tarballSha256: "t", deps: h.deps, workBudgetMs: 60_000 });
    const report = buildReport({ executed: result.rows.some((row: { executed: boolean }) => row.executed), rows: result.rows, mode: "pilot" });
    return { result, text: JSON.stringify(sanitize(report, { realHome: "/Users/someone", repoRoot: "/repo", fixtureRoot: h.manifest.runRoot, secrets: h.deps.secrets() })) };
  };

  it("a capture failure before spawn: the report carries the capture failure and no credential", async () => {
    const h = await harness({ shortCanary: true });
    const original = h.deps.prepare.bind(h.deps);
    h.deps.prepare = async (fixture: { run: string }, row: unknown) => {
      await original(fixture, row);
      await writeFile(join(fixture.run, "profile.sb"), Buffer.alloc(65537, 0x3b));
    };
    const { result, text } = await finalReport(h);
    expect(result.rows[0].failure).toEqual({ stage: "preflight", message: "provider launch evidence capture failed: profile exceeds 65536 bytes" });
    expect(text).toContain('"reason":"profile exceeds 65536 bytes"');
    expect(h.providerTokens).toEqual([]); // nothing was launched
    expect(text).not.toMatch(/tok\d{9}/); // no harness-generated token of any kind reached the report
  });

  it("a rejected provider stop: the report carries the bounded stop error and no message, token, or secret", async () => {
    const h = await harness({ shortCanary: true, providerNeverReady: true, stopReject: (role) => (role === "provider" ? Object.assign(new Error(`stop failed ${SECRET}`), { code: "EPERM" }) : undefined) });
    const { result, text } = await finalReport(h);
    expect(result.rows[0].failure).toEqual({ stage: "preflight", message: "preflight fake provider did not report readiness" });
    expect(text).toContain('"stop":{"outcome":"rejected","error":{"name":"Error","code":"EPERM"}}');
    expect(text).toContain("raw profile bytes used for this launch");
    expect(text).not.toContain(SECRET);
    expect(h.providerTokens).toHaveLength(1);
    for (const token of h.providerTokens) expect(text).not.toContain(token);
  });

  it("a passing preflight and a launched host: neither the provider identity tokens nor the host password reach the report", async () => {
    const h = await harness({
      shortCanary: true,
      probe: passingProbe,
      hostHandler: () => new Response("[]", { status: 200 }), // no auth challenge: the scenario fails after the host launched
      stopReject: (role) => (role === "provider" && h2.launched() ? Object.assign(new Error(`stop failed ${PASSWORD} ${SECRET}`), { code: "EPERM" }) : undefined),
    });
    const h2 = { launched: () => h.launches.some((launch) => launch.role === "host") };
    const { result, text } = await finalReport(h);
    expect(result.rows[0].failure?.stage).toBe("teardown");
    expect(h.launches.map((launch) => launch.role)).toContain("host");
    expect(h.providerTokens).toHaveLength(2);
    for (const token of h.providerTokens) expect(text).not.toContain(token);
    expect(text).not.toContain(PASSWORD);
    expect(text).not.toContain(SECRET);
  });
});
