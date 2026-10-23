import { createHash } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync, gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";

import { UNVERIFIED_CONTRACTS } from "./contracts.mjs";
import { canonicalPath, checkRuntimeGates } from "./gates.mjs";
import { PACKAGE_NAME } from "./package-stage.mjs";
import { forecastCanarySocketPath } from "./socket-path.mjs";

// Structural gate fixtures are SYNTHETIC: small archives and files whose
// hashes are injected through `matrix`. Nothing here claims anything about
// the real artifacts.
const created: string[] = [];
afterEach(async () => {
  for (const dir of created.splice(0)) await rm(dir, { recursive: true, force: true });
});
const sha = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
const sri = (data: Buffer) => `sha512-${createHash("sha512").update(data).digest("base64")}`;

function zipOf(name: string, text: string): Buffer {
  const raw = Buffer.from(text);
  const body = deflateRawSync(raw);
  const n = Buffer.from(name);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(8, 8);
  local.writeUInt32LE(body.length, 18);
  local.writeUInt32LE(raw.length, 22);
  local.writeUInt16LE(n.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(0x031e, 4);
  central.writeUInt16LE(8, 10);
  central.writeUInt32LE(body.length, 20);
  central.writeUInt32LE(raw.length, 24);
  central.writeUInt16LE(n.length, 28);
  central.writeUInt32LE((0o100755 << 16) >>> 0, 38);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(46 + n.length, 12);
  end.writeUInt32LE(30 + n.length + body.length, 16);
  return Buffer.concat([local, n, body, central, n, end]);
}
function tgzOf(name: string, text: string): Buffer {
  const data = Buffer.from(text);
  const h = Buffer.alloc(512);
  h.write(name, 0, 100);
  h.write("0000755\0", 100);
  h.write(data.length.toString(8).padStart(11, "0") + "\0", 124);
  h.write("        ", 148);
  h.write("0", 156);
  h.write("ustar\0", 257);
  h.write("00", 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return gzipSync(Buffer.concat([h, data, Buffer.alloc(512 - data.length), Buffer.alloc(1024)]));
}

const LIMITS = { maxEntries: 4, maxExpandedBytes: 4096, maxFileBytes: 4096 };

function packedTarball(version: unknown): Buffer {
  const data = Buffer.from(JSON.stringify({ name: PACKAGE_NAME, version }));
  const h = Buffer.alloc(512);
  h.write("package/package.json", 0, 100);
  h.write("0000644\0", 100);
  h.write(data.length.toString(8).padStart(11, "0") + "\0", 124);
  h.write("        ", 148);
  h.write("0", 156);
  h.write("ustar\0", 257);
  h.write("00", 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return gzipSync(Buffer.concat([h, data, Buffer.alloc((512 - (data.length % 512)) % 512), Buffer.alloc(1024)]));
}

async function stagedManifest() {
  const base = await realpath(await mkdtemp(join(tmpdir(), "rh-gate-")));
  created.push(base);
  const staging = join(base, "staging");
  const installed = join(base, "installed");
  await mkdir(staging);
  await mkdir(installed);
  const put = async (dir: string, name: string, data: string | Buffer) => {
    await writeFile(join(dir, name), data);
    return { path: join(dir, name), sha256: sha(data) };
  };
  const floorZip = zipOf("opencode", "v1-floor-binary");
  const v2Tgz = tgzOf("package/bin/opencode", "v2-binary");
  const dailySource = await put(installed, "opencode", "v1-daily-binary");
  const matrix = [
    { id: "v1-floor", family: "v1", version: "1.18.29", sourceCommit: "a", artifact: { kind: "zip", sha256: sha(floorZip), size: floorZip.length } },
    { id: "v1-daily", family: "v1", version: "1.18.35", sourceCommit: "b", artifact: { kind: "local-copy", path: dailySource.path } },
    { id: "v2", family: "v2", version: "2.0.28", sourceCommit: "c", artifact: { kind: "tgz", integrity: sri(v2Tgz) } },
  ];
  const reviewedContracts = Object.fromEntries(UNVERIFIED_CONTRACTS.map(({ key }: { key: string }) => [key, { review: "user-approved recipe R1", value: null }]));
  reviewedContracts["hosts.versionArgv"].value = ["--version"];
  const members = (name: string) => ({ required: [name], allowed: [name] });
  return {
    base,
    matrix,
    manifest: {
      approvals: { gate2: "user approval A2", gate3: "user approval A3" },
      platform: { os: "darwin", arch: "arm64" },
      runRoot: join(base, "runs"),
      // Short synthetic canary root (Amendment A2 socket forecast). It is never touched on disk:
      // the test resolver canonicalizes "/fixture/..." paths purely (see syntheticCanonical).
      canaryRoot: "/fixture/c",
      stagingRoot: staging,
      reportPath: join(base, "report.json"),
      node: { ...(await put(staging, "node", "node-binary")), version: "v24.15.0" },
      tarball: await put(staging, "pkg.tgz", packedTarball("0.1.0")),
      sandbox: { machServices: ["com.apple.system.notification_center"] },
      reviewedContracts,
      v2: { providers: { fake: { baseURL: "{providerBaseURL}" } }, model: "fake/fake-model", dependencyRegions: ["cache/opencode/npm"] },
      rows: [
        {
          id: "v1-floor",
          binary: await put(staging, "v1-floor", "v1-floor-binary"),
          provenance: { archive: await put(staging, "floor.zip", floorZip), member: "opencode", limits: LIMITS, members: members("opencode") },
          cache: { root: "{XDG_CACHE_HOME}/opencode", specDir: `${PACKAGE_NAME}@latest` },
        },
        {
          id: "v1-daily",
          binary: await put(staging, "v1-daily", "v1-daily-binary"),
          provenance: { source: { path: dailySource.path, sha256: dailySource.sha256 } },
          cache: { root: "{XDG_CACHE_HOME}/opencode", specDir: `${PACKAGE_NAME}@latest` },
        },
        {
          id: "v2",
          binary: await put(staging, "v2", "v2-binary"),
          provenance: { archive: { ...(await put(staging, "v2.tgz", v2Tgz)), integrity: sri(v2Tgz) }, member: "package/bin/opencode", limits: LIMITS, members: members("package/bin/opencode") },
          cache: { root: "{XDG_CACHE_HOME}/opencode", specDir: `${PACKAGE_NAME}@0.1.0`, generation: "0" },
        },
      ],
    } as Record<string, any>,
  };
}

/**
 * Injected canonical resolver: synthetic "/fixture/..." paths resolve purely (no filesystem
 * access; `aliases` maps an alias to its canonical form); every other path uses the real
 * canonicalPath. Each call is recorded in order.
 */
function syntheticCanonical(aliases: Record<string, string> = {}, calls: string[] = []) {
  return async (path: string) => {
    calls.push(path);
    if (path === "/fixture" || path.startsWith("/fixture/")) return aliases[path] ?? path;
    return canonicalPath(path);
  };
}

const context = (matrix: unknown, extra: Record<string, unknown> = {}) => ({ platform: "darwin", arch: "arm64", realHome: "/Users/someone", exists: async () => true, matrix, canonicalize: syntheticCanonical(), ...extra });

describe("canonical paths", () => {
  it("resolves the nearest existing ancestor and keeps nonexistent final components", async () => {
    const base = await realpath(await mkdtemp(join(tmpdir(), "rh-canon-")));
    created.push(base);
    await mkdir(join(base, "real"));
    await symlink(join(base, "real"), join(base, "alias"));
    expect(await canonicalPath(join(base, "alias", "not", "yet"))).toBe(join(base, "real", "not", "yet"));
    await expect(canonicalPath(`${base}/x/../y`)).rejects.toThrow(/\.\./);
    await expect(canonicalPath("relative/path")).rejects.toThrow(/absolute/);
  });
});

describe("runtime gates", () => {
  it("passes a fully staged, approved, reviewed manifest with linked provenance and returns verified hashes", async () => {
    const { manifest, matrix } = await stagedManifest();
    const result = await checkRuntimeGates(manifest, context(matrix));
    expect(result.problems).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.verified.packageSpec).toEqual({ name: PACKAGE_NAME, version: "0.1.0", spec: `${PACKAGE_NAME}@0.1.0` });
    expect(result.verified.rows.map((row: { id: string; provenance: { kind: string } }) => [row.id, row.provenance.kind])).toEqual([
      ["v1-floor", "archive-member"],
      ["v1-daily", "installed-source"],
      ["v2", "archive-member"],
    ]);
  });

  it("is closed with no manifest", async () => {
    const result = await checkRuntimeGates(undefined, context(undefined));
    expect(result.ok).toBe(false);
    expect(result.problems.join()).toMatch(/no run manifest/);
  });

  it.each([
    ["missing Gate 2 approval", (m: any) => delete m.approvals.gate2, /gate2 approval/],
    ["missing Gate 3 approval", (m: any) => (m.approvals.gate3 = " "), /gate3 approval/],
    ["a staged binary whose bytes changed", (m: any) => (m.rows[0].binary.sha256 = "0".repeat(64)), /v1-floor binary.*hash mismatch/],
    ["a binary not extracted from the verified archive", (m: any) => (m.rows[0].provenance.member = "other"), /v1-floor.*provenance.*member/],
    ["an archive that is not the plan artifact", (m: any) => (m.rows[0].provenance.archive.sha256 = "e".repeat(64)), /v1-floor.*archive/],
    ["a V2 binary whose digest differs from the archive member", (m: any) => (m.rows[2].binary = m.rows[1].binary), /v2.*(provenance|outside)/],
    ["a daily binary that is not the installed source", (m: any) => (m.rows[1].provenance.source.sha256 = "f".repeat(64)), /v1-daily.*source/],
    ["unreviewed archive limits", (m: any) => (m.rows[2].provenance.limits = { maxEntries: 4 }), /v2.*limits/],
    ["a node executable outside the staging root", (m: any) => (m.node.path = "/usr/bin/true"), /node.*outside the staging root/],
    ["a tarball without a recorded hash", (m: any) => (m.tarball.sha256 = null), /tarball.*no recorded hash/],
    ["a manifest-supplied launch argv", (m: any) => (m.rows[1].launchArgv = ["serve", "--pure"]), /launchArgv is harness-owned/],
    ["a V1 cache spec that is not the source-verified layout", (m: any) => (m.rows[0].cache.specDir = "spec"), /v1-floor.*cache.*@latest/],
    ["an unreviewed contract", (m: any) => delete m.reviewedContracts["sandbox.machServices"], /unreviewed contract.*sandbox.machServices/],
    ["unresolved Mach services", (m: any) => delete m.sandbox.machServices, /Mach services/],
    ["a missing version argv", (m: any) => (m.reviewedContracts["hosts.versionArgv"].value = null), /versionArgv/],
    ["a run root inside the real home", (m: any) => (m.runRoot = "/Users/someone/tmp/runs"), /runRoot.*real home/],
    ["a canary root inside the run root", (m: any) => (m.canaryRoot = join(m.runRoot, "canary")), /canaryRoot.*overlap/],
    ["an unknown row", (m: any) => m.rows.push({ ...m.rows[0], id: "v3" }), /unknown matrix row v3/],
    ["missing reviewed V2 values", (m: any) => delete m.v2.providers, /v2\.providers/],
    ["unsafe V2 dependency regions", (m: any) => (m.v2.dependencyRegions = ["../escape"]), /dependencyRegions/],
    ["a manifest-supplied server password", (m: any) => (m.hostEnv = { v1: { OPENCODE_SERVER_PASSWORD: "x" } }), /hostEnv/],
    ["an unsafe cache spec directory", (m: any) => (m.rows[2].cache.specDir = "../x"), /specDir/],
    ["a V2 cache key that is not the exact packed spec", (m: any) => (m.rows[2].cache.specDir = PACKAGE_NAME), /v2: cache spec must be the exact packed spec @skwid138\/opencode-command-normalizer@0\.1\.0/],
    ["a V2 cache key with a different version", (m: any) => (m.rows[2].cache.specDir = `${PACKAGE_NAME}@0.2.0`), /exact packed spec/],
  ])("is closed for %s", async (_label, mutate, message) => {
    const { manifest, matrix } = await stagedManifest();
    mutate(manifest);
    const result = await checkRuntimeGates(manifest, context(matrix));
    expect(result.ok).toBe(false);
    expect(result.problems.join("\n")).toMatch(message);
  });

  it.each([["^0.1.0"], ["latest"], ["0.1"], ["1.2.3-01"]])("is closed before staging when the packed manifest version is %j (not exact)", async (version) => {
    const { manifest, matrix } = await stagedManifest();
    const bytes = packedTarball(version);
    await writeFile(manifest.tarball.path, bytes);
    manifest.tarball.sha256 = sha(bytes);
    const result = await checkRuntimeGates(manifest, context(matrix));
    expect(result.ok).toBe(false);
    expect(result.problems.join()).toMatch(/packed manifest needs an exact version/);
    expect(result.verified.packageSpec).toBeNull();
  });

  it("catches a symlink alias into the real home and overlap through a symlink", async () => {
    const { manifest, matrix, base } = await stagedManifest();
    const syntheticHome = join(base, "synthetic-home");
    await mkdir(syntheticHome);
    await symlink(syntheticHome, join(base, "alias-to-home"));
    const aliased = { ...manifest, runRoot: join(base, "alias-to-home", "runs") };
    expect((await checkRuntimeGates(aliased, context(matrix, { realHome: syntheticHome }))).problems.join()).toMatch(/runRoot.*real home/);

    await mkdir(join(base, "runs-real"));
    await symlink(join(base, "runs-real"), join(base, "runs-link"));
    const overlapping = { ...manifest, runRoot: join(base, "runs-real"), canaryRoot: join(base, "runs-link", "canary") };
    expect((await checkRuntimeGates(overlapping, context(matrix))).problems.join()).toMatch(/runRoot and canaryRoot overlap/);
  });

  it("is closed when the forecast canary socket path exceeds the Darwin harness limit (long canary root)", async () => {
    const { manifest, matrix } = await stagedManifest();
    manifest.canaryRoot = `/fixture/${"r".repeat(128)}`;
    expect(Buffer.byteLength(forecastCanarySocketPath(manifest.canaryRoot))).toBeGreaterThan(103);
    const result = await checkRuntimeGates(manifest, context(matrix));
    expect(result.ok).toBe(false);
    expect(result.problems.join("\n")).toMatch(/canaryRoot: forecast canary socket: Unix socket path is \d+ UTF-8 bytes; the Darwin harness limit is 103/);
  });

  it("forecasts from the canonical canary root: 103 bytes passes, 104 bytes is closed", async () => {
    const { manifest, matrix } = await stagedManifest();
    // Pure synthetic roots ("/fixture/" is 9 bytes, the forecast suffix 32): nothing is resolved on disk.
    const rootOf = (forecastBytes: number) => `/fixture/${"r".repeat(forecastBytes - 32 - 9)}`;
    manifest.canaryRoot = rootOf(103);
    expect(Buffer.byteLength(forecastCanarySocketPath(manifest.canaryRoot))).toBe(103);
    expect(await checkRuntimeGates(manifest, context(matrix))).toMatchObject({ ok: true, problems: [] });
    manifest.canaryRoot = rootOf(104);
    expect((await checkRuntimeGates(manifest, context(matrix))).problems.join()).toMatch(/canaryRoot: forecast canary socket: Unix socket path is 104 UTF-8 bytes/);
  });

  it("forecasts from the canonical canary root, not the manifest string: a short alias of a long directory is closed", async () => {
    const { manifest, matrix } = await stagedManifest();
    const longCanary = `/fixture/${"long-canary-directory-".repeat(4)}canary`;
    const calls: string[] = [];
    manifest.canaryRoot = "/fixture/l";
    expect(Buffer.byteLength(forecastCanarySocketPath(manifest.canaryRoot))).toBeLessThanOrEqual(103);
    const result = await checkRuntimeGates(manifest, context(matrix, { canonicalize: syntheticCanonical({ "/fixture/l": longCanary }, calls) }));
    // The gate resolves the real home first, then every root in order, through the injected resolver.
    expect(calls).toEqual(["/Users/someone", manifest.runRoot, "/fixture/l", manifest.stagingRoot]);
    expect(result.verified.roots.canaryRoot).toBe(longCanary);
    const longBytes = Buffer.byteLength(forecastCanarySocketPath(longCanary));
    expect(longBytes).toBeGreaterThan(103);
    expect(result.problems).toEqual([`canaryRoot: forecast canary socket: Unix socket path is ${longBytes} UTF-8 bytes; the Darwin harness limit is 103 (sun_path holds 104 including the terminating NUL): ${forecastCanarySocketPath(longCanary)}`]);
  });

  it("uses the real canonicalPath when no resolver is injected (production default)", async () => {
    const { manifest, matrix, base } = await stagedManifest();
    // A symlink alias inside the launcher-owned isolation root resolves to its real target.
    await mkdir(join(base, "real-canary"));
    await symlink(join(base, "real-canary"), join(base, "canary-alias"));
    manifest.canaryRoot = join(base, "canary-alias", "c");
    const result = await checkRuntimeGates(manifest, context(matrix, { canonicalize: undefined }));
    expect(result.verified.roots.canaryRoot).toBe(join(base, "real-canary", "c"));
  });

  it("is closed on the wrong platform or without the system sandbox-exec", async () => {
    const { manifest, matrix } = await stagedManifest();
    expect((await checkRuntimeGates(manifest, context(matrix, { platform: "linux" }))).problems.join()).toMatch(/platform/);
    expect((await checkRuntimeGates(manifest, context(matrix, { arch: "x64" }))).problems.join()).toMatch(/arch/);
    expect((await checkRuntimeGates(manifest, context(matrix, { exists: async (p: string) => p !== "/usr/bin/sandbox-exec" }))).problems.join()).toMatch(/sandbox-exec/);
  });
});
