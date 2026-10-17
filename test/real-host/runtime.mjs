// Real runtime dependencies for runner.mjs. NOT EXECUTED IN GATE 1.
//
// In production this starts real processes (the sandboxed fake provider,
// preflight and version probes, and the sandboxed OpenCode host) and opens
// loopback sockets. Every such boundary is injectable through `io` and the
// supervisor, so the wiring itself is unit-tested with fakes and no sockets.
//
// Ordering guarantees per host launch:
//   1. the fake provider proves its per-instance identity token,
//   2. the host is started with a fixture-only random server password,
//   3. no host request is sent until the auth challenge proves the listener
//      is that fresh instance (401 + Basic challenge, then 2xx with the password),
//   4. every request and the SSE stream carry Basic auth and refuse redirects,
//   5. teardown checks every stopGroup result; a survivor is a teardown failure.
import { createHash, randomBytes } from "node:crypto";
import { closeSync, openSync } from "node:fs";
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { diffInventory, inventoryTree } from "./artifacts.mjs";
import { PLUGIN_ID, VERIFIED_CONTRACTS, expectedVersionOutput, versionOutputMatches } from "./contracts.mjs";
import { HOST_SHELL, SYSTEM_PATH_DIRS, buildHostEnv, createFixture, generateServerPassword, hostEnvProblems, isInside } from "./env.mjs";
import { createEventRecorder, executeScenario } from "./executor.mjs";
import { IDENTITY_PATH } from "./fake-provider.mjs";
import { FAKE_MODEL_ID, FAKE_PROVIDER_ID, v1Host } from "./host-v1.mjs";
import { v2Host } from "./host-v2.mjs";
import { createHttpClient, openEventStream, readEventStream, verifyAuthChallenge } from "./http.mjs";
import { DEFAULT_LISTENER_CLOSE_MS, createListenerOwnership } from "./listener-ownership.mjs";
import { PACKAGE_NAME, readPackedManifest, stagePackage, verifyStagedPackage } from "./package-stage.mjs";
import { createProviderEvidence, errorSummary } from "./provider-evidence.mjs";
import { waitForProviderStartup } from "./provider-startup.mjs";
import { candidateProfile, evaluatePreflight, preflightPlan, sandboxArgv } from "./sandbox.mjs";
import { evaluateLifecycle, evaluateLifecyclePhase, evaluateScenario, fixtureExecutables, parseExecRecord, probeScript, scenarioMatrix, sleepScript } from "./scenarios.mjs";
import { CANARY_PREFIX, canarySocketPath, socketPathProblem } from "./socket-path.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const DEFAULT_TIMING = Object.freeze({
  startupMs: 30_000,
  connectMs: 10_000,
  askMs: 30_000,
  debugRecordMs: 5_000,
  completionMs: 60_000,
  settleMs: 1_000,
  pollMs: 100,
  probeMs: 10_000,
  inventoryMs: 15_000,
  listenerCloseMs: DEFAULT_LISTENER_CLOSE_MS,
});
export const DEFAULT_PROVIDER_CALL_BUDGET = 12;

/** Source-derived V1 config-dir preload (contracts "v1.installFastPath"). */
export function v1ConfigPreload(version) {
  const deps = { "@opencode-ai/plugin": version };
  return {
    "package.json": `${JSON.stringify({ dependencies: deps }, null, 2)}\n`,
    "package-lock.json": `${JSON.stringify({ name: "opencode", lockfileVersion: 3, requires: true, packages: { "": { dependencies: deps } } }, null, 2)}\n`,
    ".gitignore": ["node_modules", "package.json", "package-lock.json", "bun.lock", ".gitignore"].join("\n"),
  };
}

/**
 * Exact dependency regions (relative to the fixture root) that must never
 * change during a run: dependency/lock metadata, the plugin package caches
 * (which hold the original staged package content), the fixture HOME/.npm
 * cache, and the fixture HOME/.npmrc registry setting. Everything else (the
 * database, logs, state, host log dirs) is an allowed runtime write.
 */
export function dependencyRegions(family, manifest, stagedRel) {
  const base =
    family === "v2"
      ? manifest.v2.dependencyRegions.map((region) => `xdg/${region}`)
      : ["xdg/config/opencode/node_modules", "xdg/config/opencode/package.json", "xdg/config/opencode/package-lock.json", "xdg/config/opencode/.gitignore", "xdg/cache/opencode/packages"];
  return [...new Set([...base, ...(stagedRel ? [stagedRel] : []), "home/.npm", "home/.npmrc"])];
}

const BASELINE_FILE = "dependency-baseline.json";

class TeardownError extends Error {
  constructor(message) {
    super(message);
    this.stage = "teardown";
  }
}

function allocatePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

export function countingListener(listenArgs, { createServer: makeServer = createServer } = {}) {
  return new Promise((resolve, reject) => {
    const state = { connections: 0 };
    const server = makeServer((socket) => {
      state.connections += 1;
      socket.destroy();
    });
    server.once("error", reject);
    // close() resolves only when the server.close callback confirms (Amendment A2); the
    // return of server.close() is not confirmation. A callback error rejects.
    const close = () => new Promise((done, fail) => server.close((error) => (error ? fail(error) : done())));
    server.listen(...listenArgs, () => resolve({ close, state, address: server.address() }));
  });
}

export const DEFAULT_IO = Object.freeze({
  allocatePort,
  listen: (listenArgs) => countingListener(listenArgs),
  transport: (...args) => globalThis.fetch(...args),
  randomToken: (bytes = 12) => randomBytes(bytes).toString("hex"),
  generatePassword: generateServerPassword,
  /**
   * The only filesystem operations on the canary directory (create in prepare, canary-read in
   * preflight, removal in removeRoot). Production uses node:fs/promises directly; the seam lets
   * tests back a short synthetic canary path with an owned directory (Amendment A2).
   */
  canaryFs: Object.freeze({ mkdtemp, writeFile, rm }),
});

async function readText(path) {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return "";
    throw error;
  }
}

async function readLines(path) {
  return (await readText(path))
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return { unparseable: line };
      }
    });
}

/** Parsed execution records for evidence (malformed records stay visible to the evaluator). */
async function readExecRecords(dir) {
  const names = (await readdir(dir)).filter((name) => name.endsWith(".rec")).sort();
  const records = [];
  for (const name of names) records.push(parseExecRecord(await readFile(join(dir, name))));
  return records;
}

/**
 * Lineage pids for the retention gate. Strict: once prepare has created the
 * record directory it must exist; a malformed record, an unexpected entry, or
 * any read error throws, so the root is retained (never deleted on doubt).
 * Absence is legitimate only when prepare never created the directory. An
 * in-flight `.tmp-<pid>` file (record written but not yet renamed) is lineage.
 * Nothing is fabricated and nothing here selects a process to signal.
 */
async function readExecLineage(dir, expected) {
  let names;
  try {
    names = await readdir(dir);
  } catch (error) {
    if (error?.code === "ENOENT" && !expected) return [];
    if (error?.code === "ENOENT") throw new Error(`expected execution record directory ${dir} is missing`);
    throw error;
  }
  const pids = [];
  for (const name of names.sort()) {
    const tmp = /^\.tmp-(\d+)$/.exec(name);
    if (tmp) {
      pids.push(Number(tmp[1]));
      continue;
    }
    if (!/^exec-\d+\.rec$/.test(name)) throw new Error(`unexpected entry ${name} in ${dir}`);
    const record = parseExecRecord(await readFile(join(dir, name)));
    if (record.malformed) throw new Error(`malformed execution record ${name}: ${record.malformed}`);
    pids.push(record.pid);
  }
  return pids;
}

function providerSummary(ledger) {
  const calls = ledger.filter((entry) => entry.kind !== "identity");
  return {
    calls: calls.length,
    budgetExceeded: calls.some((entry) => entry.kind === "budget-exceeded"),
    rejected: calls.filter((entry) => entry.kind === "rejected").length,
    toolNotAdvertised: calls.filter((entry) => entry.kind === "tool-not-advertised").length,
    ledger: calls,
  };
}

async function inventoryRegions(xdgRoot, regions) {
  const result = new Map();
  for (const region of regions) {
    const full = join(xdgRoot, region);
    let tree;
    try {
      tree = await inventoryTree(full);
      result.set(region, { type: "directory", digest: "" });
      for (const [rel, entry] of tree) result.set(`${region}/${rel}`, entry);
    } catch (error) {
      if (error?.code === "ENOTDIR") result.set(region, { type: "file", digest: await readText(full) });
      else if (error?.code === "ENOENT") continue; // absent: creation later shows as "added", deletion as "removed"
      else throw error;
    }
  }
  return result;
}

export function createRuntimeDeps({ manifest, verified, supervisor, realHome, timing = DEFAULT_TIMING, io = DEFAULT_IO }) {
  const state = new Map();
  const secrets = new Set();
  /** Fixture roots whose execution record directory prepare has created (absence is then an error). */
  const recordDirsCreated = new Set();
  /** Immutable per-fixture dependency baselines: never advanced, persisted to evidence with an in-memory digest. */
  const baselines = new Map();
  /**
   * Cleanup ownership for every listener this run opens (the prepare registry tripwire and the
   * preflight listeners), registered per fixture root the moment each exists (Amendment A2).
   * Each listener has one shared close attempt, confirmed only by its close callback and
   * bounded by a separate listenerCloseMs deadline that is independent of the work signal.
   * Outcomes stay available to collect and removeRoot; an unconfirmed close retains the root.
   */
  const listenerOwnership = createListenerOwnership({ closeMs: timing.listenerCloseMs ?? DEFAULT_LISTENER_CLOSE_MS });
  /** Bounded, provider-only launch evidence (Amendment A3), kept in memory per fixture root. */
  const providerEvidence = createProviderEvidence();
  /** Path redaction for the profile's diagnostic text (the raw-byte digest is taken before this). */
  const redactPaths = (text, fixture) => {
    let out = text.split(fixture.root).join("<FIXTURE>");
    if (typeof realHome === "string" && realHome.length > 1) out = out.split(realHome).join("<HOME>");
    return out;
  };
  /** Canary directory filesystem operations (production default: node:fs/promises). */
  const canaryFs = io.canaryFs ?? DEFAULT_IO.canaryFs;
  /** Secondary cleanup failures per fixture root (plain strings), surfaced through collect. */
  const cleanupProblems = new Map();
  const recordCleanupProblems = (root, problems) => {
    if (problems.length === 0) return;
    if (!cleanupProblems.has(root)) cleanupProblems.set(root, []);
    cleanupProblems.get(root).push(...problems);
  };
  const describeOutcome = (outcome) => `${outcome.label} listener close ${outcome.status}${outcome.error ? `: ${outcome.error}` : ""}`;
  /** Attempts every listener close in the group (never throws); records and returns the unconfirmed ones. */
  async function closeListenerGroup(root, group) {
    const problems = (await listenerOwnership.closeGroup(root, group)).filter((outcome) => outcome.status !== "closed").map(describeOutcome);
    recordCleanupProblems(root, problems);
    return problems;
  }
  /** Run-wide work signal (pilot deadline or operator abort), bound by the runner before fixture prepare. */
  let workSignal = null;
  /** Throws once the work signal has aborted; called at every spawn boundary and after deferred awaits. */
  const ensureWork = (where) => {
    if (workSignal?.aborted) throw new Error(`work aborted before ${where}`);
  };
  const hostFor = (row) => (row.family === "v2" ? v2Host : v1Host);
  const manifestRow = (row) => manifest.rows.find((candidate) => candidate.id === row.id);
  const binaryFor = (row) => verified.rows.find((candidate) => candidate.id === row.id).binary.path;
  const execDir = (fixture) => join(fixture.evidence, "exec");
  /**
   * V1: the source-verified bare name (resolved by the host as <name>@latest).
   * V2: the exact gate-verified packed spec, shared by the declaration, the
   * cache key, and the inventory target (Amendment A1).
   */
  const pluginSpecFor = (row) => (row.family === "v2" ? verified.packageSpec.spec : PACKAGE_NAME);

  /**
   * The only spawn path: refuses after the work signal aborts, and stops a group that started while it aborted.
   * A provider launch passes its evidence record; acquisition is recorded synchronously (never throws), so the
   * owned handle is returned or stopped with nothing awaited in between.
   */
  async function spawnGuarded(label, argv, options, record = null) {
    ensureWork(`spawn ${label}`);
    const owned = await supervisor.spawnOwned(argv[0], argv.slice(1), options);
    if (record) providerEvidence.acquired(record, owned);
    if (workSignal?.aborted) {
      await stopChecked(owned.pgid, label, record);
      throw new Error(`work aborted during spawn ${label}`);
    }
    return owned;
  }

  async function spawnLogged(fixture, name, argv, options, record = null) {
    const out = openSync(join(fixture.logs, `${name}.out.log`), "a");
    const err = openSync(join(fixture.logs, `${name}.err.log`), "a");
    try {
      return await spawnGuarded(name, argv, { ...options, stdio: ["ignore", out, err] }, record);
    } finally {
      closeSync(out);
      closeSync(err);
    }
  }

  const minimalEnv = (fixture) => buildHostEnv(fixture, { pathDirs: SYSTEM_PATH_DIRS }, { realHome });

  /** Runs one bounded owned process and returns its stdout, or an infrastructure failure. */
  async function runCaptured(fixture, argv, label) {
    const outPath = join(fixture.run, `${label}-${io.randomToken(4)}.out`);
    const fd = openSync(outPath, "w");
    let owned;
    try {
      owned = await spawnGuarded(label, argv, { cwd: fixture.run, env: minimalEnv(fixture), stdio: ["ignore", fd, "ignore"] });
    } finally {
      closeSync(fd);
    }
    const exited = await Promise.race([owned.exited, sleep(timing.probeMs).then(() => null)]);
    if (!exited) {
      await stopChecked(owned.pgid, label);
      return { ok: false, reason: "timeout", stdout: await readText(outPath) };
    }
    if (exited.code !== 0) return { ok: false, reason: `exit ${exited.code ?? exited.signal}`, stdout: await readText(outPath) };
    return { ok: true, stdout: await readText(outPath) };
  }

  /**
   * Stops an owned group and checks the result. For a provider (record given), the raw result or a
   * bounded rejection is recorded in memory BEFORE the termination check; recording never throws, so
   * evidence cannot take stop authority away. A provider stop rejection is reported by name/code only.
   */
  async function stopChecked(pgid, label, record = null) {
    let result;
    try {
      result = await supervisor.stopGroup(pgid);
    } catch (error) {
      if (!record) throw error;
      providerEvidence.stopRejected(record, error);
      const { name, code } = errorSummary(error);
      throw new TeardownError(`${label} process group ${pgid} stop rejected (${name}${code ? ` ${code}` : ""})`);
    }
    if (record) providerEvidence.stopReturned(record, result);
    if (!result || result.aliveAfter || result.unsafe) throw new TeardownError(`${label} process group ${pgid} survived stop (aliveAfter=${result?.aliveAfter}, unsafe=${result?.unsafe})`);
    return result;
  }

  async function runProbe(fixture, { sandboxed, op, target }) {
    const s = state.get(fixture.root);
    const base = [verified.node.path, join(fixture.run, "probe.mjs"), op, target];
    const run = await runCaptured(fixture, sandboxed ? sandboxArgv(s.profilePath, base) : base, "probe");
    if (!run.ok) return { completed: false, outcome: "infrastructure", reason: run.reason };
    try {
      const parsed = JSON.parse(run.stdout.trim());
      if (parsed?.completed !== true || !["allowed", "denied", "error"].includes(parsed.outcome)) return { completed: false, outcome: "infrastructure", reason: "malformed probe result" };
      return parsed;
    } catch {
      return { completed: false, outcome: "infrastructure", reason: "no probe result" };
    }
  }

  async function startProvider(fixture, { name, toolName, toolCalls, nonce }) {
    const s = state.get(fixture.root);
    const configPath = join(fixture.run, `${name}.provider.json`);
    const portFile = join(fixture.run, `${name}.provider.port`);
    const ledgerPath = join(fixture.evidence, `${name}.provider.jsonl`);
    const identityToken = io.randomToken(16);
    // A3 privacy: the per-instance identity token is redacted from collected evidence and the final
    // report (it can appear in the preflight positive-control body); the identity check is unchanged.
    secrets.add(identityToken);
    await writeFile(
      configPath,
      JSON.stringify({ model: FAKE_MODEL_ID, nonce, toolName, toolCalls: toolCalls.map((command) => ({ command })), identityToken, callBudget: manifest.limits?.providerCallBudget ?? DEFAULT_PROVIDER_CALL_BUDGET }),
      { flag: "wx" },
    );
    const argv = sandboxArgv(s.profilePath, [verified.node.path, join(fixture.run, "fake-provider.mjs"), "--config", configPath, "--port", String(s.providerPort), "--port-file", portFile, "--ledger", ledgerPath]);
    const env = minimalEnv(fixture);
    const label = `${name}.provider`;
    // Amendment A3: the intended launch and the actual profile bytes are captured BEFORE spawn;
    // invalid or oversized evidence fails here, before anything is launched.
    const record = await providerEvidence.begin(fixture.root, { label, argv, cwd: fixture.run, env, profilePath: s.profilePath, redactProfileText: (text) => redactPaths(text, fixture) });
    let owned;
    try {
      owned = await spawnLogged(fixture, label, argv, { cwd: fixture.run, env }, record);
    } catch (error) {
      providerEvidence.spawnFailed(record, error);
      throw error;
    }
    return { owned, record, ledgerPath, portFile, identityToken, url: `http://127.0.0.1:${s.providerPort}` };
  }

  /**
   * Shared provider startup wait for preflight and every host launch (Amendment A3): the port
   * file must appear before the owned launcher exits. Precedence: work abort, then exit, then ready.
   */
  async function awaitProviderStartup(provider, { prefix, where }) {
    let result;
    try {
      result = await waitForProviderStartup({
        isReady: async () => (await readText(provider.portFile)) !== "",
        exited: provider.owned.exited,
        signal: workSignal,
        timeoutMs: timing.startupMs,
        pollMs: timing.pollMs,
      });
    } catch (error) {
      providerEvidence.startup(provider.record, { outcome: "wait-failed" });
      throw error;
    }
    providerEvidence.startup(provider.record, result);
    if (result.outcome === "work-aborted") throw new Error(`work aborted before ${where}`);
    if (result.outcome === "exited-before-ready") throw new Error(`${prefix} exited before reporting readiness (code ${result.exit.code}, signal ${result.exit.signal})`);
    if (result.outcome !== "ready") throw new Error(`${prefix} did not report readiness`);
  }

  /** The provider must be up AND be this run's instance before anything depends on it. */
  async function verifyProvider(provider) {
    await awaitProviderStartup(provider, { prefix: "fake provider", where: "provider identity check" });
    const response = await io.transport(`${provider.url}${IDENTITY_PATH}`, { method: "GET", redirect: "error", signal: AbortSignal.timeout(timing.connectMs) });
    ensureWork("host launch");
    const body = response.status === 200 ? await response.text() : "";
    let token = null;
    try {
      token = JSON.parse(body).token;
    } catch {
      token = null;
    }
    if (response.status !== 200 || token !== provider.identityToken) throw new Error(`fake provider identity check failed (status ${response.status}); refusing to use the port`);
  }

  async function writeHostConfig(fixture, row, config) {
    const path = row.family === "v2" ? join(fixture.root, "config", "opencode.json") : join(fixture.xdg.XDG_CONFIG_HOME, "opencode", "opencode.json");
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(config, null, 2)}\n`);
    return path;
  }

  function buildConfig(fixture, row, scenario) {
    const s = state.get(fixture.root);
    const providerBaseURL = `http://127.0.0.1:${s.providerPort}/v1`;
    const plugin = scenario.plugin ? { spec: pluginSpecFor(row), options: scenario.plugin.options } : null;
    if (row.family === "v2") return v2Host.buildConfig({ plugin, rules: scenario.rules, reviewed: manifest.v2, providerBaseURL });
    return v1Host.buildConfig({ providerBaseURL, plugin, rules: scenario.rules });
  }

  async function startHost(fixture, row, name, configPath) {
    const s = state.get(fixture.root);
    const host = hostFor(row);
    const password = io.generatePassword();
    secrets.add(password);
    const extra = { ...(manifest.hostEnv?.[row.family] ?? {}), OPENCODE_SERVER_PASSWORD: password };
    if (row.family === "v2") Object.assign(extra, { OPENCODE_CONFIG: configPath, [VERIFIED_CONTRACTS["v2.projectConfigDisable"].value]: "1" });
    const env = buildHostEnv(fixture, { pathDirs: [fixture.bin, ...SYSTEM_PATH_DIRS], extra }, { realHome });
    const problems = hostEnvProblems(env, fixture, { realHome });
    if (problems.length > 0) throw new Error(`host environment rejected: ${problems.join("; ")}`);
    const argv = sandboxArgv(s.profilePath, [binaryFor(row), ...host.launchArgv(s.hostPort)]);
    const owned = await spawnLogged(fixture, `${name}.host`, argv, { cwd: fixture.project, env });
    const client = createHttpClient({ baseURL: `http://127.0.0.1:${s.hostPort}`, transport: io.transport, timeoutMs: timing.connectMs, auth: { username: VERIFIED_CONTRACTS.auth.value.username, password } });
    return { owned, client };
  }

  /**
   * Waits (bounded) for the host to answer, then requires the auth challenge.
   * Connection errors during startup are retried; any HTTP answer is final, so
   * a different listener on the port is never retried into acceptance.
   */
  async function verifyHost(fixture, row, client) {
    const route = hostFor(row).routes.identity(fixture.project);
    const deadline = Date.now() + timing.startupMs;
    for (;;) {
      ensureWork("host identity check");
      try {
        const verifiedHost = await verifyAuthChallenge(client, route);
        ensureWork("host control requests");
        return verifiedHost;
      } catch (error) {
        if (workSignal?.aborted) throw error;
        const transportError = error instanceof TypeError || error?.name === "TimeoutError" || error?.cause?.code === "ECONNREFUSED";
        if (!transportError || Date.now() >= deadline) throw error;
        await sleep(timing.pollMs);
      }
    }
  }

  async function openEvents(fixture, row, client) {
    const host = hostFor(row);
    const recorder = createEventRecorder(host);
    const opened = await openEventStream(client, host.routes.events(fixture.project), { timeoutMs: timing.connectMs, signal: workSignal ?? undefined });
    ensureWork("event stream use");
    const done = readEventStream(opened.response.body, (event) => recorder.push(event.data)).catch(() => undefined);
    return {
      recorder,
      close: async () => {
        opened.abort();
        await Promise.race([done, sleep(timing.connectMs)]);
      },
    };
  }

  function evidenceReader(fixture, providerLedgerPath, ledgerOffset = 0) {
    return async () => ({
      executions: await readExecRecords(execDir(fixture)),
      audit: await readLines(join(fixture.logs, "audit.log")),
      decisions: await readLines(join(fixture.logs, "decisions.log")),
      provider: providerSummary((await readLines(providerLedgerPath)).slice(ledgerOffset)),
    });
  }

  /** Stops host and provider; surfaces survivors as a teardown failure without masking an earlier error. */
  async function teardown(groups, events, earlier) {
    const problems = [];
    if (events) await events.close();
    for (const [label, owned, record] of groups) {
      if (!owned) continue;
      try {
        await stopChecked(owned.pgid, label, record ?? null);
      } catch (error) {
        problems.push(error.message);
      }
    }
    if (problems.length > 0) throw new TeardownError(`${earlier ? `${earlier.message}; ` : ""}${problems.join("; ")}`);
    if (earlier) throw earlier;
  }

  async function launch(fixture, row, name, scenario, configPath) {
    const host = hostFor(row);
    const provider = await startProvider(fixture, { name, toolName: host.toolName, toolCalls: scenario.toolCalls, nonce: scenario.nonce });
    let started = null;
    try {
      await verifyProvider(provider);
      started = await startHost(fixture, row, name, configPath);
      await verifyHost(fixture, row, started.client);
      return { provider, started };
    } catch (error) {
      await teardown([["host", started?.owned], ["provider", provider.owned, provider.record]], null, error);
      throw error;
    }
  }

  async function dependencyCheck(fixture) {
    const baseline = baselines.get(fixture.root);
    if (!baseline) return { forbidden: ["dependency baseline evidence missing: prepare did not record one"], changes: [], registryConnections: null };
    let text = null;
    try {
      text = await readFile(join(fixture.evidence, BASELINE_FILE), "utf8");
    } catch (error) {
      return { forbidden: [`dependency baseline evidence missing (${error.code ?? error.message})`], changes: [], registryConnections: null };
    }
    if (createHash("sha256").update(text).digest("hex") !== baseline.digest) {
      return { forbidden: ["dependency baseline evidence corrupt (digest mismatch)"], changes: [], registryConnections: null };
    }
    const current = await inventoryRegions(fixture.root, baseline.regions);
    const diff = diffInventory(baseline.inventory, current, { allowedWritePrefixes: [] });
    const forbidden = [...diff.forbidden];
    // Cumulative since prepare: zero registry connections alone is never treated as proof of no install.
    const connections = state.get(fixture.root).registry.state.connections;
    if (connections > 0) forbidden.push(`npm registry tripwire received ${connections} connection(s) since prepare`);
    return { forbidden, changes: diff.changes, registryConnections: connections };
  }

  const model = { providerID: FAKE_PROVIDER_ID, modelID: FAKE_MODEL_ID };

  return {
    secrets: () => [...secrets],

    bindSignal(signal) {
      workSignal = signal;
    },

    async createFixture(row) {
      await mkdir(verified.roots.runRoot, { recursive: true });
      return createFixture(verified.roots.runRoot, { label: row.id });
    },

    async prepare(fixture, row) {
      // Re-derive the packed spec from the (re-hashed) tarball before anything is staged or launched.
      const packed = await readPackedManifest({ tarballPath: manifest.tarball.path, tarballSha256: manifest.tarball.sha256 });
      if (!verified.packageSpec || packed.spec !== verified.packageSpec.spec) {
        throw new Error(`packed manifest ${packed.spec} does not match the gate-verified spec ${verified.packageSpec?.spec ?? "(none)"}`);
      }
      if (row.family === "v2" && manifestRow(row).cache.specDir !== packed.spec) throw new Error(`V2 cache spec ${manifestRow(row).cache.specDir} is not ${packed.spec}`);
      await mkdir(execDir(fixture), { recursive: true });
      recordDirsCreated.add(fixture.root);
      for (const [name, text] of [["rh-probe", probeScript({ recordDir: execDir(fixture) })], ["rh-sleep", sleepScript({ recordDir: execDir(fixture) })]]) {
        await writeFile(join(fixture.bin, name), text, { flag: "wx" });
        await chmod(join(fixture.bin, name), 0o755);
      }
      for (const name of ["fake-provider.mjs", "probe.mjs"]) await copyFile(join(HERE, name), join(fixture.run, name));
      ensureWork("port allocation");
      const [providerPort, hostPort, tripwirePort] = [await io.allocatePort(), await io.allocatePort(), await io.allocatePort()];
      ensureWork("registry tripwire listener");
      const registry = await io.listen([tripwirePort, "127.0.0.1"]);
      listenerOwnership.register(fixture.root, { group: "registry", label: "registry tripwire", listener: registry });
      try {
        ensureWork("profile and staging");
        // Any npm registry attempt lands on this owned listener (contract npm.userconfigTripwire).
        await writeFile(join(fixture.home, ".npmrc"), `registry=http://127.0.0.1:${tripwirePort}/\n`, { flag: "wx" });
        const profilePath = join(fixture.run, "profile.sb");
        await writeFile(
          profilePath,
          candidateProfile({
            fixtureRoot: fixture.root,
            // Exact paths only: host binary, staged Node, the host shell (env SHELL), and the fixture commands plus what they call.
            executables: [binaryFor(row), verified.node.path, HOST_SHELL, ...fixtureExecutables(fixture.bin)],
            loopbackPorts: [providerPort, hostPort, tripwirePort],
            machServices: manifest.sandbox.machServices,
          }),
          { flag: "wx" },
        );
        if (row.family === "v1") {
          const configDir = join(fixture.xdg.XDG_CONFIG_HOME, "opencode");
          await mkdir(join(configDir, "node_modules"), { recursive: true });
          for (const [name, text] of Object.entries(v1ConfigPreload(row.version))) await writeFile(join(configDir, name), text, { flag: "wx" });
        }
        const cache = manifestRow(row).cache;
        const cacheRoot = cache.root.replace("{XDG_CACHE_HOME}", fixture.xdg.XDG_CACHE_HOME);
        if (!isInside(cacheRoot, fixture.root)) throw new Error(`cache root ${cacheRoot} is outside the fixture`);
        ensureWork("package staging");
        const staged = await stagePackage({ tarballPath: manifest.tarball.path, tarballSha256: manifest.tarball.sha256, family: row.family, cacheRoot, specDir: cache.specDir, generation: cache.generation });
        const identity = await verifyStagedPackage({ packageDir: staged.packageDir, tarballPath: manifest.tarball.path, tarballSha256: manifest.tarball.sha256 });
        ensureWork("baseline");
        if (!identity.ok) throw new Error(`staged package identity failed: ${identity.problems.join("; ")}`);
        const canaryDir = await canaryFs.mkdtemp(join(verified.roots.canaryRoot, CANARY_PREFIX));
        state.set(fixture.root, { row, providerPort, hostPort, tripwirePort, registry, profilePath, canaryDir, packageDir: staged.packageDir });
        const regions = dependencyRegions(row.family, manifest, relative(fixture.root, staged.packageDir));
        const inventory = await inventoryRegions(fixture.root, regions);
        const text = `${JSON.stringify({ version: 1, regions, entries: [...inventory] })}\n`;
        await writeFile(join(fixture.evidence, BASELINE_FILE), text, { flag: "wx" });
        baselines.set(fixture.root, Object.freeze({ regions: Object.freeze([...regions]), inventory, digest: createHash("sha256").update(text).digest("hex") }));
      } catch (error) {
        // A failed or cancelled prepare releases its listener locally (shared close-once attempt);
        // a close failure is recorded for collect and removal, never masking the prepare error.
        await closeListenerGroup(fixture.root, "registry");
        throw error;
      }
    },

    async preflight(fixture) {
      const s = state.get(fixture.root);
      // Amendment A2 backstop: the ACTUAL canary socket path is checked before the first
      // preflight listener (the gate forecast is not the sole proof).
      const socketPath = canarySocketPath(s.canaryDir);
      const socketProblem = socketPathProblem(socketPath);
      if (socketProblem) throw new Error(`preflight refused before any listener: canary ${socketProblem}`);
      await canaryFs.writeFile(join(s.canaryDir, "canary-read"), `canary-${io.randomToken(8)}\n`);
      await writeFile(join(fixture.run, "preflight-read"), "preflight\n");
      const listeners = {};
      let provider = null;
      let primary = null;
      let result = null;
      try {
        // Incremental acquisition inside the protected region: each listener is registered with the
        // fixture the moment it exists, so a later acquisition failure still closes the earlier ones.
        for (const [key, args] of [["ipv4", [0, "127.0.0.1"]], ["ipv6", [0, "::1"]], ["unix", [socketPath]]]) {
          listeners[key] = await io.listen(args);
          listenerOwnership.register(fixture.root, { group: "preflight", label: `preflight ${key}`, listener: listeners[key] });
        }
        provider = await startProvider(fixture, { name: "preflight", toolName: "none", toolCalls: [], nonce: "preflight" });
        await awaitProviderStartup(provider, { prefix: "preflight fake provider", where: "preflight probes" });
        const plan = preflightPlan({
          fixtureRoot: fixture.root,
          canaryRoot: s.canaryDir,
          provider: { url: `${provider.url}${IDENTITY_PATH}`, token: provider.identityToken },
          forbidden: {
            ipv4: { host: "127.0.0.1", port: listeners.ipv4.address.port },
            ipv6: { host: "::1", port: listeners.ipv6.address.port },
            unix: { path: socketPath },
          },
        });
        const observations = {};
        for (const check of plan) {
          const listener = { "forbidden-ipv4": listeners.ipv4, "forbidden-ipv6": listeners.ipv6, "forbidden-unix": listeners.unix }[check.id] ?? null;
          const observation = {};
          if (!check.kind.startsWith("positive")) observation.control = await runProbe(fixture, { sandboxed: false, op: check.op, target: check.target });
          const before = listener?.state.connections ?? 0;
          observation.sandboxed = await runProbe(fixture, { sandboxed: true, op: check.op, target: check.target });
          if (listener) observation.listenerRequests = listener.state.connections - before;
          observations[check.id] = observation;
        }
        result = { ...evaluatePreflight(plan, observations), observations };
      } catch (error) {
        primary = error;
      }
      // Cleanup always attempts every listener close AND the provider stop, even if one fails.
      // The primary error is rethrown unchanged; secondary failures are recorded for collect, and
      // an unconfirmed listener close keeps the fixture root (removeRoot refuses to delete it).
      const problems = await closeListenerGroup(fixture.root, "preflight");
      if (provider) {
        try {
          await stopChecked(provider.owned.pgid, "preflight provider", provider.record);
        } catch (error) {
          problems.push(error.message);
          recordCleanupProblems(fixture.root, [error.message]);
        }
      }
      if (primary) throw primary;
      if (problems.length > 0) throw new TeardownError(`preflight cleanup failed: ${problems.join("; ")}`);
      return result;
    },

    async versionProbe(fixture, row) {
      const s = state.get(fixture.root);
      const argv = sandboxArgv(s.profilePath, [binaryFor(row), ...manifest.reviewedContracts["hosts.versionArgv"].value]);
      const run = await runCaptured(fixture, argv, "version");
      // Whole stdout, exact (contracts "versionOutput"): no trim, no first-line or substring matching.
      const ok = run.ok && versionOutputMatches(row.family, row.version, run.stdout);
      return { ok, expected: expectedVersionOutput(row.family, row.version), observed: run.ok ? run.stdout : `(${run.reason}) ${run.stdout}` };
    },

    async scenario(fixture, row, id) {
      const host = hostFor(row);
      const nonce = io.randomToken(6);
      const scenario = { ...scenarioMatrix({ fixture, nonce }).find((candidate) => candidate.id === id), nonce };
      const configPath = await writeHostConfig(fixture, row, buildConfig(fixture, row, scenario));
      const { provider, started } = await launch(fixture, row, id, scenario, configPath);
      let events = null;
      let earlier = null;
      let result = null;
      try {
        events = await openEvents(fixture, row, started.client);
        const evidence = await executeScenario({
          host,
          client: started.client,
          recorder: events.recorder,
          scenario,
          directory: fixture.project,
          model,
          readDebug: () => readText(join(fixture.logs, "debug.log")),
          readEvidence: evidenceReader(fixture, provider.ledgerPath),
          timing,
          signal: workSignal ?? undefined,
        });
        result = { ...evaluateScenario(scenario, evidence, { fixture, nonce }), evidence: { events: evidence.events, replies: evidence.replies, cancel: evidence.cancel, provider: evidence.provider } };
      } catch (error) {
        earlier = error;
      }
      await teardown([["host", started.owned], ["provider", provider.owned, provider.record]], events, earlier);
      return result;
    },

    async lifecycle(fixture, row) {
      const host = hostFor(row);
      const nonce = io.randomToken(6);
      const scenario = { ...scenarioMatrix({ fixture, nonce }).find((candidate) => candidate.id === "lifecycle"), nonce };
      let config = buildConfig(fixture, row, scenario);
      const decl = row.family === "v2" ? config.plugins[0] : config.plugin[0];
      const configPath = await writeHostConfig(fixture, row, config);
      const { provider, started } = await launch(fixture, row, "lifecycle", scenario, configPath);
      const phases = [];
      let removedIndex = -1;
      let executionOffset = 0;
      let earlier = null;
      let outcome = null;
      const inventory = async (expect) => {
        if (row.family !== "v2") return undefined;
        let last = { ok: false, problems: ["not polled"] };
        const deadline = Date.now() + timing.inventoryMs;
        while (Date.now() < deadline) {
          last = v2Host.evaluateInventory(await started.client.request(v2Host.routes.plugins(fixture.project)), { id: PLUGIN_ID, target: pluginSpecFor(row), expect });
          if (last.ok) break;
          await sleep(timing.pollMs);
        }
        return last;
      };
      const rebuild = async () => {
        await writeHostConfig(fixture, row, config);
        const response = await started.client.request(row.family === "v2" ? v2Host.routes.reload() : v1Host.routes.dispose(fixture.project));
        if (row.family === "v2" ? !v2Host.reloadAccepted(response).accepted : response.status !== 200) throw new Error(`rebuild not accepted (status ${response.status})`);
      };
      try {
        for (const phase of scenario.phases) {
          ensureWork(`lifecycle ${phase.name}`);
          if (phase.name === "removed") {
            const removed = host.removePluginDeclaration(config, decl);
            config = removed.config;
            removedIndex = removed.index;
            await rebuild();
          } else if (phase.name === "restored") {
            config = host.restorePluginDeclaration(config, decl, removedIndex);
            await rebuild();
          }
          const phaseInventory = await inventory(phase.name === "removed" ? "absent" : "active");
          if (phaseInventory && !phaseInventory.ok) {
            // Stop at the first failed inventory: no prompt, no further config mutation.
            phases.push({ name: phase.name, sessionID: null, callID: null, audit: [], inventory: phaseInventory, scenario: { status: "fail", problems: ["not run: inventory failed"] } });
            break;
          }
          const ledgerOffset = (await readLines(provider.ledgerPath)).filter((entry) => entry.kind !== "identity").length;
          const events = await openEvents(fixture, row, started.client);
          try {
            const evidence = await executeScenario({
              host,
              client: started.client,
              recorder: events.recorder,
              scenario,
              phase,
              directory: fixture.project,
              model,
              readDebug: () => readText(join(fixture.logs, "debug.log")),
              readEvidence: evidenceReader(fixture, provider.ledgerPath, ledgerOffset),
              timing,
              signal: workSignal ?? undefined,
            });
            // The execution records are shared by all phases; judge only this phase's.
            const phaseExecutions = evidence.executions.slice(executionOffset);
            executionOffset = evidence.executions.length;
            const judged = evaluateLifecyclePhase(scenario, phase, { ...evidence, executions: phaseExecutions }, { fixture, nonce });
            phases.push({ name: phase.name, sessionID: evidence.sessionID, callID: judged.callID, audit: evidence.audit, inventory: phaseInventory, scenario: judged });
            const cardinality = evidence.audit.filter((record) => record.sessionID === evidence.sessionID && record.callID === judged.callID).length;
            // Stop at the first failed behavior or cardinality: no later config mutation or prompt.
            if (judged.status !== "pass" || cardinality !== phase.audits) break;
          } finally {
            await events.close();
          }
        }
        outcome = { ...evaluateLifecycle(phases), phases: phases.map(({ name, sessionID, callID, inventory: inv, scenario: judged }) => ({ name, sessionID, callID, inventory: inv, scenario: judged })) };
      } catch (error) {
        earlier = error;
      }
      await teardown([["host", started.owned], ["provider", provider.owned, provider.record]], null, earlier);
      return outcome;
    },

    /** Per-step check against the immutable baseline (never advanced), plus the cumulative registry tripwire. */
    async tripwire(fixture) {
      return dependencyCheck(fixture);
    },

    /**
     * Final integrity, run by the runner after owned processes are stopped and
     * before the fixture is deleted (normal, failure, and deadline paths). A
     * missing baseline is an explicit skip only when prepare never made one.
     */
    async finalIntegrity(fixture) {
      if (!baselines.has(fixture.root)) return { ok: true, skipped: "no baseline: prepare did not complete", problems: [] };
      const check = await dependencyCheck(fixture);
      const problems = [...check.forbidden];
      const s = state.get(fixture.root);
      try {
        const content = await verifyStagedPackage({ packageDir: s.packageDir, tarballPath: manifest.tarball.path, tarballSha256: manifest.tarball.sha256 });
        problems.push(...content.problems.map((problem) => `staged package: ${problem}`));
      } catch (error) {
        problems.push(`staged package: ${error.message}`);
      }
      return { ok: problems.length === 0, problems };
    },

    stopAll: () => supervisor.stopAll(),

    async collect(fixture) {
      const files = {};
      const redact = (text) => [...secrets].reduce((out, secret) => out.split(secret).join("[redacted]"), text);
      for (const [label, dir] of [["logs", fixture.logs], ["evidence", fixture.evidence]]) {
        let names = [];
        try {
          names = (await readdir(dir, { withFileTypes: true })).filter((entry) => entry.isFile()).map((entry) => entry.name);
        } catch {
          names = [];
        }
        for (const name of names) files[`${label}/${name}`] = redact((await readText(join(dir, name))).slice(0, 1_000_000));
      }
      try {
        files["evidence/exec"] = await readExecRecords(execDir(fixture));
      } catch (error) {
        files["evidence/exec"] = { error: error?.code === "ENOENT" ? `execution record directory missing${recordDirsCreated.has(fixture.root) ? " (it was created by prepare)" : ""}` : String(error) };
      }
      // Plain, serializable listener close outcomes and secondary cleanup failures (Amendment A2).
      files["evidence/listeners"] = listenerOwnership.report(fixture.root).map((outcome) => (outcome.error ? { ...outcome, error: redact(outcome.error) } : outcome));
      files["evidence/cleanup-problems"] = (cleanupProblems.get(fixture.root) ?? []).map(redact);
      // Structured provider launch evidence (Amendment A3): explicit fields only, never a JSON string.
      try {
        files["evidence/provider-launches"] = providerEvidence.report(fixture.root);
      } catch {
        files["evidence/provider-launches"] = { evidence: "unavailable" };
      }
      return { files };
    },

    async removeRoot(fixture) {
      const s = state.get(fixture.root);
      // Never delete a root while a listener this run owns is not confirmed closed. This shares any
      // earlier close attempt (close-once); a failed or timed-out close keeps the root.
      await listenerOwnership.closeAll(fixture.root);
      const unconfirmed = listenerOwnership.report(fixture.root).filter((outcome) => outcome.status !== "closed");
      if (unconfirmed.length > 0) throw new Error(`fixture retained: listener close not confirmed: ${unconfirmed.map(describeOutcome).join("; ")}`);
      const lineagePids = () => readExecLineage(execDir(fixture), recordDirsCreated.has(fixture.root));
      await supervisor.removeRootIfSafe(fixture.root, { lineagePids });
      if (s?.canaryDir) await canaryFs.rm(s.canaryDir, { recursive: true, force: true });
    },
  };
}
