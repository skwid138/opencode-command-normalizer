#!/usr/bin/env node
// Constructed-archive consumer verification. Must run through test/run-isolated.mjs.
//
// The archive is built by test/pack-artifact.mjs with the system `tar` from an
// isolated stage of exactly the expected regular files. `npm pack` is NOT used:
// npm 10.9.2 / pacote 19 was observed to run the `prepare` (Husky) script even
// with --ignore-scripts. No lifecycle script runs here. This is NOT proof of npm
// publish file selection and NOT byte-reproducible (mtimes are not normalized).
// No candidate is retained: the archive lives only in the work directory.
//
// Invoke with an explicit Node, e.g.
//   <node> test/run-isolated.mjs <node> test/verify-pack.mjs
//                             build (tsc via this Node), construct + validate the
//                             archive, then extract into a clean consumer with no
//                             dependencies installed and import `.` and `./server`
//   ... test/verify-pack.mjs --consumer-types
//                             (separately gated; uses the network) additionally install the archive plus host
//                             type packages into two throwaway consumers (V1-only
//                             and V1+V2) using the launcher's disposable npm cache,
//                             then type-check root + `./server` with
//                             skipLibCheck: false and assert V2 assignability.
//                             Any compiler error, non-zero exit, signal, or timeout
//                             fails (test/consumer-compile.mjs); a host-types-only
//                             baseline is printed for diagnosis only.
//
// Only the --consumer-types installs use the network: they explicitly override
// the launcher's npm_config_offline=true and use npm_config_userconfig=/dev/null.
// No OpenCode host or provider is started. The work directory is removed in
// `finally`; the npm cache lives in the launcher root and is removed by it.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluateCompile } from "./consumer-compile.mjs";
import { assertIsolated, isInside, ROOT_VAR } from "./isolated-env.mjs";
import { buildPackageArchive, runTar } from "./pack-artifact.mjs";

assertIsolated();

const consumerTypes = process.argv.includes("--consumer-types");
const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const pkg = JSON.parse(await readFile(join(repoRoot, "package.json"), "utf8"));
const failures = [];

// Exact, user-approved Gate B install sets (plan Amendment A1). No other
// packages may be added. @types/json-schema is for the V2 temporary consumer only.
const V1_CONSUMER_PACKAGES = ["@opencode-ai/plugin@1.16.2", "typescript@6.0.3", "@types/node@22.19.20"];
const V2_CONSUMER_PACKAGES = [...V1_CONSUMER_PACKAGES, "@opencode/plugin@2.0.28", "@types/json-schema@7.0.15"];

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 60_000, ...options });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed (${result.status ?? result.signal}):\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

function check(label, ok, detail = "") {
  process.stdout.write(`${ok ? "PASS" : "FAIL"} ${label}${detail ? ` — ${detail}` : ""}\n`);
  if (!ok) failures.push(label);
}

function sizeOf(path) {
  const result = spawnSync("du", ["-sk", path], { encoding: "utf8" });
  return result.status === 0 ? `${Math.round(Number(result.stdout.split(/\s/)[0]) / 1024)} MB` : "unknown";
}

async function buildAndCheck(work) {
  const tsc = join(repoRoot, "node_modules", "typescript", "bin", "tsc");
  let checked = false;
  const archive = await buildPackageArchive({
    repoRoot,
    workDir: work,
    // The only build step: the TypeScript compiler, run with this Node. No package-manager lifecycle.
    build: async () => void run(process.execPath, [tsc, "-p", "tsconfig.build.json"], { cwd: repoRoot }),
    // Runs only after the archive passed bounded validation (exact members, regular files, caps, bytes).
    consumerChecks: async ({ archivePath, members }) => {
      await checkArchive(work, archivePath, members);
      checked = true;
      if (failures.length > 0) throw new Error(`consumer checks failed: ${failures.join("; ")}`);
    },
  });
  if (!checked) throw new Error("consumer checks did not run");
  return archive;
}

async function checkArchive(work, archivePath, members) {
  const files = members.map((member) => member.slice("package/".length));
  process.stdout.write(`constructed ${basename(archivePath)} (${files.length} regular files, validated before extraction)\n`);
  check("archive ships built entrypoints", ["dist/index.js", "dist/index.d.ts"].every((file) => files.includes(file)));
  check(
    "archive excludes sources, tests, and plans",
    files.every((file) => !file.startsWith("src/") && !file.startsWith("test/") && !file.startsWith(".project-plans/")),
    files.join(", "),
  );
  const testArtifacts = files.filter((file) => /\.test(-d)?\.(js|d\.ts|ts)$/.test(file));
  check("archive contains no compiled test or type-test artifacts", testArtifacts.length === 0, testArtifacts.join(", "));

  for (const subpath of [".", "./server"]) {
    const entry = pkg.exports?.[subpath] ?? {};
    check(`package exports ${subpath} declares import and types`, entry.import === "./dist/index.js" && entry.types === "./dist/index.d.ts", JSON.stringify(entry));
  }

  const consumer = await unpackedConsumer(work, archivePath);
  const installed = join(consumer, "node_modules", ...pkg.name.split("/"));

  // The V2 SDK (`@opencode/*`) must never be reachable from shipped JS or
  // declarations; V2 host types are structural. The V1 types package
  // (`@opencode-ai/plugin`) may appear in declarations only, as before.
  // Scanned in the extracted archive, i.e. the shipped bytes.
  const specifierPattern = /(?:from\s+|import\s*\(\s*|import\s+)["']([^"']+)["']/g;
  const v2Leaks = [];
  const v1RuntimeImports = [];
  for (const file of files.filter((path) => path.startsWith("dist/"))) {
    const text = await readFile(join(installed, file), "utf8");
    for (const match of text.matchAll(specifierPattern)) {
      const specifier = match[1];
      if (specifier.startsWith("@opencode/")) v2Leaks.push(`${file}: ${specifier}`);
      if (file.endsWith(".js") && specifier.startsWith("@opencode-ai/")) v1RuntimeImports.push(`${file}: ${specifier}`);
    }
  }
  check("no shipped file references the V2 SDK (@opencode/*)", v2Leaks.length === 0, v2Leaks.join(", "));
  check("no shipped JS imports the V1 host packages at runtime", v1RuntimeImports.length === 0, v1RuntimeImports.join(", "));
  checkImports(consumer, "unpacked consumer");

  if (consumerTypes) {
    await typedConsumer(work, archivePath, "v1", V1_CONSUMER_PACKAGES, V1_SOURCE, V1_BASELINE);
    await typedConsumer(work, archivePath, "v2", V2_CONSUMER_PACKAGES, V2_SOURCE, V2_BASELINE);
    process.stdout.write(`disposable npm cache size: ${sizeOf(process.env.npm_config_cache ?? "")}\n`);
  } else {
    process.stdout.write("NOT VERIFIED declarations in a clean consumer (separately gated: --consumer-types)\n");
  }
}

const importProbe = `
const root = await import(${JSON.stringify(pkg.name)});
const server = await import(${JSON.stringify(`${pkg.name}/server`)});
process.stdout.write(JSON.stringify({
  rootNamed: Object.keys(root).sort(),
  serverNamed: Object.keys(server).sort(),
  sameDefault: root.default === server.default,
  defaultKeys: Object.keys(root.default).sort(),
  id: root.default.id,
  serverIsFunction: typeof root.default.server === "function",
  setupIsFunction: typeof root.default.setup === "function",
  serverIsNamedPlugin: root.default.server === root.PermissionCanonicalizerPlugin,
}));
`;

function checkImports(consumer, label) {
  const imported = JSON.parse(run(process.execPath, ["--input-type=module", "-e", importProbe], { cwd: consumer }).stdout);
  const expectedNamed = ["PermissionCanonicalizerPlugin", "canonicalize", "canonicalizeAndAudit", "default", "resolveDefaultLogPaths", "splitCommandNodes"];
  check(`${label}: \`.\` JS import`, JSON.stringify(imported.rootNamed) === JSON.stringify(expectedNamed), imported.rootNamed.join(","));
  check(`${label}: \`./server\` JS import`, JSON.stringify(imported.serverNamed) === JSON.stringify(expectedNamed), imported.serverNamed.join(","));
  check(`${label}: \`.\` and \`./server\` share one default object`, imported.sameDefault === true);
  check(`${label}: default.server is the V1 plugin function`, imported.serverIsFunction && imported.serverIsNamedPlugin);
  check(
    `${label}: default export is the dual-host object { id, server, setup }`,
    JSON.stringify(imported.defaultKeys) === JSON.stringify(["id", "server", "setup"]) && imported.setupIsFunction && imported.id === "skwid138.command-normalizer",
    `${imported.defaultKeys.join(",")} id=${imported.id}`,
  );
}

async function unpackedConsumer(work, archivePath) {
  const consumer = join(work, "consumer-unpacked");
  const installed = join(consumer, "node_modules", ...pkg.name.split("/"));
  await mkdir(installed, { recursive: true });
  await writeFile(join(consumer, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }), "utf8");
  runTar(["-xzf", archivePath, "-C", installed, "--strip-components=1"]);
  const hostPackages = ["@opencode-ai/plugin", "@opencode-ai/sdk", "@opencode/plugin"];
  check(
    "clean consumer has no host SDK packages",
    hostPackages.every((name) => !existsSync(join(consumer, "node_modules", ...name.split("/")))),
  );
  return consumer;
}

const V1_SOURCE = `
import plugin, {
  canonicalize,
  canonicalizeAndAudit,
  PermissionCanonicalizerPlugin,
  resolveDefaultLogPaths,
  splitCommandNodes,
  type AuditContext,
  type AuditRecord,
  type CanonicalizeOptions,
  type DecisionRecord,
} from "${pkg.name}";
import serverEntry from "${pkg.name}/server";
import type { Plugin as V1Plugin } from "@opencode-ai/plugin";

const v1Server: V1Plugin = plugin.server;
const v1Named: V1Plugin = PermissionCanonicalizerPlugin;
const sameShape: typeof plugin = serverEntry;
const id: string = plugin.id;
const options: CanonicalizeOptions = { roots: ["~/x"], expandBraceHome: false, homedir: "/h" };
const out: string = canonicalize("~/x", options);
const nodes: string[] = splitCommandNodes("a && b");
const paths: { audit: string; debug: string; decisions: string } = resolveDefaultLogPaths({});
declare const ctx: AuditContext;
const audited: Promise<string> = canonicalizeAndAudit("~/x", options, ctx);
declare const record: AuditRecord;
declare const decision: DecisionRecord;
const decisionCallID: string | null = decision.callID;
const recordNode: string = record.command_node_text;

// Negative controls: prove declarations resolved to real types, not \`any\`.
// @ts-expect-error id is a string
const notANumber: number = plugin.id;
// @ts-expect-error the V1 host Plugin type is a real function type
const notAV1Plugin: V1Plugin = "not a plugin";

export { v1Server, v1Named, sameShape, id, out, nodes, paths, audited, decisionCallID, recordNode, notANumber, notAV1Plugin };
`;

const V2_SOURCE = `${V1_SOURCE}
import type { Plugin as V2 } from "@opencode/plugin";

const v2Root: V2.Plugin = plugin;
const v2Server: V2.Plugin = serverEntry;
declare const hostContext: V2.Context;
const cleanup: Promise<unknown> = plugin.setup(hostContext);

// Negative controls: the V2 host types are real, and a malformed plugin is rejected.
// @ts-expect-error the V2 host Plugin type is not any
const notAV2Plugin: V2.Plugin = "not a plugin";
// @ts-expect-error setup must be a function
const malformedV2Plugin: V2.Plugin = { id: "malformed", setup: 42 };
// @ts-expect-error the V2 host Context type is not any
const notAContext: V2.Context = {};

export { v2Root, v2Server, cleanup, notAV2Plugin, malformedV2Plugin, notAContext };
`;

const tsconfigFor = (moduleResolution, file) =>
  JSON.stringify(
    {
      compilerOptions: {
        target: "ES2022",
        module: moduleResolution === "NodeNext" ? "NodeNext" : "ESNext",
        moduleResolution,
        strict: true,
        skipLibCheck: false,
        noEmit: true,
        types: ["node"],
      },
      files: [file],
    },
    null,
    2,
  );

// Baselines import only the host type packages. They are DIAGNOSTIC ONLY:
// printed to help attribute a failure, never used to decide pass/fail.
const V1_BASELINE = `import type { Plugin } from "@opencode-ai/plugin";\ndeclare const p: Plugin;\nexport { p };\n`;
const V2_BASELINE = `${V1_BASELINE}import type { Plugin as V2 } from "@opencode/plugin";\ndeclare const q: V2.Plugin;\nexport { q };\n`;

async function compile(consumer, tsc, resolution, file) {
  const tsconfig = `tsconfig.${file}.${resolution}.json`;
  await writeFile(join(consumer, tsconfig), tsconfigFor(resolution, file), "utf8");
  return spawnSync(process.execPath, [tsc, "-p", tsconfig], { cwd: consumer, encoding: "utf8", timeout: 120_000 });
}

async function typedConsumer(work, archivePath, label, packages, source, baseline) {
  const consumer = join(work, `consumer-${label}`);
  const filename = basename(archivePath);
  await mkdir(consumer, { recursive: true });
  await writeFile(join(consumer, "package.json"), JSON.stringify({ name: `consumer-${label}`, private: true, type: "module" }), "utf8");
  await copyFile(archivePath, join(consumer, filename));

  const cache = process.env.npm_config_cache ?? "";
  const realCache = join(userInfo().homedir, ".npm");
  if (!isInside(cache, process.env[ROOT_VAR]) || isInside(cache, realCache)) {
    throw new Error(`refusing to install: npm cache ${cache || "(unset)"} is not inside the disposable test root`);
  }
  const args = ["install", "--no-save", "--ignore-scripts", "--no-audit", "--no-fund", `./${filename}`, ...packages];
  const overrides = { npm_config_userconfig: "/dev/null", npm_config_offline: "false" };
  process.stdout.write(
    `[${label}] cwd=${consumer}\n[${label}] cache=${cache} (disposable, inside ${ROOT_VAR})\n` +
      `[${label}] $ ${Object.entries(overrides).map(([k, v]) => `${k}=${v}`).join(" ")} npm ${args.join(" ")}\n`,
  );
  const started = Date.now();
  const install = run("npm", args, { cwd: consumer, env: { ...process.env, ...overrides }, timeout: 300_000 });
  process.stdout.write(`[${label}] install finished in ${((Date.now() - started) / 1000).toFixed(1)}s; node_modules ${sizeOf(join(consumer, "node_modules"))}\n`);
  const warnings = `${install.stdout}\n${install.stderr}`.split("\n").filter((line) => /npm (warn|WARN)/.test(line));
  for (const line of warnings) process.stdout.write(`[${label}] ${line}\n`);
  const summary = `${install.stdout}`.split("\n").find((line) => /added \d+ packages?/.test(line));
  if (summary) process.stdout.write(`[${label}] ${summary.trim()}\n`);

  const manifest = JSON.parse(await readFile(join(consumer, "node_modules", ...pkg.name.split("/"), "package.json"), "utf8"));
  check(`${label}: installed manifest is the packed version`, manifest.version === pkg.version, manifest.version);
  check(`${label}: installed manifest has no runtime dependencies`, Object.keys(manifest.dependencies ?? {}).length === 0, JSON.stringify(manifest.dependencies ?? {}));
  check(
    `${label}: installed manifest peers are only the V1 types package`,
    JSON.stringify(Object.keys(manifest.peerDependencies ?? {})) === JSON.stringify(["@opencode-ai/plugin"]),
    JSON.stringify(manifest.peerDependencies ?? {}),
  );
  const v2TreePresent = existsSync(join(consumer, "node_modules", "@opencode"));
  if (label === "v1") check("v1: V1-only consumer does not receive the V2 SDK tree (@opencode/*)", !v2TreePresent);
  else {
    check("v2: V2 consumer has @opencode/plugin installed", existsSync(join(consumer, "node_modules", "@opencode", "plugin")));
    const jsonSchemaTypes = join(consumer, "node_modules", "@types", "json-schema", "package.json");
    const version = existsSync(jsonSchemaTypes) ? JSON.parse(await readFile(jsonSchemaTypes, "utf8")).version : "missing";
    check("v2: temporary consumer has exactly @types/json-schema@7.0.15", version === "7.0.15", version);
  }

  checkImports(consumer, label);

  await writeFile(join(consumer, "consumer.ts"), source, "utf8");
  await writeFile(join(consumer, "baseline.ts"), baseline, "utf8");
  const tsc = join(consumer, "node_modules", "typescript", "bin", "tsc");
  for (const resolution of ["NodeNext", "Bundler"]) {
    const subject = `${label}: tsc (${resolution}, strict, skipLibCheck: false) root + ./server${label === "v2" ? " + V2 assignability + negative controls" : " + negative controls"}`;
    const verdict = evaluateCompile(await compile(consumer, tsc, resolution, "consumer.ts"));
    check(subject, verdict.ok, [...verdict.reasons, ...verdict.errors].join("\n"));
    if (!verdict.ok) {
      const baselineVerdict = evaluateCompile(await compile(consumer, tsc, resolution, "baseline.ts"));
      process.stdout.write(
        `  DIAGNOSTIC ONLY (does not change the result): host-types-only baseline ${baselineVerdict.ok ? "compiles cleanly" : `reports: ${[...baselineVerdict.reasons, ...baselineVerdict.errors].join(" | ")}`}\n`,
      );
    }
  }
}

const work = await mkdtemp(join(tmpdir(), "pack-verify-"));
try {
  const archive = await buildAndCheck(work);
  process.stdout.write(`constructed archive sha256 ${archive.sha256} (${archive.size} bytes; temporary, not retained)\n`);
} catch (error) {
  failures.push(error instanceof Error ? error.message : String(error));
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
} finally {
  await rm(work, { recursive: true, force: true });
}

if (failures.length > 0) {
  process.stderr.write(`pack verification failed: ${failures.length} failure(s)\n`);
  process.exit(1);
}
