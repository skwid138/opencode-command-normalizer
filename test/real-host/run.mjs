#!/usr/bin/env node
// Opt-in real-host runner. Not part of `npm test` or CI.
//
//   npm run test:real-host                                   closed: prints gate status, exits 2
//   npm run test:real-host -- --manifest <m.json> --check    verifies gates and staged hashes; starts nothing
//   npm run test:real-host -- --manifest <m.json> --execute --pilot
//                                                            one row: controls, version, ask-once pilot only
//                                                            (independent 15-minute work deadline from before prepare)
//   npm run test:real-host -- --manifest <m.json> --execute  full matrix
//
// The runner never downloads, installs, or stages anything. The manifest must
// point at artifacts already staged under separately approved Gate 2 and carry
// Gate 2/Gate 3 approval references. Exit codes: 0 complete (or pilot passed),
// 1 ran but failed/incomplete, 2 gates closed or usage error.
import { readFile } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { UNVERIFIED_CONTRACTS } from "./contracts.mjs";
import { checkRuntimeGates } from "./gates.mjs";
import { buildReport, pilotVerdict, writeReport } from "./report.mjs";
import { runMatrix } from "./runner.mjs";
import { createRuntimeDeps } from "./runtime.mjs";
import { exitCodeFor, installSignalHandlers } from "./signals.mjs";
import { createSupervisor } from "./supervisor.mjs";

const USAGE = `usage: node test/real-host/run.mjs [--manifest <path> (--check | --execute [--pilot])]

Without --manifest the runner is closed and prints what is required.
--check     verify gates and staged artifact hashes; start nothing
--execute   run the sandboxed real-host matrix (requires every gate)
--pilot     with --execute: first row, ask-once pilot only
`;

const out = (text) => process.stdout.write(`${text}\n`);
const err = (text) => process.stderr.write(`${text}\n`);

let args;
try {
  args = parseArgs({ options: { manifest: { type: "string" }, check: { type: "boolean" }, execute: { type: "boolean" }, pilot: { type: "boolean" }, help: { type: "boolean" } } }).values;
} catch (error) {
  err(error.message);
  err(USAGE);
  process.exit(2);
}

if (args.help) {
  out(USAGE);
  process.exit(0);
}

if (!args.manifest) {
  out("NOT EXECUTED: real-host runtime gates are closed.");
  out("- Gate 2 (exact downloads and staging) requires separate user approval.");
  out("- Gate 3 (sandbox safety pilot and runtime matrix) requires separate user approval.");
  out("- After approval, stage artifacts, write a run manifest, then run --check before --execute.");
  out("Unverified contracts that need a review reference in the manifest:");
  for (const { key, description } of UNVERIFIED_CONTRACTS) out(`  ${key}: ${description}`);
  process.exit(2);
}

if (!args.check && !args.execute) {
  err("a manifest requires --check or --execute");
  process.exit(2);
}

let manifest;
try {
  manifest = JSON.parse(await readFile(args.manifest, "utf8"));
} catch (error) {
  err(`cannot read manifest ${args.manifest}: ${error.message}`);
  process.exit(2);
}

const realHome = userInfo().homedir;
const gates = await checkRuntimeGates(manifest, { realHome });
if (!gates.ok) {
  out("GATES CLOSED: nothing was started.");
  for (const problem of gates.problems) out(`- ${problem}`);
  process.exit(2);
}
out("All runtime gates pass (staged hashes verified).");
if (args.check) {
  out("--check: nothing was started.");
  process.exit(0);
}

const repoRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const supervisor = createSupervisor();
const controller = new AbortController();
// First signal: abort + stop owned groups, then the normal path still collects
// evidence, applies the retention gate, and writes the report. Second: exit.
const signalHandlers = installSignalHandlers({ controller, supervisor });

const mode = args.pilot ? "pilot" : "matrix";
const rows = manifest.rows.map((row) => gates.verified.rows.find((verifiedRow) => verifiedRow.id === row.id));
const deps = createRuntimeDeps({ manifest, verified: gates.verified, supervisor, realHome });
const result = await runMatrix({ rows, mode, tarballSha256: gates.verified.tarball.sha256, deps, signal: controller.signal });
const report = buildReport({
  executed: result.rows.some((row) => row.executed),
  rows: result.rows,
  mode,
  stoppedEarly: result.stopped,
  aborted: result.aborted,
  deadlineExceeded: result.deadlineExceeded,
  workBudgetMs: result.workBudgetMs,
  shutdownFailures: signalHandlers.failures(),
  node: gates.verified.node,
  tarball: gates.verified.tarball,
  approvals: manifest.approvals,
});
await writeReport(manifest.reportPath, report, { realHome, repoRoot, fixtureRoot: gates.verified.roots.runRoot, secrets: deps.secrets() });
signalHandlers.uninstall();
out(`report: ${manifest.reportPath}`);
out(`status: ${report.status}${result.aborted ? " (aborted by signal)" : ""}${result.deadlineExceeded ? " (pilot work deadline exceeded)" : ""}`);
for (const reason of report.reasons) out(`- ${reason}`);
const pilot = mode === "pilot" ? pilotVerdict(report) : null;
if (pilot?.passed) out("PILOT PASSED (full report: version, preflight, scenario, cleanup). The matrix was not run; the report is incomplete by design.");
else if (pilot) for (const problem of pilot.problems) out(`- pilot: ${problem}`);
process.exit(exitCodeFor({ aborted: result.aborted, report, pilot }));
