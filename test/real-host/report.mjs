// Sanitized run report. "complete" is reserved for a run in which every
// required matrix row actually executed and every required scenario,
// lifecycle check, preflight, and cleanup passed. Anything less is
// "incomplete" (not proven) or "failed" (disproven).
import { writeFile } from "node:fs/promises";

import { MATRIX } from "./artifacts.mjs";
import { scenarioMatrix } from "./scenarios.mjs";

export const REQUIRED_ROWS = MATRIX.map((row) => row.id);
export const REQUIRED_SCENARIOS = scenarioMatrix({ fixture: { home: "/h", project: "/p", bin: "/h/bin", logs: "/l", evidence: "/e" }, nonce: "n" })
  .filter((scenario) => scenario.kind === "single")
  .map((scenario) => scenario.id);

export const LIMITS =
  "Results apply only to the exact versions and binaries hashed in this report and this local environment. " +
  "Runtime HOME behavior and host readiness are unknown for anything not exercised here.";

const SECRET_KEY = /(token|secret|password|passwd|authorization|cookie|api[-_]?key|credential)/i;
const SECRET_VALUE = /\b(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|Bearer\s+\S+)/;

export function sanitize(value, { realHome, repoRoot, fixtureRoot, secrets = [] }) {
  const replacements = [
    ...secrets.filter((secret) => typeof secret === "string" && secret.length >= 8).map((secret) => [secret, "[redacted]"]),
    [fixtureRoot, "<FIXTURE>"],
    [repoRoot, "<REPO>"],
    [realHome, "<HOME>"],
  ].filter(([from]) => typeof from === "string" && from.length > 1);
  const visit = (current) => {
    if (typeof current === "string") {
      if (SECRET_VALUE.test(current)) return "[redacted]";
      let out = current;
      for (const [from, to] of replacements) out = out.split(from).join(to);
      return out;
    }
    if (Array.isArray(current)) return current.map(visit);
    if (current && typeof current === "object") {
      return Object.fromEntries(Object.entries(current).map(([key, inner]) => [key, SECRET_KEY.test(key) ? "[redacted]" : visit(inner)]));
    }
    return current;
  };
  return visit(value);
}

export function buildReport({ executed, rows = [], gateProblems = [], shutdownFailures = [], deadlineExceeded = false, ...rest }) {
  const incomplete = [];
  const failed = shutdownFailures.map((failure) => `shutdown: ${failure}`);
  if (deadlineExceeded) failed.push("pilot work deadline exceeded");
  if (!executed) incomplete.push("runtime was not executed", ...gateProblems.map((problem) => `gate: ${problem}`));
  for (const id of REQUIRED_ROWS) {
    const row = rows.find((candidate) => candidate.id === id);
    if (!row) {
      if (executed) incomplete.push(`row ${id} was not run`);
      continue;
    }
    if (row.failure) failed.push(`${id}: ${row.failure.stage}: ${row.failure.message}`);
    if (!row.executed) {
      incomplete.push(`${id}: not executed`);
      continue;
    }
    if (row.integrity && !row.integrity.ok) failed.push(`${id}: final integrity: ${row.integrity.problems.join("; ")}`);
    if (!row.preflight?.ok) failed.push(`${id}: sandbox preflight failed: ${(row.preflight?.failures ?? ["missing"]).join("; ")}`);
    if (!row.version?.ok) failed.push(`${id}: version probe ${row.version ? `expected ${row.version.expected}, observed ${row.version.observed}` : "missing"}`);
    for (const scenarioID of REQUIRED_SCENARIOS) {
      const result = (row.scenarios ?? []).find((candidate) => candidate.id === scenarioID);
      if (!result) incomplete.push(`${id}: missing scenario ${scenarioID}`);
      else if (result.status !== "pass") failed.push(`${id}: ${scenarioID}: ${result.problems.join("; ")}`);
    }
    if (!row.lifecycle) incomplete.push(`${id}: missing lifecycle`);
    else if (row.lifecycle.status !== "pass") failed.push(`${id}: lifecycle: ${row.lifecycle.problems.join("; ")}`);
    const cleanup = row.cleanup;
    if (!cleanup || cleanup.unsafe || (cleanup.aliveAfter ?? []).length > 0 || cleanup.rootRemoved !== true) {
      failed.push(`${id}: cleanup incomplete: ${JSON.stringify(cleanup ?? null)}`);
    }
  }
  const status = failed.length > 0 ? "failed" : incomplete.length > 0 ? "incomplete" : "complete";
  return { status, reasons: [...failed, ...incomplete], limits: LIMITS, executed, rows, shutdownFailures, deadlineExceeded, ...rest };
}

/** A pilot passes only when the full report shows one clean, executed pilot row. */
export function pilotVerdict(report) {
  const problems = [];
  if (report.mode !== "pilot") problems.push(`report mode is ${report.mode}, not pilot`);
  if (!report.executed) problems.push("runtime was not executed");
  for (const failure of report.shutdownFailures ?? []) problems.push(`shutdown: ${failure}`);
  if (report.deadlineExceeded) problems.push("pilot work deadline exceeded");
  const row = report.rows?.[0];
  if (!row) problems.push("no pilot row");
  else {
    if (row.failure) problems.push(`${row.id}: ${row.failure.stage}: ${row.failure.message}`);
    if (!row.executed) problems.push(`${row.id}: not executed`);
    if (!row.preflight?.ok) problems.push(`${row.id}: preflight did not pass`);
    if (!row.version?.ok) problems.push(`${row.id}: version probe did not pass`);
    if (!row.integrity?.ok || row.integrity?.skipped) problems.push(`${row.id}: final integrity did not pass`);
    const pilot = (row.scenarios ?? []).find((scenario) => scenario.id === "pilot-ask-once");
    if (pilot?.status !== "pass") problems.push(`${row.id}: pilot-ask-once ${pilot ? pilot.problems.join("; ") : "missing"}`);
    const cleanup = row.cleanup;
    if (!cleanup || cleanup.unsafe || (cleanup.aliveAfter ?? []).length > 0 || cleanup.rootRemoved !== true) problems.push(`${row.id}: cleanup incomplete: ${JSON.stringify(cleanup ?? null)}`);
  }
  return { passed: problems.length === 0, problems };
}

export async function writeReport(path, report, context) {
  await writeFile(path, `${JSON.stringify(sanitize(report, context), null, 2)}\n`, { flag: "wx" });
}
