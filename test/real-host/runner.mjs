// Matrix orchestration with injected dependencies. Fail-closed rules:
//   - Any failed step stops the run: a thrown error, a failed preflight, a
//     version mismatch, a returned scenario or lifecycle failure, a forbidden
//     change found by the per-step dependency tripwire, a cleanup failure, or
//     an abort signal. Nothing is relaxed or retried to get past it, and no
//     later scenario, lifecycle, or row runs.
//   - Cleanup always runs in this order: stop owned processes (never delayed
//     to collect logs), collect evidence from files, then remove the fixture
//     root only if the retention gate allows it.
//   - Pilot mode runs one row's ask-once pilot only; its report is
//     "incomplete" by design until the full matrix runs.
//   - Pilot mode has an independent work deadline that starts before fixture
//     prepare. On expiry the run-wide work signal aborts (the runtime checks it
//     at every spawn boundary and after deferred awaits), owned processes are
//     stopped at once, and the in-flight step is awaited (never abandoned by a
//     timer race). No later step runs; cleanup, final integrity, evidence, and
//     the report still complete through the normal pipeline.
//   - Final integrity runs after owned shutdown and before fixture deletion on
//     every path; a failure keeps the root.
import { REQUIRED_SCENARIOS } from "./report.mjs";

/** Independent pilot work budget (Amendment A1). Applies to pilot mode only; the matrix has no implicit deadline. */
export const PILOT_WORK_BUDGET_MS = 15 * 60 * 1000;

class StageError extends Error {
  constructor(stage, message) {
    super(message);
    this.stage = stage;
  }
}

const messageOf = (error) => (error instanceof Error ? error.message : String(error));

async function runRow({ row, scenarioIDs, includeLifecycle, tarballSha256, deps, signal, abortStage, cancellation, endWork }) {
  const result = {
    id: row.id,
    family: row.family,
    version: null,
    expectedVersion: row.version,
    sourceCommit: row.sourceCommit,
    binary: row.binary,
    tarballSha256,
    executed: false,
    preflight: null,
    scenarios: [],
    lifecycle: null,
    tripwires: [],
    cleanup: null,
    evidence: null,
    integrity: null,
  };
  const checkAbort = () => {
    if (signal?.aborted) throw new StageError(abortStage(), abortStage() === "deadline" ? "pilot work deadline exceeded" : "run aborted by signal");
  };
  const tripwire = async (fixture, step) => {
    const outcome = await deps.tripwire(fixture, row, step);
    result.tripwires.push({ step, ...outcome });
    if (outcome.forbidden.length > 0) throw new StageError("tripwire", `${step}: forbidden dependency changes: ${outcome.forbidden.join(", ")}`);
  };
  let fixture = null;
  let stage = "fixture";
  try {
    checkAbort();
    fixture = await deps.createFixture(row);
    checkAbort();
    stage = "prepare";
    await deps.prepare(fixture, row);
    checkAbort();
    await tripwire(fixture, "prepare");
    checkAbort();
    stage = "preflight";
    result.preflight = await deps.preflight(fixture, row);
    checkAbort();
    if (!result.preflight.ok) throw new StageError("preflight", `sandbox preflight failed: ${result.preflight.failures.join("; ")}`);
    checkAbort();
    stage = "version";
    result.version = await deps.versionProbe(fixture, row);
    checkAbort();
    if (!result.version.ok) throw new StageError("version", `sandboxed version probe: expected ${result.version.expected}, observed ${result.version.observed}`);
    for (const id of scenarioIDs) {
      checkAbort();
      stage = "scenario";
      let outcome;
      try {
        outcome = await deps.scenario(fixture, row, id);
      } catch (error) {
        throw new StageError(error?.stage ?? "scenario", `${id}: ${messageOf(error)}`);
      }
      result.scenarios.push(outcome);
      checkAbort();
      if (outcome.status !== "pass") throw new StageError("scenario", `${id}: ${outcome.problems.join("; ")}`);
      await tripwire(fixture, id);
    }
    if (includeLifecycle) {
      checkAbort();
      stage = "lifecycle";
      result.lifecycle = await deps.lifecycle(fixture, row);
      checkAbort();
      if (result.lifecycle.status !== "pass") throw new StageError("lifecycle", result.lifecycle.problems.join("; "));
      await tripwire(fixture, "lifecycle");
    }
  } catch (error) {
    const aborted = signal?.aborted && !(error instanceof StageError);
    result.failure = aborted
      ? { stage: abortStage(), message: `${abortStage() === "deadline" ? "pilot work deadline exceeded" : "run aborted by signal"} during ${stage}: ${messageOf(error)}` }
      : { stage: error instanceof StageError ? error.stage : stage, message: messageOf(error) };
  } finally {
    // Work -> cleanup boundary: disarm the pilot work timer before shutdown, evidence, integrity, and removal.
    // A deadline that already expired stays recorded as a failure above.
    endWork();
    result.executed = result.scenarios.length > 0;
    // The cancellation stop (if any) already ran at abort time, before any evidence collection.
    if (cancellation.promise) result.cancellationStop = await cancellation.promise;
    const stopped = await deps.stopAll();
    result.cleanup = {
      stopped,
      aliveAfter: stopped.filter((entry) => entry.aliveAfter).map((entry) => entry.pgid),
      unsafe: stopped.some((entry) => entry.unsafe),
      rootRemoved: false,
    };
    if (fixture) {
      try {
        result.evidence = await deps.collect(fixture, row);
      } catch (error) {
        result.evidence = { error: messageOf(error) };
      }
      try {
        result.integrity = deps.finalIntegrity ? await deps.finalIntegrity(fixture, row) : { ok: false, problems: ["final integrity check unavailable"] };
      } catch (error) {
        result.integrity = { ok: false, problems: [`final integrity check failed: ${messageOf(error)}`] };
      }
      if (result.integrity.ok) {
        try {
          await deps.removeRoot(fixture, row);
          result.cleanup.rootRemoved = true;
        } catch (error) {
          result.cleanup.error = messageOf(error);
        }
      } else {
        result.cleanup.error = `fixture retained: final integrity failed: ${result.integrity.problems.join("; ")}`;
        if (!result.failure) result.failure = { stage: "integrity", message: result.integrity.problems.join("; ") };
      }
    }
    const cleanupProblem = result.cleanup.aliveAfter.length > 0 || result.cleanup.unsafe || (fixture && !result.cleanup.rootRemoved) || result.evidence?.error;
    if (cleanupProblem && !result.failure) {
      result.failure = { stage: "cleanup", message: result.cleanup.error ?? result.evidence?.error ?? `owned groups alive after stop: ${result.cleanup.aliveAfter.join(", ")}` };
    }
  }
  return result;
}

export async function runMatrix({ rows, mode, tarballSha256, deps, signal, workBudgetMs, timers = { setTimeout, clearTimeout } }) {
  if (mode !== "pilot" && mode !== "matrix") throw new Error(`unknown mode: ${mode}`);
  const selected = mode === "pilot" ? rows.slice(0, 1) : rows;
  const scenarioIDs = mode === "pilot" ? ["pilot-ask-once"] : REQUIRED_SCENARIOS;
  const work = new AbortController();
  let deadlineExceeded = false;
  const cancellation = { promise: null };
  const stopNow = () => {
    // First action on cancellation: stop owned processes, before any evidence is collected.
    cancellation.promise ??= Promise.resolve()
      .then(() => deps.stopAll())
      .catch((error) => [{ error: messageOf(error) }]);
  };
  work.signal.addEventListener("abort", stopNow, { once: true });
  const forward = () => work.abort();
  if (signal?.aborted) work.abort();
  else signal?.addEventListener("abort", forward, { once: true });
  const budget = mode === "pilot" ? (workBudgetMs ?? PILOT_WORK_BUDGET_MS) : null;
  const timer =
    budget === null
      ? null
      : timers.setTimeout(() => {
          deadlineExceeded = true;
          work.abort();
        }, budget);
  const abortStage = () => (deadlineExceeded ? "deadline" : "aborted");
  let disarmed = false;
  const endWork = () => {
    if (timer !== null && !disarmed) timers.clearTimeout(timer);
    disarmed = true;
  };
  deps.bindSignal?.(work.signal);
  const results = [];
  let stopped = false;
  try {
    for (const row of selected) {
      const result = await runRow({ row, scenarioIDs, includeLifecycle: mode === "matrix", tarballSha256, deps, signal: work.signal, abortStage, cancellation, endWork });
      results.push(result);
      if (result.failure || work.signal.aborted) {
        stopped = true;
        break;
      }
    }
  } finally {
    endWork();
    signal?.removeEventListener("abort", forward);
  }
  return { mode, rows: results, stopped, aborted: Boolean(signal?.aborted), deadlineExceeded, workBudgetMs: budget };
}
