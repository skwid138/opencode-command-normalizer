import { describe, expect, it } from "vitest";

import { REQUIRED_SCENARIOS, buildReport, pilotVerdict } from "./report.mjs";
import { PILOT_WORK_BUDGET_MS, runMatrix } from "./runner.mjs";

const ROWS = [
  { id: "v1-floor", family: "v1", version: "1.18.29", sourceCommit: "a", binary: { sha256: "1" } },
  { id: "v1-daily", family: "v1", version: "1.18.35", sourceCommit: "b", binary: { sha256: "2" } },
  { id: "v2", family: "v2", version: "2.0.28", sourceCommit: "c", binary: { sha256: "3" } },
];

function fakeDeps(overrides: Record<string, unknown> = {}) {
  const calls: string[] = [];
  const deps = {
    createFixture: async (row: { id: string }) => {
      calls.push(`fixture ${row.id}`);
      return { root: `/fx/${row.id}` };
    },
    prepare: async () => void calls.push("prepare"),
    preflight: async () => {
      calls.push("preflight");
      return { ok: true, failures: [] };
    },
    versionProbe: async (_f: unknown, row: { version: string }) => {
      calls.push("version");
      return { ok: true, expected: row.version, observed: row.version };
    },
    scenario: async (_f: unknown, _r: unknown, id: string) => {
      calls.push(`scenario ${id}`);
      return { id, status: "pass", problems: [] };
    },
    lifecycle: async () => {
      calls.push("lifecycle");
      return { status: "pass", problems: [] };
    },
    tripwire: async (_f: unknown, _r: unknown, step: string) => {
      calls.push(`tripwire ${step}`);
      return { forbidden: [], changes: [] };
    },
    stopAll: async () => {
      calls.push("stopAll");
      return [];
    },
    collect: async () => {
      calls.push("collect");
      return { logs: "x" };
    },
    finalIntegrity: async () => {
      calls.push("finalIntegrity");
      return { ok: true, problems: [] };
    },
    removeRoot: async () => void calls.push("removeRoot"),
    ...overrides,
  };
  return { calls, deps };
}

const CLEANUP = ["stopAll", "collect", "finalIntegrity", "removeRoot"];

describe("matrix orchestration", () => {
  it("runs prepare, preflight, version probe, each scenario with an immediate tripwire, lifecycle, then stops, collects, and cleans up", async () => {
    const { calls, deps } = fakeDeps();
    const result = await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps });

    expect(result.stopped).toBe(false);
    expect(result.rows.map((row: { executed: boolean }) => row.executed)).toEqual([true, true, true]);
    expect(calls.slice(0, calls.indexOf("removeRoot") + 1)).toEqual([
      "fixture v1-floor",
      "prepare",
      "tripwire prepare",
      "preflight",
      "version",
      ...REQUIRED_SCENARIOS.flatMap((id: string) => [`scenario ${id}`, `tripwire ${id}`]),
      "lifecycle",
      "tripwire lifecycle",
      ...CLEANUP,
    ]);
    expect(result.rows[0]).toMatchObject({ tarballSha256: "t", version: { ok: true }, cleanup: { rootRemoved: true, aliveAfter: [], unsafe: false } });
  });

  it("stops the whole run at a failed preflight without the version probe or scenarios", async () => {
    const { calls, deps } = fakeDeps({ preflight: async () => (calls.push("preflight"), { ok: false, failures: ["canary-read: sandbox allowed the operation"] }) });
    const result = await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps });
    expect(calls).toEqual(["fixture v1-floor", "prepare", "tripwire prepare", "preflight", ...CLEANUP]);
    expect(result).toMatchObject({ stopped: true, rows: [{ executed: false, failure: { stage: "preflight" } }] });
  });

  it("a preflight that throws (for example a listener acquisition failure) stops before the version probe and still stops, collects, checks integrity, and removes", async () => {
    const { calls, deps } = fakeDeps({
      preflight: async () => {
        calls.push("preflight");
        throw new Error("EADDRINUSE: synthetic preflight listener failure");
      },
    });
    const result = await runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps });
    expect(calls).toEqual(["fixture v1-floor", "prepare", "tripwire prepare", "preflight", ...CLEANUP]);
    expect(result.rows[0]).toMatchObject({ preflight: null, version: null, scenarios: [], failure: { stage: "preflight", message: "EADDRINUSE: synthetic preflight listener failure" }, cleanup: { rootRemoved: true } });
  });

  it("a thrown preflight whose fixture is retained by removal reports the retention without replacing the preflight failure", async () => {
    const { calls, deps } = fakeDeps({
      preflight: async () => {
        calls.push("preflight");
        throw new Error("synthetic preflight failure");
      },
      removeRoot: async () => {
        calls.push("removeRoot");
        throw new Error("fixture retained: listener close not confirmed: preflight ipv6 listener close timeout");
      },
    });
    const result = await runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps });
    expect(result.rows[0]).toMatchObject({ failure: { stage: "preflight", message: "synthetic preflight failure" }, cleanup: { rootRemoved: false, error: expect.stringMatching(/fixture retained/) } });
  });

  it("stops before any scenario when the sandboxed version probe reports a different version", async () => {
    const { calls, deps } = fakeDeps({ versionProbe: async () => (calls.push("version"), { ok: false, expected: "1.18.29", observed: "1.18.34" }) });
    const result = await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps });
    expect(calls).not.toContain(`scenario ${REQUIRED_SCENARIOS[0]}`);
    expect(result).toMatchObject({ stopped: true, rows: [{ failure: { stage: "version", message: expect.stringMatching(/1\.18\.34/) } }] });
  });

  it("a version probe that throws (spawn error) stops the row at the version stage, before any scenario", async () => {
    const { calls, deps } = fakeDeps({ versionProbe: async () => { calls.push("version"); throw new Error("spawn /x/opencode ENOENT"); } });
    const result = await runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps });
    expect(calls.filter((call) => call.startsWith("scenario"))).toEqual([]);
    expect(result).toMatchObject({ stopped: true, rows: [{ failure: { stage: "version", message: expect.stringMatching(/ENOENT/) } }] });
    expect(calls.slice(-4)).toEqual(CLEANUP);
  });

  it("fails closed on a returned scenario failure: no later scenario, lifecycle, or row runs", async () => {
    const { calls, deps } = fakeDeps({
      scenario: async (_f: unknown, _r: unknown, id: string) => (calls.push(`scenario ${id}`), id === "tilde-allow" ? { id, status: "fail", problems: ["no terminal tool result"] } : { id, status: "pass", problems: [] }),
    });
    const result = await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps });
    expect(calls.filter((call) => call.startsWith("scenario"))).toEqual(["scenario pilot-ask-once", "scenario baseline-plugin-absent", "scenario tilde-allow"]);
    expect(calls).not.toContain("lifecycle");
    expect(calls.slice(-4)).toEqual(CLEANUP);
    expect(result).toMatchObject({ stopped: true, rows: [{ failure: { stage: "scenario", message: expect.stringMatching(/tilde-allow: no terminal/) } }] });
    expect(result.rows).toHaveLength(1);
  });

  it("fails closed on a returned lifecycle failure", async () => {
    const { deps } = fakeDeps({ lifecycle: async () => ({ status: "fail", problems: ["restored: expected 1 audit record(s), got 2"] }) });
    const result = await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps });
    expect(result).toMatchObject({ stopped: true, rows: [{ failure: { stage: "lifecycle" } }] });
  });

  it("stops owned processes before collecting evidence and before removing files when a scenario throws", async () => {
    const { calls, deps } = fakeDeps({
      scenario: async (_f: unknown, _r: unknown, id: string) => {
        calls.push(`scenario ${id}`);
        if (id === "tilde-allow") throw Object.assign(new Error("host group 77 still alive after stop"), { stage: "teardown" });
        return { id, status: "pass", problems: [] };
      },
    });
    const result = await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps });
    expect(calls.slice(-4)).toEqual(CLEANUP);
    expect(result).toMatchObject({ stopped: true, rows: [{ failure: { stage: "teardown", message: expect.stringMatching(/tilde-allow: host group 77/) } }] });
  });

  it("keeps the root, records a cleanup failure, and runs no later row when an owned process is still alive", async () => {
    const { calls, deps } = fakeDeps({
      stopAll: async () => (calls.push("stopAll"), [{ pgid: 99, aliveAfter: true, unsafe: false }]),
      removeRoot: async () => {
        throw new Error("refusing to remove /fx/v1-floor: owned process group(s) still alive: 99");
      },
    });
    const result = await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps });
    expect(result.rows).toHaveLength(1);
    expect(result).toMatchObject({ stopped: true, rows: [{ failure: { stage: "cleanup" }, cleanup: { rootRemoved: false, aliveAfter: [99], error: expect.stringMatching(/still alive/) } }] });
    expect(calls.filter((call) => call.startsWith("fixture"))).toEqual(["fixture v1-floor"]);
  });

  it("fails the row immediately when a per-step tripwire finds a dependency change", async () => {
    const { calls, deps } = fakeDeps({
      tripwire: async (_f: unknown, _r: unknown, step: string) => (calls.push(`tripwire ${step}`), { forbidden: step === "pilot-ask-once" ? ["added cache/opencode/packages/x/node_modules/left-pad"] : [], changes: [] }),
    });
    const result = await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps });
    expect(calls).not.toContain("scenario baseline-plugin-absent");
    expect(result).toMatchObject({ stopped: true, rows: [{ failure: { stage: "tripwire", message: expect.stringMatching(/pilot-ask-once.*left-pad/) } }] });
  });

  it("an abort signal stops further steps, still cleans up in order, and marks the run aborted", async () => {
    const controller = new AbortController();
    const { calls, deps } = fakeDeps({
      scenario: async (_f: unknown, _r: unknown, id: string) => {
        calls.push(`scenario ${id}`);
        if (id === "baseline-plugin-absent") controller.abort();
        return { id, status: "pass", problems: [] };
      },
    });
    const result = await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps, signal: controller.signal });
    expect(calls).not.toContain("scenario tilde-allow");
    expect(calls.slice(-4)).toEqual(CLEANUP);
    expect(result).toMatchObject({ stopped: true, aborted: true, rows: [{ failure: { stage: "aborted" } }] });
  });

  it("pilot mode runs only the first row's ask-once pilot, with no lifecycle", async () => {
    const { calls, deps } = fakeDeps();
    const result = await runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps });
    expect(calls).toEqual(["fixture v1-floor", "prepare", "tripwire prepare", "preflight", "version", "scenario pilot-ask-once", "tripwire pilot-ask-once", ...CLEANUP]);
    expect(result.rows).toHaveLength(1);
  });

});

describe("final integrity in the cleanup pipeline", () => {
  it("fails the row, keeps the root, and stops the run when final integrity fails after shutdown", async () => {
    const { calls, deps } = fakeDeps({ finalIntegrity: async () => (calls.push("finalIntegrity"), { ok: false, problems: ["changed xdg/config/opencode/package.json"] }) });
    const result = await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps });
    expect(calls).not.toContain("removeRoot");
    expect(calls.slice(-3)).toEqual(["stopAll", "collect", "finalIntegrity"]);
    expect(result).toMatchObject({ stopped: true, rows: [{ failure: { stage: "integrity" }, integrity: { ok: false }, cleanup: { rootRemoved: false } }] });
    expect(result.rows).toHaveLength(1);
  });

  it("runs final integrity after shutdown on the failure path too", async () => {
    const { calls, deps } = fakeDeps({ preflight: async () => (calls.push("preflight"), { ok: false, failures: ["x"] }) });
    await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps });
    expect(calls.slice(-4)).toEqual(CLEANUP);
  });
});

describe("independent pilot work deadline (injected timer, tiny budget)", () => {
  function fakeTimers() {
    const scheduled: Array<{ ms: number; fn: () => void; cleared: boolean }> = [];
    return {
      scheduled,
      timers: {
        setTimeout: (fn: () => void, ms: number) => {
          const handle = { ms, fn, cleared: false };
          scheduled.push(handle);
          return handle;
        },
        clearTimeout: (handle: { cleared: boolean }) => {
          handle.cleared = true;
        },
      },
      fire: () => scheduled.forEach((handle) => !handle.cleared && handle.fn()),
    };
  }
  const deferred = () => {
    let resolve!: (value?: unknown) => void;
    const promise = new Promise((r) => (resolve = r));
    return { promise, resolve };
  };

  it("pilot defaults to 15 minutes; matrix schedules no deadline (not silent matrix policy)", async () => {
    expect(PILOT_WORK_BUDGET_MS).toBe(15 * 60 * 1000);
    const pilot = fakeTimers();
    await runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps: fakeDeps().deps, timers: pilot.timers });
    expect(pilot.scheduled.map((handle) => handle.ms)).toEqual([PILOT_WORK_BUDGET_MS]);
    expect(pilot.scheduled[0].cleared).toBe(true);
    const matrix = fakeTimers();
    await runMatrix({ rows: ROWS, mode: "matrix", tarballSha256: "t", deps: fakeDeps().deps, timers: matrix.timers });
    expect(matrix.scheduled).toEqual([]);
  });

  it("starts before fixture prepare and binds the run-wide work signal into the runtime", async () => {
    const t = fakeTimers();
    const bound: AbortSignal[] = [];
    const { calls, deps } = fakeDeps({ bindSignal: (signal: AbortSignal) => (calls.push("bindSignal"), bound.push(signal)) });
    await runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps, timers: t.timers, workBudgetMs: 5 });
    expect(calls.slice(0, 2)).toEqual(["bindSignal", "fixture v1-floor"]);
    expect(t.scheduled[0].ms).toBe(5);
    expect(bound[0]).toBeInstanceOf(AbortSignal);
  });

  it("expiry during a deferred prepare: stops owned processes at once, never proceeds after prepare resolves, and still completes cleanup and a non-passing report", async () => {
    const t = fakeTimers();
    const gate = deferred();
    const { calls, deps } = fakeDeps({
      prepare: async () => {
        calls.push("prepare");
        await gate.promise;
        calls.push("prepare-resolved");
      },
    });
    const running = runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps, timers: t.timers, workBudgetMs: 5 });
    await new Promise((resolve) => setImmediate(resolve));
    t.fire();
    await new Promise((resolve) => setImmediate(resolve));
    expect(calls).toEqual(["fixture v1-floor", "prepare", "stopAll"]);
    gate.resolve();
    const result = await running;

    expect(calls).toEqual(["fixture v1-floor", "prepare", "stopAll", "prepare-resolved", ...CLEANUP]);
    expect(result).toMatchObject({ deadlineExceeded: true, stopped: true, rows: [{ failure: { stage: "deadline" }, executed: false }] });
    const report = buildReport({ executed: false, mode: "pilot", rows: result.rows, deadlineExceeded: result.deadlineExceeded });
    expect(report.status).toBe("failed");
    expect(report.reasons.join()).toMatch(/pilot work deadline exceeded/);
    expect(pilotVerdict(report).passed).toBe(false);
  });

  it("expiry during a deferred preflight: no version probe or scenario runs afterwards", async () => {
    const t = fakeTimers();
    const gate = deferred();
    const { calls, deps } = fakeDeps({
      preflight: async () => {
        calls.push("preflight");
        await gate.promise;
        return { ok: true, failures: [] };
      },
    });
    const running = runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps, timers: t.timers, workBudgetMs: 5 });
    await new Promise((resolve) => setImmediate(resolve));
    t.fire();
    gate.resolve();
    const result = await running;
    expect(calls).not.toContain("version");
    expect(calls.filter((call) => call.startsWith("scenario"))).toEqual([]);
    expect(result.rows[0].failure.stage).toBe("deadline");
  });

  it("a deadline after shutdown still runs final integrity, and an integrity failure is reported", async () => {
    const t = fakeTimers();
    const gate = deferred();
    const { calls, deps } = fakeDeps({
      scenario: async (_f: unknown, _r: unknown, id: string) => {
        calls.push(`scenario ${id}`);
        await gate.promise;
        return { id, status: "pass", problems: [] };
      },
      finalIntegrity: async () => (calls.push("finalIntegrity"), { ok: false, problems: ["added home/.npm"] }),
    });
    const running = runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps, timers: t.timers, workBudgetMs: 5 });
    await new Promise((resolve) => setTimeout(resolve, 5));
    t.fire();
    gate.resolve();
    const result = await running;
    expect(calls.slice(-3)).toEqual(["stopAll", "collect", "finalIntegrity"]);
    expect(result.rows[0]).toMatchObject({ failure: { stage: "deadline" }, integrity: { ok: false, problems: ["added home/.npm"] }, cleanup: { rootRemoved: false } });
  });

  it("disarms the work timer at the work->cleanup boundary: a timer firing during cleanup is not an expiry", async () => {
    const t = fakeTimers();
    const gate = deferred();
    const { calls, deps } = fakeDeps({
      stopAll: async () => {
        calls.push("stopAll");
        await gate.promise;
        return [];
      },
    });
    const running = runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps, timers: t.timers, workBudgetMs: 5 });
    for (let i = 0; i < 20 && !calls.includes("stopAll"); i += 1) await new Promise((resolve) => setImmediate(resolve));
    expect(calls.at(-1)).toBe("stopAll");
    expect(t.scheduled[0].cleared).toBe(true);
    t.fire();
    gate.resolve();
    const result = await running;
    expect(result.deadlineExceeded).toBe(false);
    expect(result.rows[0].failure).toBeUndefined();
    expect(calls.filter((call) => call === "stopAll")).toEqual(["stopAll"]);
    expect(calls.slice(-4)).toEqual(CLEANUP);
  });

  it("disarms at the boundary on the failure path too, and an already-expired deadline stays a failure", async () => {
    const failing = fakeTimers();
    const { deps } = fakeDeps({ preflight: async () => ({ ok: false, failures: ["x"] }), stopAll: async () => (failing.fire(), []) });
    const result = await runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps, timers: failing.timers, workBudgetMs: 5 });
    expect(result).toMatchObject({ deadlineExceeded: false, rows: [{ failure: { stage: "preflight" } }] });

    const expired = fakeTimers();
    const gate = deferred();
    const late = fakeDeps({ prepare: async () => gate.promise });
    const running = runMatrix({ rows: ROWS, mode: "pilot", tarballSha256: "t", deps: late.deps, timers: expired.timers, workBudgetMs: 5 });
    await new Promise((resolve) => setImmediate(resolve));
    expired.fire();
    gate.resolve();
    expect(await running).toMatchObject({ deadlineExceeded: true, rows: [{ failure: { stage: "deadline" } }] });
  });
});
