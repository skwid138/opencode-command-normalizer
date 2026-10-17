import { describe, expect, it } from "vitest";

import { REQUIRED_ROWS, REQUIRED_SCENARIOS, buildReport, pilotVerdict, sanitize } from "./report.mjs";

const passScenarios = () => REQUIRED_SCENARIOS.map((id: string) => ({ id, status: "pass", problems: [] }));
const row = (id: string, overrides: Record<string, unknown> = {}) => ({
  id,
  executed: true,
  expectedVersion: "x",
  version: { ok: true, expected: "x", observed: "x" },
  binary: { path: "/fx/stage/opencode", sha256: "a".repeat(64) },
  tarballSha256: "b".repeat(64),
  preflight: { ok: true, failures: [] },
  scenarios: passScenarios(),
  lifecycle: { status: "pass", problems: [] },
  cleanup: { aliveAfter: [], rootRemoved: true, unsafe: false },
  integrity: { ok: true, problems: [] },
  ...overrides,
});
const allRows = () => REQUIRED_ROWS.map((id: string) => row(id));

describe("report status", () => {
  it("requires every matrix row and every scenario, including lifecycle, to have actually run and passed", () => {
    expect(REQUIRED_ROWS).toEqual(["v1-floor", "v1-daily", "v2"]);
    expect(REQUIRED_SCENARIOS).toContain("pilot-ask-once");
    expect(REQUIRED_SCENARIOS).not.toContain("lifecycle");
    expect(buildReport({ executed: true, rows: allRows() })).toMatchObject({ status: "complete", reasons: [] });
  });

  it("is incomplete when runtime was not executed", () => {
    const report = buildReport({ executed: false, rows: [], gateProblems: ["gate 2 approval missing"] });
    expect(report.status).toBe("incomplete");
    expect(report.reasons.join("\n")).toMatch(/runtime was not executed/);
    expect(report.reasons.join("\n")).toMatch(/gate 2 approval missing/);
  });

  it("is incomplete for a startup-only row or a missing row or scenario", () => {
    expect(buildReport({ executed: true, rows: [row("v1-floor", { scenarios: [], lifecycle: null }), row("v1-daily"), row("v2")] }).reasons.join()).toMatch(
      /v1-floor: missing scenario pilot-ask-once/,
    );
    expect(buildReport({ executed: true, rows: [row("v1-floor"), row("v2")] }).reasons.join()).toMatch(/row v1-daily was not run/);
    expect(buildReport({ executed: true, rows: [row("v1-floor", { executed: false }), row("v1-daily"), row("v2")] }).status).toBe("incomplete");
  });

  it("is failed when any scenario, lifecycle, preflight, or cleanup failed", () => {
    const failing = passScenarios();
    failing[2] = { id: failing[2].id, status: "fail", problems: ["x"] };
    expect(buildReport({ executed: true, rows: [row("v1-floor", { scenarios: failing }), row("v1-daily"), row("v2")] }).status).toBe("failed");
    expect(buildReport({ executed: true, rows: [row("v1-floor", { lifecycle: { status: "fail", problems: ["dup"] } }), row("v1-daily"), row("v2")] }).status).toBe("failed");
    expect(buildReport({ executed: true, rows: [row("v1-floor", { preflight: { ok: false, failures: ["canary-read"] } }), row("v1-daily"), row("v2")] }).status).toBe(
      "failed",
    );
    expect(buildReport({ executed: true, rows: [row("v1-floor", { cleanup: { aliveAfter: [123], rootRemoved: false, unsafe: false } }), row("v1-daily"), row("v2")] }).status).toBe(
      "failed",
    );
  });

  it("states that results are limited to the exact versions and local environment", () => {
    expect(buildReport({ executed: true, rows: allRows() }).limits).toMatch(/exact versions.*local environment/);
  });
});

describe("shutdown failures", () => {
  it("fails an otherwise complete report when a signal shutdown stop failed", () => {
    const report = buildReport({ executed: true, rows: allRows(), shutdownFailures: ["SIGTERM shutdown stop failed: group 77 survived stop"] });
    expect(report.status).toBe("failed");
    expect(report.reasons.join()).toMatch(/shutdown: SIGTERM shutdown stop failed/);
    expect(pilotVerdict(buildReport({ executed: true, mode: "pilot", rows: allRows().slice(0, 1), shutdownFailures: ["x"] })).passed).toBe(false);
  });
});

describe("pilot verdict", () => {
  const pilotRow = (overrides: Record<string, unknown> = {}) =>
    row("v1-floor", { scenarios: [{ id: "pilot-ask-once", status: "pass", problems: [] }], lifecycle: null, ...overrides });

  it("passes only a clean pilot: executed, preflight ok, version ok, pilot passed, no failure, clean cleanup", () => {
    expect(pilotVerdict(buildReport({ executed: true, mode: "pilot", rows: [pilotRow()] }))).toEqual({ passed: true, problems: [] });
  });

  it.each([
    ["a failed cleanup", { cleanup: { aliveAfter: [7], rootRemoved: false, unsafe: false }, failure: { stage: "cleanup", message: "alive" } }, /cleanup/],
    ["a root that was kept", { cleanup: { aliveAfter: [], rootRemoved: false, unsafe: false } }, /cleanup/],
    ["a version mismatch", { version: { ok: false, expected: "1.18.29", observed: "1.18.34" } }, /version/],
    ["a failed preflight", { preflight: { ok: false, failures: ["x"] } }, /preflight/],
    ["a failed pilot scenario", { scenarios: [{ id: "pilot-ask-once", status: "fail", problems: ["y"] }] }, /pilot-ask-once/],
    ["a row failure", { failure: { stage: "tripwire", message: "left-pad" } }, /tripwire/],
    ["a failed final integrity", { integrity: { ok: false, problems: ["added home/.npm"] } }, /final integrity/],
    ["a skipped final integrity", { integrity: { ok: true, skipped: "no baseline", problems: [] } }, /final integrity/],
  ])("fails for %s", (_label, overrides, message) => {
    const verdict = pilotVerdict(buildReport({ executed: true, mode: "pilot", rows: [pilotRow(overrides)] }));
    expect(verdict.passed).toBe(false);
    expect(verdict.problems.join("\n")).toMatch(message);
  });

  it("fails when nothing ran or the report is not a pilot", () => {
    expect(pilotVerdict(buildReport({ executed: false, mode: "pilot", rows: [] })).passed).toBe(false);
    expect(pilotVerdict(buildReport({ executed: true, mode: "matrix", rows: allRows() })).passed).toBe(false);
  });
});

describe("report status with version evidence", () => {
  it("is failed when an executed row's sandboxed version probe did not match", () => {
    const rows = allRows();
    rows[1] = row("v1-daily", { version: { ok: false, expected: "1.18.35", observed: "1.18.34" } });
    expect(buildReport({ executed: true, rows }).reasons.join()).toMatch(/v1-daily: version probe/);
  });

  it("is failed when an executed row has no version probe", () => {
    const rows = allRows();
    rows[2] = row("v2", { version: null });
    expect(buildReport({ executed: true, rows }).status).toBe("failed");
  });
});

describe("report sanitization", () => {
  it("replaces fixture, repo, and real-home paths and redacts credential-like keys and values", () => {
    const out = sanitize(
      {
        path: "/Users/me/code/repo/test/x",
        home: "/Users/me/.config/opencode",
        fixture: "/private/var/fx/rh-v1-1/home",
        nested: [{ apiKey: "abc", Authorization: "Bearer t", ok: "sk-live1234567890abcdef" }],
        log: "host said s3cr3t-fixture-password twice: s3cr3t-fixture-password",
      },
      { realHome: "/Users/me", repoRoot: "/Users/me/code/repo", fixtureRoot: "/private/var/fx/rh-v1-1", secrets: ["s3cr3t-fixture-password"] },
    );
    expect(out).toEqual({
      path: "<REPO>/test/x",
      home: "<HOME>/.config/opencode",
      fixture: "<FIXTURE>/home",
      nested: [{ apiKey: "[redacted]", Authorization: "[redacted]", ok: "[redacted]" }],
      log: "host said [redacted] twice: [redacted]",
    });
  });
});
