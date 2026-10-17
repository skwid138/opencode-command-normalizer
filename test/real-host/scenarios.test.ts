import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readdir, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { FIXTURE_COMMANDS, SCRIPT_SYSTEM_EXECUTABLES, TAIL_ARGS, evaluateCompletion, fixtureExecutables, evaluateLifecycle, evaluateScenario, parseExecRecord, probeScript, scenarioMatrix, sleepScript } from "./scenarios.mjs";

const HOME = "/fx/home";
const PROJECT = "/fx/project";
const NONCE = "abc123";
const fixture = { home: HOME, project: PROJECT, bin: `${HOME}/bin`, logs: "/fx/logs", evidence: "/fx/evidence" };
const ctx = { fixture, nonce: NONCE };
const ABS = `${HOME}/bin/rh-probe`;
const TAIL = `'~/lit' '$HOME/lit' '' 'a b'`;

type Scenario = {
  id: string;
  plugin: null | { options: Record<string, unknown> };
  command: string;
  rules: Array<{ pattern: string; effect: string }>;
  replies: string[];
  expect: Record<string, any>;
};
const matrix: Scenario[] = scenarioMatrix({ fixture, nonce: NONCE });
const byId = (id: string) => matrix.find((s) => s.id === id)!;

const created: string[] = [];
afterEach(async () => {
  for (const dir of created.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe("scenario matrix", () => {
  it("covers the pilot, baseline, home forms, canonical decisions, roots, braces, lifecycle, cancel, and asks", () => {
    expect(matrix.map((s) => s.id)).toEqual([
      "pilot-ask-once",
      "baseline-plugin-absent",
      "tilde-allow",
      "dollar-home-allow",
      "deny-resource",
      "ask-reject",
      "roots-empty",
      "braces-off",
      "braces-on",
      "lifecycle",
      "cancel",
      "asks-immediate-and-later",
    ]);
  });

  it("keeps roots [] separate from brace cases, which use valid non-empty roots", () => {
    expect(byId("roots-empty").plugin!.options.roots).toEqual([]);
    for (const id of ["braces-off", "braces-on"]) {
      expect((byId(id).plugin!.options.roots as string[]).length).toBeGreaterThan(0);
      expect(byId(id).command.startsWith("${HOME}/")).toBe(true);
    }
    expect(byId("braces-off").plugin!.options.expandBraceHome).toBe(false);
    expect(byId("braces-on").plugin!.options.expandBraceHome).toBe(true);
  });

  it("never overrides homedir or uses --pure, denies a specific resource, and names exact permission outcomes", () => {
    for (const s of matrix) {
      if (s.plugin) expect(s.plugin.options).not.toHaveProperty("homedir");
      expect(s.command).not.toMatch(/--pure/);
    }
    expect(byId("deny-resource").rules.find((rule) => rule.effect === "deny")!.pattern).toBe(`${ABS} *`);
    expect(byId("deny-resource").expect.terminal).toBe("denied");
    for (const id of ["ask-reject", "baseline-plugin-absent", "roots-empty", "braces-off"]) expect(byId(id).expect.terminal, id).toBe("rejected");
    expect(byId("cancel").expect.terminal).toBe("aborted");
  });

  it("passes a literal argument tail (quoted ~, quoted $HOME, empty, embedded space) and expects it verbatim in argv and audit", () => {
    expect(TAIL_ARGS).toEqual(["~/lit", "$HOME/lit", "", "a b"]);
    expect(byId("tilde-allow").command).toBe(`~/bin/rh-probe ${NONCE} ${TAIL}`);
    expect(byId("dollar-home-allow").command).toBe(`$HOME/bin/rh-probe ${NONCE} ${TAIL}`);
    expect(byId("tilde-allow").expect.argvs).toEqual([[NONCE, ...TAIL_ARGS]]);
    expect(byId("tilde-allow").expect.auditTexts).toEqual([`${ABS} ${NONCE} ${TAIL}`]);
    expect(byId("deny-resource").expect.argvs).toEqual([]);
  });
});

describe("fixture execution records", () => {
  async function runScript(script: string, name: string, args: string[]) {
    const dir = await realpath(await mkdtemp(join(tmpdir(), "rh-rec-")));
    created.push(dir);
    const records = join(dir, "records");
    const home = join(dir, "home");
    const cwd = join(dir, "project");
    for (const d of [records, join(home, "bin"), cwd]) await mkdir(d, { recursive: true });
    const exe = join(home, "bin", name);
    await writeFile(exe, script.replaceAll("@RECORDS@", records));
    await chmod(exe, 0o755);
    const result = spawnSync(exe, args, { cwd, env: { HOME: home, PATH: "/usr/bin:/bin" }, encoding: "utf8", timeout: 5000 });
    const files = (await readdir(records)).filter((file) => file.endsWith(".rec"));
    return { result, files, records, home, cwd, exe };
  }

  it("records the exact executable, argv (including empty and spaced args), argc, HOME, cwd, and pid unambiguously", async () => {
    const run = await runScript(probeScript({ recordDir: "@RECORDS@" }), "rh-probe", ["n0", "~/lit", "$HOME/lit", "", "a b", "x\ny"]);
    expect(run.result.status).toBe(0);
    expect(run.files).toHaveLength(1);
    const record = parseExecRecord(await readFile(join(run.records, run.files[0])));
    expect(record).toEqual({
      tool: "rh-probe",
      executable: run.exe,
      pid: expect.any(Number),
      home: run.home,
      cwd: run.cwd,
      argc: 6,
      argv: ["n0", "~/lit", "$HOME/lit", "", "a b", "x\ny"],
    });
  });

  it("the bounded sleep fixture records the same way before sleeping", () => {
    expect(sleepScript({ recordDir: "/r" })).toMatch(/exec \/bin\/sleep 30\n$/);
    expect(sleepScript({ recordDir: "/r" })).toContain("rh-exec-v1");
  });

  it("fixture scripts invoke only explicit absolute executables from the single contract list", () => {
    expect(FIXTURE_COMMANDS).toEqual(["rh-probe", "rh-sleep"]);
    expect(SCRIPT_SYSTEM_EXECUTABLES).toEqual(["/bin/sh", "/bin/mv", "/bin/sleep"]);
    for (const script of [probeScript({ recordDir: "/r" }), sleepScript({ recordDir: "/r" })]) {
      const invoked = [...script.matchAll(/(?:^#!|&& |exec |^)(\/[\w/]+)/gm)].map((match) => match[1]);
      expect(invoked.length).toBeGreaterThan(0);
      for (const path of invoked) expect(SCRIPT_SYSTEM_EXECUTABLES, path).toContain(path);
      expect(script).not.toMatch(/(^|[;&|] *)mv /m);
      expect(script).not.toMatch(/(^|[;&|] *|exec )sleep /m);
    }
    expect(fixtureExecutables("/fx/home/bin")).toEqual(["/fx/home/bin/rh-probe", "/fx/home/bin/rh-sleep", "/bin/sh", "/bin/mv", "/bin/sleep"]);
  });

  it("the required system executables exist as executable files (metadata only, never executed)", async () => {
    for (const path of SCRIPT_SYSTEM_EXECUTABLES) {
      const info = await stat(path);
      expect(info.isFile(), path).toBe(true);
      expect(info.mode & 0o111, path).not.toBe(0);
    }
  });

  it("rejects malformed records", () => {
    expect(parseExecRecord(Buffer.from("garbage"))).toMatchObject({ malformed: expect.any(String) });
    expect(parseExecRecord(Buffer.from("rh-exec-v1\u00001\u0000/h\u0000/c\u00002\u0000/h/bin/rh-probe\u0000only-one\u0000"))).toMatchObject({ malformed: expect.stringMatching(/argc/) });
  });
});

// ---- evidence fixtures ----
const rec = (argv: string[], over: Record<string, unknown> = {}) => ({ tool: "rh-probe", executable: ABS, pid: 10, home: HOME, cwd: PROJECT, argc: argv.length, argv, ...over });

function pilotEvidence() {
  return {
    sessionID: "s1",
    promptAccepted: true,
    events: [
      { kind: "connected" },
      { kind: "submitted" },
      { kind: "permission-asked", sessionID: "s1", requestID: "per_1", callID: "c1", patterns: [`${ABS} ${NONCE} ${TAIL}`] },
      { kind: "permission-replied", sessionID: "s1", requestID: "per_1", reply: "once" },
      { kind: "tool-running", sessionID: "s1", callID: "c1" },
      { kind: "tool-terminal", sessionID: "s1", callID: "c1", status: "completed", failure: null },
      { kind: "session-idle", sessionID: "s1" },
    ] as Array<Record<string, any>>,
    replies: [{ requestID: "per_1", decision: "once", accepted: true, afterDebugRecord: true }],
    executions: [rec([NONCE, ...["~/lit", "$HOME/lit", "", "a b"]])] as Array<Record<string, any>>,
    audit: [{ sessionID: "s1", callID: "c1", command_node_text: `${ABS} ${NONCE} ${TAIL}` }],
    decisions: [{ sessionID: "s1", requestID: "per_1", callID: "c1", reply: "once" }] as Array<Record<string, any>>,
    provider: { calls: 2, budgetExceeded: false, rejected: 0, toolNotAdvertised: 0, ledger: [{ kind: "tool-call" }, { kind: "final" }] },
  };
}

function rejectEvidence() {
  const e = pilotEvidence();
  e.events[3].reply = "reject";
  e.events[5] = { kind: "tool-terminal", sessionID: "s1", callID: "c1", status: "error", failure: "rejected", error: "The user rejected permission to use this specific tool call." };
  e.replies[0].decision = "reject";
  e.decisions[0].reply = "reject";
  e.executions = [];
  return e;
}

function denyEvidence() {
  const e = pilotEvidence();
  e.events = [
    { kind: "connected" },
    { kind: "submitted" },
    { kind: "tool-terminal", sessionID: "s1", callID: "c1", status: "error", failure: "denied" },
    { kind: "session-idle", sessionID: "s1" },
  ];
  e.replies = [];
  e.executions = [];
  e.decisions = [];
  return e;
}

describe("completion evidence", () => {
  it("is complete only with a matching terminal tool result followed by idle for the same session", () => {
    expect(evaluateCompletion(pilotEvidence(), { expectedToolCalls: 1 })).toMatchObject({ complete: true, callIDs: ["c1"] });
  });

  it.each([
    ["prompt admission only", (e: any) => (e.events = e.events.slice(0, 2)), /no terminal tool result/],
    ["idle without a terminal result", (e: any) => (e.events = e.events.filter((x: any) => x.kind !== "tool-terminal")), /no terminal tool result/],
    ["a terminal result for another session", (e: any) => (e.events.find((x: any) => x.kind === "tool-terminal").sessionID = "other"), /no terminal tool result/],
    ["no idle after the terminal result", (e: any) => (e.events = e.events.filter((x: any) => x.kind !== "session-idle")), /no idle/],
    ["idle only before the terminal result", (e: any) => e.events.splice(5, 0, e.events.pop()), /no idle/],
    ["a stream that connected after submission", (e: any) => e.events.splice(0, 2, e.events[1], e.events[0]), /connected before/],
    ["an unaccepted prompt", (e: any) => (e.promptAccepted = false), /prompt was not accepted/],
    ["an extra terminal call", (e: any) => e.events.splice(6, 0, { kind: "tool-terminal", sessionID: "s1", callID: "c2", status: "completed" }), /expected 1 terminal/],
  ])("is incomplete for %s", (_label, mutate, message) => {
    const evidence = pilotEvidence();
    mutate(evidence);
    const result = evaluateCompletion(evidence, { expectedToolCalls: 1 });
    expect(result.complete).toBe(false);
    expect(result.problems.join("\n")).toMatch(message);
  });
});

describe("scenario evaluation", () => {
  it("passes the pilot with complete, correlated evidence", () => {
    expect(evaluateScenario(byId("pilot-ask-once"), pilotEvidence(), ctx)).toEqual({ id: "pilot-ask-once", status: "pass", problems: [] });
  });

  it("passes a V2-faithful local success (providerExecuted: false) and rejects a provider-executed one", () => {
    const local = pilotEvidence();
    local.events[5].providerExecuted = false;
    expect(evaluateScenario(byId("pilot-ask-once"), local, ctx).status).toBe("pass");
    const hosted = pilotEvidence();
    hosted.events[5].providerExecuted = true;
    expect(evaluateScenario(byId("pilot-ask-once"), hosted, ctx).problems.join()).toMatch(/provider-executed/);
  });

  it.each([
    ["a missing execution", (e: any) => (e.executions = []), /expected 1 execution/],
    ["an execution with the wrong HOME", (e: any) => (e.executions[0].home = "/Users/real"), /HOME/],
    ["an execution with the wrong executable", (e: any) => (e.executions[0].executable = "/usr/local/bin/rh-probe"), /executable/],
    ["a shell-expanded tail (quoted ~ was expanded)", (e: any) => (e.executions[0].argv[1] = `${HOME}/lit`), /argv/],
    ["a dropped empty argument", (e: any) => (e.executions[0] = rec([NONCE, "~/lit", "$HOME/lit", "a b"])), /argv/],
    ["an argc that disagrees with argv", (e: any) => (e.executions[0].argc = 9), /argc/],
    ["a malformed execution record", (e: any) => e.executions.push({ malformed: "bad magic" }), /malformed/],
    ["a duplicated audit record (idempotent duplicate hook)", (e: any) => e.audit.push({ ...e.audit[0] }), /audit records for \(s1, c1\): 2/],
    ["an audit record that was not rewritten", (e: any) => (e.audit[0].command_node_text = `~/bin/rh-probe ${NONCE} ${TAIL}`), /audit command/],
    ["a reply sent before the plugin cached the ask", (e: any) => (e.replies[0].afterDebugRecord = false), /before the plugin debug record/],
    ["an unaccepted reply", (e: any) => (e.replies[0].accepted = false), /reply.*not accepted/],
    ["a hidden second ask", (e: any) => e.events.splice(3, 0, { kind: "permission-asked", sessionID: "s1", requestID: "per_2", callID: "c1", patterns: [] }), /expected 1 ask/],
    ["a missing decision record", (e: any) => (e.decisions = []), /decision record/],
    ["an ask whose patterns miss the canonical path", (e: any) => (e.events[2].patterns = ["~/bin/rh-probe"]), /patterns/],
    ["a completed terminal that reports a failure", (e: any) => (e.events[5].failure = "other"), /completed execution/],
    ["a provider budget overrun", (e: any) => (e.provider.budgetExceeded = true), /budget/],
    ["a hidden tool", (e: any) => (e.provider.toolNotAdvertised = 1), /not advertised/],
    ["a provider retry", (e: any) => e.provider.ledger.push({ kind: "tool-call" }), /tool calls issued: 2/],
  ])("fails on %s", (_label, mutate, message) => {
    const evidence = pilotEvidence();
    mutate(evidence);
    const result = evaluateScenario(byId("pilot-ask-once"), evidence, ctx);
    expect(result.status).toBe("fail");
    expect(result.problems.join("\n")).toMatch(message);
  });

  it("deny passes only for the permission-denied failure with zero executions and no ask", () => {
    expect(evaluateScenario(byId("deny-resource"), denyEvidence(), ctx).status).toBe("pass");
    for (const failure of ["other", "rejected", "aborted", null]) {
      const e = denyEvidence();
      e.events[2].failure = failure;
      expect(evaluateScenario(byId("deny-resource"), e, ctx).problems.join(), String(failure)).toMatch(/expected a denied permission outcome/);
    }
    const executed = denyEvidence();
    executed.executions = [rec([NONCE, "~/lit", "$HOME/lit", "", "a b"])];
    expect(evaluateScenario(byId("deny-resource"), executed, ctx).problems.join()).toMatch(/expected 0 execution/);
    const providerRan = denyEvidence();
    providerRan.events[2].providerExecuted = true;
    expect(evaluateScenario(byId("deny-resource"), providerRan, ctx).problems.join()).toMatch(/provider-executed/);
  });

  it("reject passes only for the rejected failure correlated to an explicit reject reply for the same call", () => {
    expect(evaluateScenario(byId("ask-reject"), rejectEvidence(), ctx)).toMatchObject({ status: "pass" });
    const arbitrary = rejectEvidence();
    arbitrary.events[5].failure = "other";
    arbitrary.events[5].error = "/bin/sh: rh-probe: command not found";
    expect(evaluateScenario(byId("ask-reject"), arbitrary, ctx).problems.join()).toMatch(/expected a rejected permission outcome/);
    const otherCall = rejectEvidence();
    otherCall.events[2].callID = "c9";
    otherCall.decisions[0].callID = "c9";
    expect(evaluateScenario(byId("ask-reject"), otherCall, ctx).problems.join()).toMatch(/no explicit reject reply correlated to call c1/);
    const repliedOnce = rejectEvidence();
    repliedOnce.events[3].reply = "once";
    expect(evaluateScenario(byId("ask-reject"), repliedOnce, ctx).problems.join()).toMatch(/permission\.replied/);
  });

  it("requires zero audit records when the plugin is absent, and records the host's observed patterns", () => {
    const evidence = rejectEvidence();
    const result = evaluateScenario(byId("baseline-plugin-absent"), evidence, ctx);
    expect(result.problems.join("\n")).toMatch(/plugin absent but 1 audit record/);
    expect(evaluateScenario(byId("baseline-plugin-absent"), { ...evidence, audit: [], decisions: [] }, ctx)).toMatchObject({
      status: "pass",
      observed: { patterns: [[`${ABS} ${NONCE} ${TAIL}`]] },
    });
  });

  it("cancel requires the abort outcome and the child to have exited", () => {
    const evidence = {
      ...pilotEvidence(),
      events: [
        { kind: "connected" },
        { kind: "submitted" },
        { kind: "tool-running", sessionID: "s1", callID: "c1" },
        { kind: "tool-terminal", sessionID: "s1", callID: "c1", status: "error", failure: "aborted" },
        { kind: "session-idle", sessionID: "s1" },
      ] as Array<Record<string, any>>,
      replies: [],
      decisions: [],
      executions: [rec([NONCE, "~/lit", "$HOME/lit", "", "a b"], { tool: "rh-sleep", executable: `${HOME}/bin/rh-sleep`, pid: 4242 })],
      audit: [{ sessionID: "s1", callID: "c1", command_node_text: `${HOME}/bin/rh-sleep ${NONCE} ${TAIL}` }],
      cancel: { requested: true, accepted: true, childPidsAliveAfter: [4242] },
    };
    expect(evaluateScenario(byId("cancel"), evidence, ctx).problems.join()).toMatch(/still alive after cancel: 4242/);
    const exited = { ...evidence, cancel: { ...evidence.cancel, childPidsAliveAfter: [] } };
    expect(evaluateScenario(byId("cancel"), exited, ctx).status).toBe("pass");
    exited.events[3] = { ...exited.events[3], failure: "other" };
    expect(evaluateScenario(byId("cancel"), exited, ctx).problems.join()).toMatch(/expected an aborted/);
  });
});

describe("lifecycle cardinality", () => {
  const phase = (name: string, audits: number, inventory = { ok: true, problems: [] as string[] }) => ({
    name,
    sessionID: `s-${name}`,
    callID: `c-${name}`,
    audit: Array.from({ length: audits }, () => ({ sessionID: `s-${name}`, callID: `c-${name}` })),
    inventory,
    scenario: { status: "pass", problems: [] as string[] },
  });

  it("passes 1 active, 0 removed, 1 restored for the actual callIDs", () => {
    expect(evaluateLifecycle([phase("active", 1), phase("removed", 0), phase("restored", 1)])).toEqual({ status: "pass", problems: [] });
  });

  it("detects duplicate hooks after restore, a hook that survived removal, inventory failures, and missing phases", () => {
    expect(evaluateLifecycle([phase("active", 1), phase("removed", 0), phase("restored", 2)]).problems.join()).toMatch(/restored: expected 1 audit record.*got 2/);
    expect(evaluateLifecycle([phase("active", 1), phase("removed", 1), phase("restored", 1)]).problems.join()).toMatch(/removed: expected 0/);
    expect(evaluateLifecycle([phase("active", 1), phase("removed", 0, { ok: false, problems: ["still listed"] }), phase("restored", 1)]).problems.join()).toMatch(
      /removed: inventory: still listed/,
    );
    expect(evaluateLifecycle([phase("active", 1), phase("restored", 1)]).status).toBe("fail");
  });
});
