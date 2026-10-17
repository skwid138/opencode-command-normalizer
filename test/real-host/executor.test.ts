import { describe, expect, it } from "vitest";

import { createEventRecorder, executeScenario } from "./executor.mjs";
import { createHttpClient } from "./http.mjs";
import { v1Host } from "./host-v1.mjs";
import { v2Host } from "./host-v2.mjs";
import { evaluateScenario, scenarioMatrix } from "./scenarios.mjs";

const HOME = "/fx/home";
const fixture = { home: HOME, project: "/fx/project", bin: `${HOME}/bin`, logs: "/fx/logs", evidence: "/fx/evidence" };
const NONCE = "n1";
const TAIL = `'~/lit' '$HOME/lit' '' 'a b'`;
const ARGV = [NONCE, "~/lit", "$HOME/lit", "", "a b"];
const record = (tool: string, pid: number) => ({ tool, executable: `${HOME}/bin/${tool}`, pid, home: HOME, cwd: fixture.project, argc: ARGV.length, argv: ARGV });
const matrix = scenarioMatrix({ fixture, nonce: NONCE });
const byId = (id: string) => matrix.find((s: { id: string }) => s.id === id);
const tick = (ms = 5) => new Promise((resolve) => setTimeout(resolve, ms));

type Options = { debugDelayMs?: number; debugNever?: boolean; noTerminal?: boolean; connect?: boolean; family?: "v1" | "v2" };

/**
 * In-memory V1/V2 host: reacts to control requests by appending raw events to
 * the recorder, the way a real host would publish them on its SSE stream.
 */
function fakeHost(opts: Options = {}) {
  const host = opts.family === "v2" ? v2Host : v1Host;
  const recorder = createEventRecorder(host);
  const debug: string[] = [];
  const evidence = { executions: [] as unknown[], audit: [] as unknown[], decisions: [] as unknown[] };
  const log: string[] = [];
  const raw = (type: string, body: Record<string, unknown>) =>
    recorder.push(opts.family === "v2" ? { id: `evt_${type}`, type, data: body } : { type, properties: body });
  if (opts.connect !== false) raw("server.connected", {});

  const toolDone = (status: string) => {
    if (opts.noTerminal) return;
    if (status === "completed") evidence.executions.push(record("rh-probe", 1));
    if (opts.family === "v2") {
      // Source-faithful: a locally executed tool publishes executed: tool.providerExecuted === false.
      if (status === "completed") raw("session.tool.success", { sessionID: "s1", id: "c1", executed: false });
      else raw("session.tool.failed", { sessionID: "s1", id: "c1", executed: false, error: { type: "aborted", message: "The user declined this tool call" } });
    } else {
      const state = status === "completed" ? { status } : { status, error: "The user rejected permission to use this specific tool call." };
      raw("message.part.updated", { sessionID: "s1", part: { type: "tool", sessionID: "s1", callID: "c1", tool: "bash", state } });
    }
    raw("session.idle", { sessionID: "s1" });
  };

  const transport = async (url: string, init: { method: string; body?: string }) => {
    const path = new URL(url).pathname;
    log.push(`${init.method} ${path}`);
    if (path === "/session" || path === "/api/session") {
      return new Response(JSON.stringify(opts.family === "v2" ? { data: { id: "s1" } } : { id: "s1" }), { status: 200 });
    }
    if (path.endsWith("/prompt_async") || path.endsWith("/prompt")) {
      evidence.audit.push({ sessionID: "s1", callID: "c1", command_node_text: `${HOME}/bin/rh-probe ${NONCE} ${TAIL}` });
      setTimeout(() => {
        if (opts.family === "v2") raw("permission.asked", { id: "per_1", sessionID: "s1", action: "shell", resources: [`${HOME}/bin/rh-probe ${NONCE} ${TAIL}`], source: { type: "tool", messageID: "m", id: "c1" } });
        else raw("permission.asked", { id: "per_1", sessionID: "s1", permission: "bash", patterns: [`${HOME}/bin/rh-probe ${NONCE} ${TAIL}`], always: [], tool: { messageID: "m", callID: "c1" } });
        if (!opts.debugNever) setTimeout(() => debug.push(`2026 permission asked cached: requestID=per_1 callID=c1`), opts.debugDelayMs ?? 0);
      }, 5);
      return new Response(opts.family === "v2" ? JSON.stringify({ data: {} }) : null, { status: opts.family === "v2" ? 200 : 204 });
    }
    if (path.includes("/reply")) {
      const decision = JSON.parse(init.body!)[opts.family === "v2" ? "decision" : "reply"];
      log.push(`reply ${decision} debugSeen=${debug.length > 0}`);
      evidence.decisions.push({ sessionID: "s1", requestID: "per_1", callID: "c1", reply: decision });
      setTimeout(() => {
        raw("permission.replied", { sessionID: "s1", requestID: "per_1", reply: decision });
        toolDone(decision === "reject" ? "error" : "completed");
      }, 5);
      return opts.family === "v2" ? new Response(null, { status: 204 }) : new Response("true", { status: 200 });
    }
    return new Response("not found", { status: 404 });
  };

  return {
    recorder,
    log,
    client: createHttpClient({ baseURL: "http://127.0.0.1:4096", transport }),
    readDebug: async () => debug.join("\n"),
    readEvidence: async () => ({
      ...evidence,
      provider: { calls: 2, budgetExceeded: false, rejected: 0, toolNotAdvertised: 0, ledger: [{ kind: "tool-call" }, { kind: "final" }] },
    }),
  };
}

const timing = { connectMs: 200, askMs: 500, debugRecordMs: 300, completionMs: 500, settleMs: 20, pollMs: 5 };

async function run(id: string, opts: Options = {}) {
  const fake = fakeHost(opts);
  const evidence = await executeScenario({
    host: opts.family === "v2" ? v2Host : v1Host,
    client: fake.client,
    recorder: fake.recorder,
    scenario: byId(id),
    directory: fixture.project,
    model: { providerID: "fake", modelID: "fake-model" },
    readDebug: fake.readDebug,
    readEvidence: fake.readEvidence,
    timing,
  });
  return { fake, evidence };
}

describe("scenario executor", () => {
  for (const family of ["v1", "v2"] as const) {
    it(`${family}: drives the ask-once pilot to evidence that passes evaluation`, async () => {
      const { evidence } = await run("pilot-ask-once", { family });
      expect(evaluateScenario(byId("pilot-ask-once"), evidence, { fixture, nonce: NONCE })).toEqual({ id: "pilot-ask-once", status: "pass", problems: [] });
      expect(evidence.events.map((e: { kind: string }) => e.kind)).toEqual([
        "connected",
        "submitted",
        "permission-asked",
        "permission-replied",
        "tool-terminal",
        "session-idle",
      ]);
    });
  }

  it("waits for the plugin's matching debug record before replying", async () => {
    const { fake, evidence } = await run("pilot-ask-once", { debugDelayMs: 60 });
    expect(fake.log).toContain("reply once debugSeen=true");
    expect(evidence.replies).toEqual([{ requestID: "per_1", decision: "once", accepted: true, afterDebugRecord: true }]);
  });

  it("still replies after the bounded debug deadline, recording that the precondition failed", async () => {
    const { evidence } = await run("pilot-ask-once", { debugNever: true });
    expect(evidence.replies[0]).toMatchObject({ afterDebugRecord: false, accepted: true });
    expect(evaluateScenario(byId("pilot-ask-once"), evidence, { fixture, nonce: NONCE }).problems.join()).toMatch(/before the plugin debug record/);
  });

  it("returns bounded incomplete evidence instead of hanging when no terminal result arrives", async () => {
    const started = Date.now();
    const { evidence } = await run("pilot-ask-once", { noTerminal: true });
    expect(Date.now() - started).toBeLessThan(3000);
    expect(evaluateScenario(byId("pilot-ask-once"), evidence, { fixture, nonce: NONCE }).problems.join()).toMatch(/no terminal tool result/);
  });

  it("fails fast when the event stream never connects, before submitting anything", async () => {
    const fake = fakeHost({ connect: false });
    await expect(
      executeScenario({
        host: v1Host,
        client: fake.client,
        recorder: fake.recorder,
        scenario: byId("pilot-ask-once"),
        directory: fixture.project,
        model: { providerID: "fake", modelID: "fake-model" },
        readDebug: fake.readDebug,
        readEvidence: fake.readEvidence,
        timing,
      }),
    ).rejects.toThrow(/did not connect/);
    expect(fake.log).toEqual([]);
  });
});

describe("cancel", () => {
  function cancelHost(childSurvives: boolean) {
    const recorder = createEventRecorder(v1Host);
    const alive = new Set<number>();
    const executions: unknown[] = [];
    const log: string[] = [];
    const raw = (type: string, properties: Record<string, unknown>) => recorder.push({ type, properties });
    raw("server.connected", {});
    const transport = async (url: string, init: { method: string }) => {
      const path = new URL(url).pathname;
      log.push(`${init.method} ${path}`);
      if (path === "/session") return new Response(JSON.stringify({ id: "s1" }), { status: 200 });
      if (path.endsWith("/prompt_async")) {
        setTimeout(() => {
          alive.add(777);
          executions.push(record("rh-sleep", 777));
          raw("message.part.updated", { sessionID: "s1", part: { type: "tool", sessionID: "s1", callID: "c1", tool: "bash", state: { status: "running" } } });
        }, 5);
        return new Response(null, { status: 204 });
      }
      if (path.endsWith("/abort")) {
        if (!childSurvives) alive.delete(777);
        setTimeout(() => {
          raw("message.part.updated", { sessionID: "s1", part: { type: "tool", sessionID: "s1", callID: "c1", tool: "bash", state: { status: "error", error: "Tool execution aborted" } } });
          raw("session.idle", { sessionID: "s1" });
        }, 5);
        return new Response("true", { status: 200 });
      }
      return new Response("", { status: 404 });
    };
    return {
      log,
      run: () =>
        executeScenario({
          host: v1Host,
          client: createHttpClient({ baseURL: "http://127.0.0.1:4096", transport }),
          recorder,
          scenario: byId("cancel"),
          directory: fixture.project,
          model: { providerID: "fake", modelID: "fake-model" },
          readDebug: async () => "",
          readEvidence: async () => ({
            executions,
            audit: [{ sessionID: "s1", callID: "c1", command_node_text: `${HOME}/bin/rh-sleep ${NONCE} ${TAIL}` }],
            decisions: [],
            provider: { calls: 1, budgetExceeded: false, rejected: 0, toolNotAdvertised: 0, ledger: [{ kind: "tool-call" }] },
          }),
          timing,
          pidAlive: (pid: number) => alive.has(pid),
        }),
    };
  }

  it("cancels only after the tool is running and its pid is recorded, then verifies the child exited", async () => {
    const host = cancelHost(false);
    const evidence = await host.run();
    expect(host.log).toEqual(["POST /session", "POST /session/s1/prompt_async", "POST /session/s1/abort"]);
    expect(evidence.cancel).toEqual({ requested: true, accepted: true, childPidsAliveAfter: [] });
    expect(evaluateScenario(byId("cancel"), evidence, { fixture, nonce: NONCE })).toMatchObject({ status: "pass" });
  });

  it("records a child that survived the cancel", async () => {
    const evidence = await cancelHost(true).run();
    expect(evidence.cancel.childPidsAliveAfter).toEqual([777]);
    expect(evaluateScenario(byId("cancel"), evidence, { fixture, nonce: NONCE }).status).toBe("fail");
  });
});

describe("event recorder", () => {
  it("normalizes raw SSE payloads in arrival order and resolves waiters", async () => {
    const recorder = createEventRecorder(v1Host);
    const waiting = recorder.waitFor((event: { kind: string }) => event.kind === "session-idle", { timeoutMs: 200 });
    recorder.push('{"type":"server.connected","properties":{}}');
    await tick();
    recorder.push({ type: "session.idle", properties: { sessionID: "s" } });
    await expect(waiting).resolves.toMatchObject({ kind: "session-idle", sessionID: "s" });
    recorder.push("not json");
    expect(recorder.records.map((event: { kind: string }) => event.kind)).toEqual(["connected", "session-idle", "unparseable"]);
    await expect(recorder.waitFor(() => false, { timeoutMs: 20 })).resolves.toBeNull();
  });
});
