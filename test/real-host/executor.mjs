// Drives one scenario against a running host through its HTTP control API and
// records evidence. All waits are bounded. The executor never decides pass or
// fail; scenarios.mjs judges the evidence it returns.
//
// Controlled replies: for each expected ask, wait for the permission.asked
// event, then (when the plugin is present) wait for the plugin's matching
// debug record "permission asked cached: requestID=<id>" before replying,
// within a bounded deadline. That record is the reply precondition only; it
// is not a general readiness signal. If it never appears, the reply is still
// sent (so the session can finish and evidence can be collected) and the
// evidence records afterDebugRecord: false, which fails evaluation.
import { ASK_CACHED_DEBUG } from "./contracts.mjs";
import { evaluateCompletion } from "./scenarios.mjs";
import { pidLiveness } from "./supervisor.mjs";

export const PROMPT_TEXT = "real-host fixture: perform the scripted tool call";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitUntil(check, timeoutMs, pollMs, signal) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await check()) return true;
    if (Date.now() >= deadline || signal?.aborted) return false;
    await sleep(pollMs);
  }
}

/** Run-wide work signal check before each host control request (pilot deadline or operator abort). */
function ensureWork(signal, where) {
  if (signal?.aborted) throw new Error(`work aborted before ${where}`);
}

export function createEventRecorder(host) {
  const records = [];
  let waiters = [];
  function append(event) {
    records.push(event);
    const still = [];
    for (const waiter of waiters) {
      if (waiter.predicate(event)) {
        clearTimeout(waiter.timer);
        waiter.resolve(event);
      } else still.push(waiter);
    }
    waiters = still;
  }
  return {
    records,
    push(payload) {
      let raw = payload;
      if (typeof payload === "string") {
        try {
          raw = JSON.parse(payload);
        } catch {
          append({ kind: "unparseable" });
          return;
        }
      }
      append(host.normalizeEvent(raw));
    },
    mark(event) {
      append(event);
    },
    waitFor(predicate, { timeoutMs }) {
      const existing = records.find(predicate);
      if (existing) return Promise.resolve(existing);
      return new Promise((resolve) => {
        const waiter = { predicate, resolve, timer: setTimeout(() => {
          waiters = waiters.filter((candidate) => candidate !== waiter);
          resolve(null);
        }, timeoutMs) };
        waiters.push(waiter);
      });
    },
  };
}

/** Only a genuine ESRCH proves a cancelled child is gone; EPERM or any other error is not proof. */
const isPidAlive = (pid) => pidLiveness(pid) !== "dead";

export async function executeScenario({ host, client, recorder, scenario, phase, directory, model, readDebug, readEvidence, timing, pidAlive = isPidAlive, signal }) {
  const replies = phase?.replies ?? scenario.replies;
  const expect = phase?.expect ?? scenario.expect;
  const pluginPresent = Boolean(scenario.plugin) && phase?.name !== "removed";

  const connected = await recorder.waitFor((event) => event.kind === "connected", { timeoutMs: timing.connectMs });
  if (!connected) throw new Error(`event stream did not connect within ${timing.connectMs}ms`);

  ensureWork(signal, "session creation");
  const created = await client.request(host.routes.createSession(directory));
  const sessionID = host.sessionIDFrom(created);
  if (!sessionID) throw new Error(`session creation failed (status ${created.status})`);

  ensureWork(signal, "prompt");
  recorder.mark({ kind: "submitted", sessionID });
  const prompt = await client.request(host.routes.prompt({ sessionID, text: PROMPT_TEXT, model, directory }));
  const promptAccepted = prompt.status >= 200 && prompt.status < 300;

  const sent = [];
  for (const decision of replies) {
    const ask = await recorder.waitFor(
      (event) => event.kind === "permission-asked" && event.sessionID === sessionID && !sent.some((reply) => reply.requestID === event.requestID),
      { timeoutMs: timing.askMs },
    );
    if (!ask) break;
    const afterDebugRecord = pluginPresent
      ? await waitUntil(async () => (await readDebug()).includes(ASK_CACHED_DEBUG(ask.requestID)), timing.debugRecordMs, timing.pollMs, signal)
      : false;
    ensureWork(signal, "permission reply");
    const response = await client.request(host.routes.reply({ sessionID, requestID: ask.requestID, decision, directory }));
    sent.push({ requestID: ask.requestID, decision, accepted: host.replyAccepted(response), afterDebugRecord });
  }

  let cancel;
  if (expect.cancel) {
    cancel = { requested: false, accepted: false, childPidsAliveAfter: [] };
    let pids = [];
    const running = await waitUntil(async () => {
      const seen = recorder.records.some((event) => event.kind === "tool-running" && event.sessionID === sessionID);
      pids = ((await readEvidence({ sessionID })).executions ?? []).filter((entry) => entry.tool === expect.tool).map((entry) => entry.pid);
      return seen && pids.length > 0;
    }, timing.completionMs, timing.pollMs);
    if (running) {
      ensureWork(signal, "cancel");
      const response = await client.request(host.routes.cancel({ sessionID, directory }));
      cancel.requested = true;
      cancel.accepted = response.status >= 200 && response.status < 300;
      await waitUntil(() => pids.every((pid) => !pidAlive(pid)), timing.completionMs, timing.pollMs);
      cancel.childPidsAliveAfter = pids.filter((pid) => pidAlive(pid));
    }
  }

  await waitUntil(
    () => evaluateCompletion({ events: recorder.records, sessionID, promptAccepted }, { expectedToolCalls: scenario.toolCalls.length }).complete,
    timing.completionMs,
    timing.pollMs,
    signal,
  );
  // Short bounded settle so a hidden retry or late duplicate is still recorded.
  await sleep(timing.settleMs);

  const collected = await readEvidence({ sessionID });
  return { sessionID, promptAccepted, events: [...recorder.records], replies: sent, ...(cancel ? { cancel } : {}), ...collected };
}
