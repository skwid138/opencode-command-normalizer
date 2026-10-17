#!/usr/bin/env node
// Fake OpenAI-compatible chat endpoint for real-host runs.
//
// Self-contained (node: builtins only) so it can be copied into the fixture
// and run under the sandbox by an explicit Node executable. It never forwards
// anything. Per tool-bearing request it emits the next scripted call to the
// host's built-in tool (bash on V1, shell on V2), and once every scripted call
// has a tool result it returns a terminal text containing the fixed nonce.
// Requests without tools (auxiliary, e.g. titles) get plain text. Unknown
// routes and models are rejected; a finite call budget is enforced here, as a
// harness guard.
//
// The handler is pure and unit-tested in memory. serve()/main() open a real
// loopback socket and are only used by the separately approved runtime gate.
import { createServer } from "node:http";
import { appendFileSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const AUX_TEXT = "real-host fixture";

export const IDENTITY_PATH = "/__rh/identity";

export function createFakeProvider({ model, nonce, toolName, toolCalls, toolArgs, callBudget, identityToken, basePath = "/v1" }) {
  if (typeof identityToken !== "string" || identityToken.length < 8) throw new Error("fake provider requires a per-instance identity token");
  const ledger = [];
  let calls = 0;
  let budgetExceeded = false;
  let rejected = 0;
  let toolNotAdvertised = 0;
  const callId = (index) => `call_${nonce}_${index}`;

  function reply(status, body, entry) {
    ledger.push({ n: calls, status, ...entry });
    return { status, headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
  }

  function completion(request, message, finishReason, entry) {
    const created = 0;
    const id = `chatcmpl_${nonce}_${calls}`;
    ledger.push({ n: calls, status: 200, stream: request.stream === true, ...entry });
    if (request.stream !== true) {
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id, object: "chat.completion", created, model, choices: [{ index: 0, message, finish_reason: finishReason }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }),
      };
    }
    const delta = message.tool_calls
      ? { role: "assistant", tool_calls: message.tool_calls.map((call, index) => ({ index, ...call })) }
      : { role: "assistant", content: message.content };
    const chunks = [
      { id, object: "chat.completion.chunk", created, model, choices: [{ index: 0, delta, finish_reason: null }] },
      { id, object: "chat.completion.chunk", created, model, choices: [{ index: 0, delta: {}, finish_reason: finishReason }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } },
    ];
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: `${chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join("")}data: [DONE]\n\n` };
  }

  function handle({ method, path, body }) {
    // Identity is a harness probe, not a model call: it never spends the budget.
    if (method === "GET" && path === IDENTITY_PATH) {
      ledger.push({ n: calls, status: 200, kind: "identity" });
      return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify({ token: identityToken }) };
    }
    calls += 1;
    if (calls > callBudget) {
      budgetExceeded = true;
      return reply(429, { error: { message: "real-host fake provider call budget exceeded" } }, { kind: "budget-exceeded" });
    }
    if (method !== "POST" || path !== `${basePath}/chat/completions`) {
      rejected += 1;
      return reply(404, { error: { message: "unknown route" } }, { kind: "rejected", method, path });
    }
    const request = body && typeof body === "object" ? body : {};
    if (request.model !== model) {
      rejected += 1;
      return reply(400, { error: { message: "unknown model" } }, { kind: "rejected", model: request.model ?? null });
    }
    const advertised = Array.isArray(request.tools) ? request.tools.map((tool) => tool?.function?.name).filter((name) => typeof name === "string") : [];
    if (advertised.length === 0) return completion(request, { role: "assistant", content: AUX_TEXT }, "stop", { kind: "aux" });
    if (!advertised.includes(toolName)) {
      toolNotAdvertised += 1;
      return completion(request, { role: "assistant", content: `tool ${toolName} not advertised ${nonce}` }, "stop", { kind: "tool-not-advertised", advertised });
    }
    const messages = Array.isArray(request.messages) ? request.messages : [];
    const answered = new Set(messages.filter((m) => m?.role === "tool" && typeof m.tool_call_id === "string").map((m) => m.tool_call_id));
    const next = toolCalls.findIndex((_, index) => !answered.has(callId(index)));
    if (next === -1) return completion(request, { role: "assistant", content: `done ${nonce}` }, "stop", { kind: "final", answered: answered.size });
    const call = { id: callId(next), type: "function", function: { name: toolName, arguments: JSON.stringify(toolArgs(toolCalls[next])) } };
    return completion(request, { role: "assistant", content: null, tool_calls: [call] }, "tool_calls", { kind: "tool-call", callId: call.id, index: next });
  }

  return {
    handle,
    summary: () => ({ calls, budgetExceeded, rejected, toolNotAdvertised, ledger: [...ledger] }),
  };
}

const MAX_BODY_BYTES = 4 * 1024 * 1024;

/** Binds 127.0.0.1 on the owned port the sandbox profile allows. Runtime gate only. */
export function serve(provider, { port, onLedger }) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`fake provider needs an explicit owned port, got ${port}`);
  const server = createServer((req, res) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) req.destroy();
      else chunks.push(chunk);
    });
    req.on("end", () => {
      let body = null;
      try {
        body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : null;
      } catch {
        body = null;
      }
      const response = provider.handle({ method: req.method, path: new URL(req.url, "http://127.0.0.1").pathname, body });
      onLedger?.(provider.summary().ledger.at(-1));
      res.writeHead(response.status, response.headers);
      res.end(response.body);
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}

async function main() {
  const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, index, all) => (index % 2 === 0 ? [...pairs, [value.replace(/^--/, ""), all[index + 1]]] : pairs), []));
  const config = JSON.parse(readFileSync(args.config, "utf8"));
  const provider = createFakeProvider({ ...config, toolArgs: (call) => ({ command: call.command }) });
  const server = await serve(provider, { port: Number(args.port), onLedger: (entry) => appendFileSync(args.ledger, `${JSON.stringify(entry)}\n`) });
  writeFileSync(`${args["port-file"]}.tmp`, String(server.address().port));
  renameSync(`${args["port-file"]}.tmp`, args["port-file"]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
