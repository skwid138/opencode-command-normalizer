import { describe, expect, it } from "vitest";

import { createFakeProvider } from "./fake-provider.mjs";

const NONCE = "n0nce42";
const tools = (name: string) => [{ type: "function", function: { name, parameters: {} } }];

function provider(overrides: Record<string, unknown> = {}) {
  return createFakeProvider({
    model: "fake-model",
    nonce: NONCE,
    toolName: "bash",
    toolCalls: [{ command: "~/bin/rh-probe one" }],
    toolArgs: (call: { command: string }) => ({ command: call.command }),
    callBudget: 5,
    identityToken: "tok-12345678", // gitleaks:allow -- synthetic fake-provider identity fixture, not a credential
    ...overrides,
  });
}

function parseSSE(body: string) {
  return body
    .split("\n\n")
    .filter((block) => block.startsWith("data: "))
    .map((block) => block.slice(6))
    .filter((data) => data !== "[DONE]")
    .map((data) => JSON.parse(data));
}

const chat = (body: Record<string, unknown>) => ({ method: "POST", path: "/v1/chat/completions", body });

describe("fake OpenAI-compatible provider", () => {
  it("answers the first tool-bearing request with exactly the scripted built-in tool call", () => {
    const fake = provider();
    const response = fake.handle(chat({ model: "fake-model", stream: true, messages: [{ role: "user", content: "go" }], tools: tools("bash") }));

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toBe("text/event-stream");
    expect(response.body.endsWith("data: [DONE]\n\n")).toBe(true);
    const chunks = parseSSE(response.body);
    const call = chunks[0].choices[0].delta.tool_calls[0];
    expect(call).toMatchObject({ index: 0, id: `call_${NONCE}_0`, type: "function", function: { name: "bash" } });
    expect(JSON.parse(call.function.arguments)).toEqual({ command: "~/bin/rh-probe one" });
    expect(chunks.at(-1).choices[0].finish_reason).toBe("tool_calls");
  });

  it("returns a terminal text with the nonce once every scripted call has a tool result", () => {
    const fake = provider();
    const messages = [
      { role: "user", content: "go" },
      { role: "assistant", tool_calls: [{ id: `call_${NONCE}_0`, type: "function", function: { name: "bash", arguments: "{}" } }] },
      { role: "tool", tool_call_id: `call_${NONCE}_0`, content: "output" },
    ];
    const response = fake.handle(chat({ model: "fake-model", stream: false, messages, tools: tools("bash") }));

    expect(response.status).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.choices[0]).toMatchObject({ finish_reason: "stop", message: { role: "assistant", content: `done ${NONCE}` } });
  });

  it("walks a multi-call script in order (immediate first ask, later ask)", () => {
    const fake = provider({ toolCalls: [{ command: "a" }, { command: "b" }] });
    const result = (id: string) => [
      { role: "assistant", tool_calls: [{ id, type: "function", function: { name: "bash", arguments: "{}" } }] },
      { role: "tool", tool_call_id: id, content: "x" },
    ];
    const second = fake.handle(chat({ model: "fake-model", messages: [{ role: "user", content: "go" }, ...result(`call_${NONCE}_0`)], tools: tools("bash") }));
    expect(JSON.parse(JSON.parse(second.body).choices[0].message.tool_calls[0].function.arguments).command).toBe("b");
  });

  it("answers auxiliary no-tool requests with plain text and never a tool call", () => {
    const fake = provider();
    const response = fake.handle(chat({ model: "fake-model", messages: [{ role: "user", content: "title this" }] }));
    expect(JSON.parse(response.body).choices[0].message).toEqual({ role: "assistant", content: "real-host fixture" });
    expect(fake.summary().ledger.at(-1)).toMatchObject({ kind: "aux" });
  });

  it("records when the built-in tool is not advertised instead of calling a hidden tool", () => {
    const fake = provider();
    const response = fake.handle(chat({ model: "fake-model", messages: [{ role: "user", content: "go" }], tools: tools("read") }));
    expect(JSON.parse(response.body).choices[0].message.tool_calls).toBeUndefined();
    expect(fake.summary()).toMatchObject({ toolNotAdvertised: 1 });
  });

  it("rejects unknown routes, methods, and models", () => {
    const fake = provider();
    expect(fake.handle({ method: "GET", path: "/v1/models", body: null }).status).toBe(404);
    expect(fake.handle({ method: "POST", path: "/v1/responses", body: {} }).status).toBe(404);
    expect(fake.handle(chat({ model: "gpt-4o", messages: [] })).status).toBe(400);
    expect(fake.summary().rejected).toBe(3);
  });

  it("serves its per-instance identity token without spending the call budget", () => {
    const fake = provider({ callBudget: 1 });
    const identity = fake.handle({ method: "GET", path: "/__rh/identity", body: null });
    expect(identity).toMatchObject({ status: 200 });
    expect(JSON.parse(identity.body)).toEqual({ token: "tok-12345678" }); // gitleaks:allow -- synthetic fake-provider identity fixture, not a credential
    expect(fake.handle(chat({ model: "fake-model", messages: [] })).status).toBe(200);
    expect(fake.summary()).toMatchObject({ calls: 1, budgetExceeded: false, rejected: 0 });
  });

  it("requires an identity token", () => {
    expect(() => provider({ identityToken: "" })).toThrow(/identity token/);
  });

  it("enforces a finite call budget and reports when it is exceeded", () => {
    const fake = provider({ callBudget: 2 });
    const request = chat({ model: "fake-model", messages: [{ role: "user", content: "x" }] });
    expect(fake.handle(request).status).toBe(200);
    expect(fake.handle(request).status).toBe(200);
    expect(fake.handle(request).status).toBe(429);
    expect(fake.summary()).toMatchObject({ calls: 3, budgetExceeded: true });
  });
});
