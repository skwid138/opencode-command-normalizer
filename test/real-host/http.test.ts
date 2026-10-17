import { describe, expect, it } from "vitest";

import { createHttpClient, createSSEParser, encodeQuery, openEventStream, readEventStream, verifyAuthChallenge } from "./http.mjs";

type Call = { url: string; init: { method: string; body?: string; headers?: Record<string, string>; signal?: AbortSignal; redirect?: string } };

function fakeTransport(respond: (call: Call) => { status: number; body?: string; headers?: Record<string, string> }) {
  const calls: Call[] = [];
  const transport = async (url: string, init: Call["init"]) => {
    const call = { url, init };
    calls.push(call);
    const { status, body = "", headers = {} } = respond(call);
    return new Response(status === 204 || status === 401 ? null : body, { status, headers: { "content-type": "application/json", ...headers } });
  };
  return { calls, transport };
}

describe("loopback HTTP client", () => {
  it("refuses any base URL that is not an http loopback address with an explicit port", () => {
    for (const bad of ["https://127.0.0.1:1", "http://example.com:80", "http://localhost:4096", "http://127.0.0.1", "http://10.0.0.1:1"]) {
      expect(() => createHttpClient({ baseURL: bad }), bad).toThrow(/loopback/);
    }
    expect(() => createHttpClient({ baseURL: "http://127.0.0.1:4096" })).not.toThrow();
    expect(() => createHttpClient({ baseURL: "http://[::1]:4096" })).not.toThrow();
  });

  it("sends a bodyless POST with no body and no content type", async () => {
    const { calls, transport } = fakeTransport(() => ({ status: 204 }));
    const client = createHttpClient({ baseURL: "http://127.0.0.1:4096", transport });

    const result = await client.request({ method: "POST", path: "/api/location/reload" });

    expect(result).toEqual({ status: 204, json: null, text: "", headers: { "content-type": "application/json" } });
    expect(calls[0].url).toBe("http://127.0.0.1:4096/api/location/reload");
    expect(calls[0].init.body).toBeUndefined();
    expect(calls[0].init.headers?.["content-type"]).toBeUndefined();
    expect(calls[0].init.signal).toBeInstanceOf(AbortSignal);
  });

  it("sends JSON bodies and parses JSON responses, including bare booleans", async () => {
    const { calls, transport } = fakeTransport(() => ({ status: 200, body: "true" }));
    const client = createHttpClient({ baseURL: "http://127.0.0.1:4096", transport });

    const result = await client.request({ method: "POST", path: "/permission/per_1/reply", body: { reply: "once" } });

    expect(result.json).toBe(true);
    expect(JSON.parse(calls[0].init.body!)).toEqual({ reply: "once" });
    expect(calls[0].init.headers?.["content-type"]).toBe("application/json");
  });

  it("encodes deepObject location queries", () => {
    expect(encodeQuery({ location: { directory: "/tmp/fix ture" } })).toBe("location%5Bdirectory%5D=%2Ftmp%2Ffix%20ture");
    expect(encodeQuery({ directory: "/a" })).toBe("directory=%2Fa");
    expect(encodeQuery(undefined)).toBe("");
  });
});

describe("authenticated loopback control", () => {
  const auth = { username: "opencode", password: "fixture-only-password-1234" };
  const basic = `Basic ${Buffer.from("opencode:fixture-only-password-1234").toString("base64")}`;

  it("sends Basic auth and refuses redirects on every request and on the event stream", async () => {
    const { calls, transport } = fakeTransport(() => ({ status: 200, body: "[]" }));
    const client = createHttpClient({ baseURL: "http://127.0.0.1:4096", transport, auth });
    await client.request({ method: "GET", path: "/session" });
    await client.open({ path: "/event" });
    for (const call of calls) {
      expect(call.init.headers?.authorization).toBe(basic);
      expect(call.init.redirect).toBe("error");
    }
    const anonymous = createHttpClient({ baseURL: "http://127.0.0.1:4096", transport });
    await anonymous.request({ method: "GET", path: "/x" });
    expect(calls.at(-1)!.init.redirect).toBe("error");
  });

  it("can send one explicitly unauthenticated request and exposes response headers", async () => {
    const { calls, transport } = fakeTransport(() => ({ status: 401, headers: { "www-authenticate": 'Basic realm="Secure Area"' } }));
    const client = createHttpClient({ baseURL: "http://127.0.0.1:4096", transport, auth });
    const response = await client.request({ method: "GET", path: "/session", anonymous: true });
    expect(calls[0].init.headers?.authorization).toBeUndefined();
    expect(response.headers["www-authenticate"]).toBe('Basic realm="Secure Area"');
  });

  it("validates the fresh instance by its auth challenge before trusting the port", async () => {
    const route = { method: "GET", path: "/session" };
    const honest = fakeTransport((call) =>
      call.init.headers?.authorization === basic ? { status: 200, body: "[]" } : { status: 401, headers: { "www-authenticate": 'Basic realm="Secure Area"' } },
    );
    await expect(verifyAuthChallenge(createHttpClient({ baseURL: "http://127.0.0.1:4096", transport: honest.transport, auth }), route)).resolves.toEqual({
      challenged: true,
      authorized: true,
    });

    const openListener = fakeTransport(() => ({ status: 200, body: "[]" }));
    await expect(verifyAuthChallenge(createHttpClient({ baseURL: "http://127.0.0.1:4096", transport: openListener.transport, auth }), route)).rejects.toThrow(/did not challenge/);

    const wrongPassword = fakeTransport(() => ({ status: 401, headers: { "www-authenticate": 'Basic realm="Secure Area"' } }));
    await expect(verifyAuthChallenge(createHttpClient({ baseURL: "http://127.0.0.1:4096", transport: wrongPassword.transport, auth }), route)).rejects.toThrow(/rejected the fixture credentials/);

    const noChallengeHeader = fakeTransport(() => ({ status: 401 }));
    await expect(verifyAuthChallenge(createHttpClient({ baseURL: "http://127.0.0.1:4096", transport: noChallengeHeader.transport, auth }), route)).rejects.toThrow(/did not challenge/);
    expect(() => verifyAuthChallenge(createHttpClient({ baseURL: "http://127.0.0.1:4096", transport: honest.transport }), route)).toThrow(/requires fixture credentials/);
  });

  it("bounds the event-stream open with an independent deadline even if the transport ignores abort", async () => {
    const hanging = async () => new Promise<Response>(() => {});
    const client = createHttpClient({ baseURL: "http://127.0.0.1:4096", transport: hanging, auth });
    const started = Date.now();
    await expect(openEventStream(client, { path: "/event" }, { timeoutMs: 50 })).rejects.toThrow(/did not open within 50ms/);
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it("rejects a non-200 or bodiless event stream", async () => {
    const { transport } = fakeTransport(() => ({ status: 401 }));
    const client = createHttpClient({ baseURL: "http://127.0.0.1:4096", transport, auth });
    await expect(openEventStream(client, { path: "/event" }, { timeoutMs: 200 })).rejects.toThrow(/status 401/);
  });
});

describe("SSE parser", () => {
  it("parses events split across chunks, multi-line data, CRLF, ids, and comments", () => {
    const parser = createSSEParser();
    expect(parser.push(": keepalive\n\nid: 1\nevent: msg\ndata: {\"a\":")).toEqual([]);
    expect(parser.push("1}\r\ndata: x\r\n\r\ndata: second\n\n")).toEqual([
      { id: "1", event: "msg", data: '{"a":1}\nx' },
      // The last event ID persists across events (SSE spec).
      { id: "1", event: "message", data: "second" },
    ]);
  });

  it("treats a CRLF split across chunks as one line ending", () => {
    const parser = createSSEParser();
    expect(parser.push("data: a\r")).toEqual([]);
    expect(parser.push("\ndata: b\r\n\r\n")).toEqual([{ id: "", event: "message", data: "a\nb" }]);
  });

  it("fails instead of buffering an unbounded event", () => {
    const parser = createSSEParser({ maxEventBytes: 16 });
    expect(() => parser.push(`data: ${"x".repeat(32)}`)).toThrow(/exceeds/);
  });

  it("reads a response body stream to events and stops at the abort signal", async () => {
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode("data: {\"type\":\"server.connected\"}\n\n"));
        controller.enqueue(encoder.encode("data: {\"type\":\"two\"}\n\n"));
        controller.close();
      },
    });
    const seen: unknown[] = [];
    await readEventStream(body, (event: { data: string }) => {
      seen.push(JSON.parse(event.data));
    });
    expect(seen).toEqual([{ type: "server.connected" }, { type: "two" }]);
  });
});
