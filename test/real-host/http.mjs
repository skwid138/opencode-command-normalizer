// Minimal loopback-only HTTP client and bounded SSE parser for host control.
// The transport is injectable so unit tests never open sockets.

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]"]);

export function encodeQuery(query) {
  if (!query) return "";
  const parts = [];
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    if (value !== null && typeof value === "object") {
      for (const [inner, innerValue] of Object.entries(value)) {
        if (innerValue !== undefined) parts.push(`${encodeURIComponent(`${key}[${inner}]`)}=${encodeURIComponent(String(innerValue))}`);
      }
    } else parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
  }
  return parts.join("&");
}

export function assertLoopbackBaseURL(baseURL) {
  let url;
  try {
    url = new URL(baseURL);
  } catch {
    throw new Error(`base URL is not a loopback http URL: ${baseURL}`);
  }
  if (url.protocol !== "http:" || !LOOPBACK_HOSTS.has(url.hostname) || url.port === "" || url.username || url.password) {
    throw new Error(`base URL is not a loopback http URL with an explicit port: ${baseURL}`);
  }
  return url;
}

export const AUTH_CHALLENGE = 'Basic realm="Secure Area"';

export function createHttpClient({ baseURL, transport = globalThis.fetch, timeoutMs = 10_000, auth = null }) {
  const base = assertLoopbackBaseURL(baseURL);
  const origin = `${base.protocol}//${base.host}`;
  const authorization = auth ? `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString("base64")}` : null;
  const headersFor = (extra, anonymous) => ({ ...extra, ...(authorization && !anonymous ? { authorization } : {}) });
  return {
    origin,
    hasAuth: Boolean(authorization),
    url(path, query) {
      const encoded = encodeQuery(query);
      return `${origin}${path}${encoded ? `?${encoded}` : ""}`;
    },
    /** Every request refuses redirects so traffic can never be bounced to another listener. */
    async request({ method, path, query, body, timeout = timeoutMs, anonymous = false }) {
      const extra = {};
      const init = { method, redirect: "error", signal: AbortSignal.timeout(timeout) };
      if (body !== undefined) {
        init.body = JSON.stringify(body);
        extra["content-type"] = "application/json";
      }
      init.headers = headersFor(extra, anonymous);
      const response = await transport(this.url(path, query), init);
      const text = response.status === 204 || response.status === 401 ? "" : await response.text();
      let json = null;
      if (text !== "") {
        try {
          json = JSON.parse(text);
        } catch {
          json = null;
        }
      }
      const headers = {};
      response.headers?.forEach?.((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      return { status: response.status, json, text, headers };
    },
    /** Opens an SSE stream; returns the raw fetch Response (read body with readEventStream). */
    async open({ path, query, signal }) {
      return transport(this.url(path, query), { method: "GET", redirect: "error", headers: headersFor({ accept: "text/event-stream" }, false), signal });
    },
  };
}

/**
 * Identity of a freshly started host on an allocated port: an unauthenticated
 * request must receive the exact Basic challenge (so this is not some other
 * open listener), and the same request with the fixture-only credentials must
 * succeed (so it is the instance we started with that password). No other
 * request may be sent before this passes.
 */
export function verifyAuthChallenge(client, route) {
  if (!client.hasAuth) throw new Error("auth challenge verification requires fixture credentials");
  return (async () => {
    const anonymous = await client.request({ ...route, anonymous: true });
    if (anonymous.status !== 401 || anonymous.headers["www-authenticate"] !== AUTH_CHALLENGE) {
      throw new Error(`listener did not challenge an unauthenticated request (status ${anonymous.status}); refusing to trust the port`);
    }
    const authorized = await client.request(route);
    if (authorized.status < 200 || authorized.status >= 300) throw new Error(`host rejected the fixture credentials (status ${authorized.status})`);
    return { challenged: true, authorized: true };
  })();
}

/** Opens the event stream with a deadline that holds even if the transport ignores abort. */
export async function openEventStream(client, route, { timeoutMs, signal }) {
  const controller = new AbortController();
  const forward = () => controller.abort();
  signal?.addEventListener("abort", forward, { once: true });
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`event stream did not open within ${timeoutMs}ms`));
    }, timeoutMs);
  });
  try {
    const response = await Promise.race([client.open({ ...route, signal: controller.signal }), deadline]);
    if (response.status !== 200 || !response.body) throw new Error(`event stream refused (status ${response.status})`);
    return { response, abort: () => controller.abort() };
  } catch (error) {
    controller.abort();
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", forward);
  }
}

export function createSSEParser({ maxEventBytes = 1_048_576 } = {}) {
  let buffer = "";
  let data = [];
  let event = "";
  let id = "";
  function line(text) {
    if (text === "") {
      if (data.length === 0) {
        event = "";
        return null;
      }
      const dispatched = { id, event: event || "message", data: data.join("\n") };
      data = [];
      event = "";
      return dispatched;
    }
    if (text.startsWith(":")) return null;
    const colon = text.indexOf(":");
    const field = colon === -1 ? text : text.slice(0, colon);
    let value = colon === -1 ? "" : text.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "data") data.push(value);
    else if (field === "event") event = value;
    else if (field === "id") id = value;
    return null;
  }
  return {
    push(chunk) {
      buffer += chunk;
      const events = [];
      for (;;) {
        const match = /\r\n|\n|\r/.exec(buffer);
        if (!match) break;
        // A trailing lone CR may be the first half of a CRLF split across chunks.
        if (match[0] === "\r" && match.index === buffer.length - 1) break;
        const dispatched = line(buffer.slice(0, match.index));
        buffer = buffer.slice(match.index + match[0].length);
        if (dispatched) events.push(dispatched);
      }
      const pending = buffer.length + data.reduce((sum, part) => sum + part.length, 0);
      if (pending > maxEventBytes) throw new Error(`SSE event exceeds ${maxEventBytes} bytes`);
      return events;
    },
  };
}

/** Reads a WHATWG byte stream as SSE and calls onEvent for each event, in order. */
export async function readEventStream(body, onEvent, options) {
  const parser = createSSEParser(options);
  const decoder = new TextDecoder();
  const reader = body.getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      for (const event of parser.push(decoder.decode(value, { stream: true }))) await onEvent(event);
    }
  } finally {
    reader.releaseLock();
  }
}
