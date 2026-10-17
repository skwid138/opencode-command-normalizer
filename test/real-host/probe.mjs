#!/usr/bin/env node
// Single-operation preflight probe, run under the candidate sandbox (and once
// unsandboxed as the control) during the runtime gate. Prints one JSON line
// { completed: true, op, outcome: "allowed" | "denied" | "error", code?, status?, body? }
// and exits 0. The runtime treats no result, unparseable output, a nonzero
// exit, or a timeout as infrastructure failure, never as a denial.
// Self-contained: node: builtins only.
//
//   node probe.mjs read <path>
//   node probe.mjs write <path>
//   node probe.mjs http-get <loopback url>
//   node probe.mjs connect <host:port | [v6]:port>
//   node probe.mjs connect-unix <socket path>
//
// Unit tests exercise read/write only; the network operations open sockets and
// are not executed before the runtime gate.
import { readFile, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { pathToFileURL } from "node:url";

const TIMEOUT_MS = 2000;
const MAX_BODY = 4096;
const DENIAL_CODES = new Set(["EPERM", "EACCES"]);

// A completed probe reports what happened to the one attempted operation:
// allowed, denied (EPERM/EACCES), or error (any other errno, refused, timeout).
const classify = (op, error) => {
  const code = error?.code ?? error?.cause?.code ?? error?.name ?? "unknown";
  return { completed: true, op, outcome: DENIAL_CODES.has(code) ? "denied" : "error", code };
};

function connectOnce(op, options) {
  return new Promise((resolve) => {
    const socket = connect(options);
    const done = (result) => {
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(TIMEOUT_MS, () => done({ completed: true, op, outcome: "error", code: "ETIMEDOUT" }));
    socket.once("connect", () => done({ completed: true, op, outcome: "allowed" }));
    socket.once("error", (error) => done(classify(op, error)));
  });
}

export async function runProbe(op, target) {
  try {
    switch (op) {
      case "read":
        await readFile(target);
        return { completed: true, op, outcome: "allowed" };
      case "write":
        await writeFile(target, "real-host-probe\n");
        return { completed: true, op, outcome: "allowed" };
      case "http-get": {
        const response = await fetch(target, { redirect: "error", signal: AbortSignal.timeout(TIMEOUT_MS) });
        return { completed: true, op, outcome: "allowed", status: response.status, body: (await response.text()).slice(0, MAX_BODY) };
      }
      case "connect": {
        const match = /^\[?([^\]]+)\]?:(\d+)$/.exec(target);
        if (!match) return { completed: true, op, outcome: "error", code: "bad target" };
        return await connectOnce(op, { host: match[1], port: Number(match[2]) });
      }
      case "connect-unix":
        return await connectOnce(op, { path: target });
      default:
        return { completed: true, op, outcome: "error", code: "unknown probe operation" };
    }
  } catch (error) {
    return classify(op, error);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = await runProbe(process.argv[2], process.argv[3]);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
