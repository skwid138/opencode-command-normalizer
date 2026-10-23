#!/usr/bin/env node
// Test launcher: creates a disposable HOME / XDG / TMPDIR root, clears
// inherited OpenCode and npm config overrides, runs the given command with
// that environment, then removes only the root it created.
//
// Usage: node test/run-isolated.mjs <command> [args...]
import { spawn } from "node:child_process";
import { constants } from "node:os";
import { dirname, delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildIsolatedEnv, createIsolationRoot, removeIsolationRoot } from "./isolated-env.mjs";

const FORWARDED_SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP"];

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const [command, ...args] = process.argv.slice(2);
if (!command) {
  process.stderr.write("usage: node test/run-isolated.mjs <command> [args...]\n");
  process.exit(2);
}

function runChild(env) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd: repoRoot, env, stdio: "inherit" });
    // One explicit handler per signal so the child receives the original
    // signal regardless of how Node invokes listeners.
    const handlers = FORWARDED_SIGNALS.map((signal) => [signal, () => child.kill(signal)]);
    for (const [signal, handler] of handlers) process.on(signal, handler);
    let settled = false;
    const settle = (code) => {
      if (settled) return;
      settled = true;
      for (const [signal, handler] of handlers) process.off(signal, handler);
      resolve(code);
    };
    child.on("error", (error) => {
      process.stderr.write(`run-isolated: failed to start ${command}: ${error.message}\n`);
      settle(127);
    });
    child.on("exit", (code, signal) => {
      if (code !== null) settle(code);
      else settle(signal ? 128 + (constants.signals[signal] ?? 0) : 1);
    });
  });
}

let exitCode = 1;
let layout;
try {
  layout = await createIsolationRoot();
  const env = buildIsolatedEnv(process.env, layout);
  env.PATH = [join(repoRoot, "node_modules", ".bin"), env.PATH ?? ""].filter(Boolean).join(delimiter);
  exitCode = await runChild(env);
} catch (error) {
  process.stderr.write(`run-isolated: ${error instanceof Error ? error.message : String(error)}\n`);
  exitCode = 1;
} finally {
  if (layout) {
    try {
      await removeIsolationRoot(layout);
    } catch (error) {
      process.stderr.write(`run-isolated: failed to remove ${layout.root}: ${error instanceof Error ? error.message : String(error)}\n`);
      if (exitCode === 0) exitCode = 1;
    }
  }
}
process.exit(exitCode);
