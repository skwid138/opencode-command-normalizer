import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import defaultExport, { PermissionCanonicalizerPlugin } from "./index";

const HOME = "/home/example";

type Hook = (event: Record<string, unknown>) => Promise<void> | void;

/** Controlled AsyncIterable standing in for ctx.event.subscribe(). */
function createEventChannel(behavior: { honorAbort?: boolean } = {}) {
  const honorAbort = behavior.honorAbort ?? true;
  const queue: unknown[] = [];
  let waiter: ((result: IteratorResult<unknown>) => void) | null = null;
  let failer: ((error: unknown) => void) | null = null;
  let ended = false;
  let idleResolvers: Array<() => void> = [];
  const signals: Array<AbortSignal | undefined> = [];

  function notifyIdle() {
    if (waiter && queue.length === 0) {
      const resolvers = idleResolvers;
      idleResolvers = [];
      for (const resolve of resolvers) resolve();
    }
  }

  function finish() {
    ended = true;
    if (waiter) {
      const resolve = waiter;
      waiter = null;
      failer = null;
      resolve({ done: true, value: undefined });
    }
  }

  return {
    signals,
    subscribe(options?: { signal?: AbortSignal }): AsyncIterable<unknown> {
      signals.push(options?.signal);
      if (honorAbort) options?.signal?.addEventListener("abort", finish, { once: true });
      return {
        [Symbol.asyncIterator]() {
          return {
            next(): Promise<IteratorResult<unknown>> {
              if (queue.length > 0) return Promise.resolve({ done: false, value: queue.shift() });
              if (ended) return Promise.resolve({ done: true, value: undefined });
              return new Promise((resolve, reject) => {
                waiter = resolve;
                failer = reject;
                notifyIdle();
              });
            },
            return(): Promise<IteratorResult<unknown>> {
              if (honorAbort) finish();
              return Promise.resolve({ done: true, value: undefined });
            },
          };
        },
      };
    },
    push(...events: unknown[]) {
      for (const event of events) {
        if (waiter) {
          const resolve = waiter;
          waiter = null;
          failer = null;
          resolve({ done: false, value: event });
        } else {
          queue.push(event);
        }
      }
    },
    fail(error: unknown) {
      const reject = failer;
      waiter = null;
      failer = null;
      reject?.(error);
    },
    end: finish,
    /** Resolves once the consumer has processed everything and is waiting again. */
    idle(): Promise<void> {
      return new Promise((resolve) => {
        idleResolvers.push(resolve);
        notifyIdle();
      });
    },
  };
}

async function createFakeHost(
  options: unknown = {},
  behavior: { honorAbort?: boolean; subscribeThrows?: unknown; disposeThrows?: unknown } = {},
) {
  const hooks = new Map<string, Hook>();
  const disposed: string[] = [];
  const channel = createEventChannel({ honorAbort: behavior.honorAbort });
  const ctx = {
    options,
    tool: {
      hook: async (name: string, callback: Hook) => {
        hooks.set(name, callback);
        return {
          dispose: async () => {
            disposed.push(name);
            hooks.delete(name);
            if (behavior.disposeThrows !== undefined) throw behavior.disposeThrows;
          },
        };
      },
    },
    event: {
      subscribe: (opts?: { signal?: AbortSignal }) => {
        if (behavior.subscribeThrows !== undefined) throw behavior.subscribeThrows;
        return channel.subscribe(opts);
      },
    },
  };
  return { ctx, hooks, disposed, channel };
}

async function logPaths() {
  const dir = await mkdtemp(join(tmpdir(), "permission-canon-v2-"));
  return {
    dir,
    auditLogPath: join(dir, "audit.log"),
    debugLogPath: join(dir, "debug.log"),
    decisionsLogPath: join(dir, "decisions.log"),
  };
}

async function readLines(path: string): Promise<Record<string, unknown>[]> {
  try {
    return (await readFile(path, "utf8"))
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return [];
    throw error;
  }
}

function shellEvent(command: unknown, extra: Record<string, unknown> = {}) {
  return {
    tool: "shell",
    sessionID: "ses_v2",
    agent: "aragorn",
    messageID: "msg_v2",
    id: "call_v2",
    input: { command, workdir: "/repo", timeout: 1000 },
    ...extra,
  };
}

describe("dual-host default export", () => {
  it("exposes a stable id, the V1 server function, and a V2 setup function on one object", () => {
    expect(defaultExport.id).toBe("skwid138.command-normalizer");
    expect(defaultExport.server).toBe(PermissionCanonicalizerPlugin);
    expect(typeof defaultExport.setup).toBe("function");
  });
});

describe("V2 setup: tool execute.before", () => {
  it("normalizes shell argv0 in place and audits each node with V2 identity fields", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);

    const event = shellEvent("~/workspace/tools/foo.sh --path ~/kept && pwd");
    const input = event.input;
    await host.hooks.get("execute.before")?.(event);

    expect(event.input).toBe(input);
    expect(input).toEqual({ command: `${HOME}/workspace/tools/foo.sh --path ~/kept && pwd`, workdir: "/repo", timeout: 1000 });
    await expect(readLines(paths.auditLogPath)).resolves.toMatchObject([
      { sessionID: "ses_v2", agent: "aragorn", callID: "call_v2", command_node_text: `${HOME}/workspace/tools/foo.sh --path ~/kept` },
      { sessionID: "ses_v2", agent: "aragorn", callID: "call_v2", command_node_text: "pwd" },
    ]);
    await cleanup?.();
  });

  it("ignores non-shell tools and non-string or missing commands without auditing", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);
    const hook = host.hooks.get("execute.before");

    const events = [
      shellEvent("~/a.sh", { tool: "bash" }),
      shellEvent("~/a.sh", { tool: "read" }),
      shellEvent(42),
      { ...shellEvent("~/a.sh"), input: "~/a.sh" },
      { ...shellEvent("~/a.sh"), input: null },
      { ...shellEvent("~/a.sh"), input: { cmd: "~/a.sh" } },
    ];
    const snapshots = events.map((event) => JSON.stringify(event));
    for (const event of events) await hook?.(event);

    expect(events.map((event) => JSON.stringify(event))).toEqual(snapshots);
    await expect(readLines(paths.auditLogPath)).resolves.toEqual([]);
    await cleanup?.();
  });

  it("never lets a hook failure propagate into the host tool call", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);
    const event = { ...shellEvent("~/workspace/a.sh"), input: Object.freeze({ command: "~/workspace/a.sh" }) };

    await expect(Promise.resolve(host.hooks.get("execute.before")?.(event))).resolves.toBeUndefined();
    expect(event.input).toEqual({ command: "~/workspace/a.sh" });
    await expect(readFile(paths.debugLogPath, "utf8")).resolves.toContain("permission canonicalizer hook failed");
    await cleanup?.();
  });

  it("still rewrites only the command when both audit and debug destinations are unwritable", async () => {
    const paths = await logPaths();
    const blocker = join(paths.dir, "blocker");
    await writeFile(blocker, "a regular file where a directory is expected", "utf8");
    const host = await createFakeHost({
      homedir: HOME,
      auditLogPath: join(blocker, "audit.log"),
      debugLogPath: join(blocker, "debug.log"),
      decisionsLogPath: paths.decisionsLogPath,
    });
    const cleanup = await defaultExport.setup(host.ctx as never);
    const input = { command: "~/workspace/a.sh --flag ~/kept && pwd", workdir: "/repo", timeout: 1000, description: "run a" };
    const event = { tool: "shell", sessionID: "ses_v2", agent: "aragorn", messageID: "msg_v2", id: "call_v2", input };
    const { command: _command, ...otherInputFields } = input;
    const otherBefore = structuredClone(otherInputFields);
    const { input: _input, ...identityBefore } = structuredClone(event);

    await expect(Promise.resolve(host.hooks.get("execute.before")?.(event))).resolves.toBeUndefined();

    expect(event.input).toBe(input);
    expect(input.command).toBe(`${HOME}/workspace/a.sh --flag ~/kept && pwd`);
    const { command: _after, ...otherAfter } = input;
    expect(otherAfter).toEqual(otherBefore);
    const { input: _inputAfter, ...identityAfter } = event;
    expect(identityAfter).toEqual(identityBefore);
    await expect(readFile(blocker, "utf8")).resolves.toBe("a regular file where a directory is expected");
    await cleanup?.();
  });
});

describe("V2 setup: options", () => {
  it("applies the existing roots, expandBraceHome, and homedir options", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, roots: ["~/workspace"], expandBraceHome: true, ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);
    const hook = host.hooks.get("execute.before");

    const inside = shellEvent("${HOME}/workspace/a.sh");
    const outside = shellEvent("~/other/b.sh");
    await hook?.(inside);
    await hook?.(outside);

    expect((inside.input as { command: string }).command).toBe(`${HOME}/workspace/a.sh`);
    expect((outside.input as { command: string }).command).toBe("~/other/b.sh");
    await cleanup?.();
  });

  it("keeps the home form with explicit empty roots", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, roots: [], ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);
    const event = shellEvent("$HOME/workspace/a.sh");

    await host.hooks.get("execute.before")?.(event);

    expect((event.input as { command: string }).command).toBe("$HOME/workspace/a.sh");
    await cleanup?.();
  });

  it("returns the whole original bytes when a later node bails after an earlier node was rewritten", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);
    const command = "~/workspace/a.sh && FOO=1 ~/workspace/b.sh";
    const event = shellEvent(command);

    await host.hooks.get("execute.before")?.(event);

    expect((event.input as { command: string }).command).toBe(command);
    await cleanup?.();
  });

  it("registers nothing and subscribes to nothing when options are malformed", async () => {
    const invalidOptions: unknown[] = [
      { roots: "~/workspace" },
      { roots: [1] },
      { roots: ["relative/dir"] },
      { expandBraceHome: "yes" },
      null,
      [],
      "string-options",
    ];
    for (const options of invalidOptions) {
      const host = await createFakeHost(options);
      const cleanup = await defaultExport.setup(host.ctx as never);
      expect(host.hooks.size, JSON.stringify(options)).toBe(0);
      expect(host.channel.signals, JSON.stringify(options)).toEqual([]);
      await cleanup?.();
    }
    const defaults = (await import("./index")).resolveDefaultLogPaths(process.env);
    await expect(readFile(defaults.debug, "utf8")).resolves.toContain("permission canonicalizer disabled due to malformed config");
  });
});

function asked(data: Record<string, unknown>, envelope: Record<string, unknown> = {}) {
  return { id: "evt_outer_asked", created: 1, type: "permission.asked", data, ...envelope };
}

function replied(data: Record<string, unknown>) {
  return { id: "evt_outer_replied", created: 2, type: "permission.replied", data };
}

describe("V2 setup: permission decision capture", () => {
  it("maps asked/replied events into the existing decision record schema", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);

    host.channel.push(
      asked({
        id: "per_1",
        sessionID: "ses_v2",
        action: "shell",
        resources: ["/home/example/workspace/a.sh"],
        save: ["/home/example/workspace/a.sh *"],
        source: { type: "tool", messageID: "msg_1", id: "call_1" },
        message: "Run a.sh?",
      }),
      replied({ sessionID: "ses_v2", requestID: "per_1", reply: "always" }),
    );
    await host.channel.idle();

    const records = await readLines(paths.decisionsLogPath);
    expect(records).toHaveLength(1);
    expect(Object.keys(records[0] ?? {})).toEqual([
      "ts",
      "sessionID",
      "callID",
      "requestID",
      "permission",
      "patterns",
      "always",
      "reply",
      "askedTs",
    ]);
    expect(records[0]).toMatchObject({
      sessionID: "ses_v2",
      callID: "call_1",
      requestID: "per_1",
      permission: "shell",
      patterns: ["/home/example/workspace/a.sh"],
      always: ["/home/example/workspace/a.sh *"],
      reply: "always",
    });
    expect(String(records[0]?.askedTs) <= String(records[0]?.ts)).toBe(true);
    await cleanup?.();
  });
});

describe("V2 setup: decision correlation edge cases", () => {
  it("joins by session, never by the outer envelope id, and keeps duplicate request ids per session", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);

    host.channel.push(
      asked({ id: "per_dup", sessionID: "ses_a", action: "shell", resources: [], source: { type: "tool", messageID: "m", id: "call_a" } }, { id: "per_dup_outer" }),
      asked({ id: "per_dup", sessionID: "ses_b", action: "shell", resources: [], source: { type: "tool", messageID: "m", id: "call_b" } }),
      replied({ sessionID: "ses_a", requestID: "per_dup_outer", reply: "once" }),
      replied({ sessionID: "ses_b", requestID: "per_dup", reply: "reject" }),
      replied({ sessionID: "ses_a", requestID: "per_dup", reply: "once" }),
      replied({ sessionID: "ses_a", requestID: "per_dup", reply: "once" }),
    );
    await host.channel.idle();

    await expect(readLines(paths.decisionsLogPath)).resolves.toMatchObject([
      { sessionID: "ses_b", requestID: "per_dup", callID: "call_b", reply: "reject" },
      { sessionID: "ses_a", requestID: "per_dup", callID: "call_a", reply: "once" },
    ]);
    await expect(readFile(paths.debugLogPath, "utf8")).resolves.toContain("permission replied without pending ask: requestID=per_dup_outer");
    await cleanup?.();
  });

  it("records a null callID for non-tool or missing sources and an empty always list when save is absent", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);

    host.channel.push(
      asked({ id: "per_nosource", sessionID: "ses_v2", action: "read", resources: ["/x"] }),
      asked({ id: "per_othersource", sessionID: "ses_v2", action: "read", resources: ["/y"], source: { type: "session", id: "not_a_call" } }),
      replied({ sessionID: "ses_v2", requestID: "per_nosource", reply: "once" }),
      replied({ sessionID: "ses_v2", requestID: "per_othersource", reply: "once" }),
    );
    await host.channel.idle();

    await expect(readLines(paths.decisionsLogPath)).resolves.toMatchObject([
      { requestID: "per_nosource", callID: null, always: [] },
      { requestID: "per_othersource", callID: null, always: [] },
    ]);
    await expect(readFile(paths.debugLogPath, "utf8")).resolves.toContain("permission asked missing callID: requestID=per_nosource");
    await cleanup?.();
  });

  it("survives malformed events and unexpected replies and keeps processing later events", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);

    host.channel.push(
      null,
      "permission.asked",
      { type: 42, data: {} },
      { type: "permission.asked" },
      { type: "permission.asked", data: "nope" },
      asked({ id: 7, sessionID: "ses_v2" }),
      asked({ id: "per_bad_fields", sessionID: 9, action: ["x"], resources: "nope", save: [1, "keep"] }),
      replied({ requestID: 7, reply: "once" }),
      { type: "session.idle", data: { sessionID: "ses_v2" } },
      replied({ requestID: "per_bad_fields", reply: { surprise: true } }),
      asked({ id: "per_after", sessionID: "ses_v2", action: "shell", resources: [] }),
      replied({ sessionID: "ses_v2", requestID: "per_after", reply: "once" }),
    );
    await host.channel.idle();

    await expect(readLines(paths.decisionsLogPath)).resolves.toMatchObject([
      { requestID: "per_bad_fields", sessionID: "", permission: "", patterns: [], always: ["keep"], reply: { surprise: true } },
      { requestID: "per_after", reply: "once" },
    ]);
    await expect(readFile(paths.debugLogPath, "utf8")).resolves.toContain("permission replied with unexpected reply: requestID=per_bad_fields");
    await cleanup?.();
  });

  it("logs a decision append failure and still processes the following event", async () => {
    const paths = await logPaths();
    const blocked = join(paths.dir, "not-a-directory");
    await (await import("node:fs/promises")).writeFile(blocked, "x", "utf8");
    const decisionsLogPath = join(blocked, "decisions.log");
    const host = await createFakeHost({ homedir: HOME, ...paths, decisionsLogPath });
    const cleanup = await defaultExport.setup(host.ctx as never);

    host.channel.push(
      asked({ id: "per_fail", sessionID: "ses_v2", action: "shell", resources: [] }),
      replied({ sessionID: "ses_v2", requestID: "per_fail", reply: "once" }),
    );
    await host.channel.idle();
    await expect(readFile(paths.debugLogPath, "utf8")).resolves.toContain("permission decision event failed: ENOTDIR");

    const event = shellEvent("~/workspace/a.sh");
    await host.hooks.get("execute.before")?.(event);
    expect((event.input as { command: string }).command).toBe(`${HOME}/workspace/a.sh`);

    host.channel.push(asked({ id: "per_next", sessionID: "ses_v2", action: "shell", resources: [] }));
    await host.channel.idle();
    await expect(readFile(paths.debugLogPath, "utf8")).resolves.toContain("permission asked cached: requestID=per_next");
    await cleanup?.();
  });

  it("joins the oldest pending ask at the default 1000 cap and evicts it at 1001", async () => {
    async function askMany(count: number) {
      const paths = await logPaths();
      const host = await createFakeHost({ homedir: HOME, ...paths });
      const cleanup = await defaultExport.setup(host.ctx as never);
      for (let index = 0; index < count; index += 1) {
        host.channel.push(asked({ id: `per_${index}`, sessionID: "ses_cap", action: "shell", resources: [], source: { type: "tool", messageID: "m", id: `call_${index}` } }));
      }
      await host.channel.idle();
      return { host, paths, cleanup };
    }
    const reply = (requestID: string) => replied({ sessionID: "ses_cap", requestID, reply: "once" });

    const atCap = await askMany(1000);
    atCap.host.channel.push(reply("per_0"));
    await atCap.host.channel.idle();
    await expect(readLines(atCap.paths.decisionsLogPath)).resolves.toMatchObject([{ requestID: "per_0", callID: "call_0" }]);
    await atCap.cleanup?.();

    const overCap = await askMany(1001);
    overCap.host.channel.push(reply("per_0"), reply("per_1"), reply("per_1000"));
    await overCap.host.channel.idle();
    await expect(readLines(overCap.paths.decisionsLogPath)).resolves.toMatchObject([
      { requestID: "per_1", callID: "call_1" },
      { requestID: "per_1000", callID: "call_1000" },
    ]);
    await overCap.cleanup?.();
  });
});

function trackUnhandledRejections() {
  const seen: unknown[] = [];
  const listener = (reason: unknown) => seen.push(reason);
  process.on("unhandledRejection", listener);
  return {
    seen,
    async stop() {
      await new Promise((resolve) => setTimeout(resolve, 10));
      process.off("unhandledRejection", listener);
    },
  };
}

describe("V2 setup: lifecycle", () => {
  it("resolves setup without waiting on the event stream and subscribes exactly once", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });

    const cleanup = await defaultExport.setup(host.ctx as never);
    await host.channel.idle();

    expect(host.channel.signals).toHaveLength(1);
    expect(host.channel.signals[0]).toBeInstanceOf(AbortSignal);
    expect(host.channel.signals[0]?.aborted).toBe(false);
    await cleanup?.();
  });

  it("keeps normalizing and leaves no unhandled rejection when subscribe throws at startup", async () => {
    const tracker = trackUnhandledRejections();
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths }, { subscribeThrows: new Error("bus not ready") });

    const cleanup = await defaultExport.setup(host.ctx as never);
    const event = shellEvent("~/workspace/a.sh");
    await host.hooks.get("execute.before")?.(event);

    expect((event.input as { command: string }).command).toBe(`${HOME}/workspace/a.sh`);
    await vi.waitFor(async () => {
      await expect(readFile(paths.debugLogPath, "utf8")).resolves.toContain("permission event subscription failed: bus not ready");
    });
    await cleanup?.();
    await tracker.stop();
    expect(tracker.seen).toEqual([]);
  });

  it("logs a stream failure without an unhandled rejection and keeps the hook working", async () => {
    const tracker = trackUnhandledRejections();
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);
    await host.channel.idle();

    host.channel.fail(new Error("stream reset"));
    await vi.waitFor(async () => {
      await expect(readFile(paths.debugLogPath, "utf8")).resolves.toContain("permission event subscription failed: stream reset");
    });
    const event = shellEvent("~/workspace/a.sh");
    await host.hooks.get("execute.before")?.(event);

    expect((event.input as { command: string }).command).toBe(`${HOME}/workspace/a.sh`);
    await cleanup?.();
    await tracker.stop();
    expect(tracker.seen).toEqual([]);
  });

  it("cleanup aborts the subscription signal and disposes the hook registration", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });
    const cleanup = await defaultExport.setup(host.ctx as never);

    await cleanup?.();

    expect(host.channel.signals[0]?.aborted).toBe(true);
    expect(host.disposed).toEqual(["execute.before"]);
  });

  it("ignores later events and hook calls after cleanup, even if the host iterator ignores abort", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths }, { honorAbort: false });
    const cleanup = await defaultExport.setup(host.ctx as never);
    const hook = host.hooks.get("execute.before");

    host.channel.push(asked({ id: "per_before", sessionID: "ses_v2", action: "shell", resources: [] }));
    await host.channel.idle();
    await cleanup?.();

    host.channel.push(
      replied({ sessionID: "ses_v2", requestID: "per_before", reply: "once" }),
      asked({ id: "per_after", sessionID: "ses_v2", action: "shell", resources: [] }),
      replied({ sessionID: "ses_v2", requestID: "per_after", reply: "once" }),
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    const late = shellEvent("~/workspace/a.sh");
    await hook?.(late);

    await expect(readLines(paths.decisionsLogPath)).resolves.toEqual([]);
    await expect(readLines(paths.auditLogPath)).resolves.toEqual([]);
    expect((late.input as { command: string }).command).toBe("~/workspace/a.sh");
  });

  it("cleanup is idempotent and logs, rather than throws, a registration dispose failure", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths }, { disposeThrows: new Error("already disposed") });
    const cleanup = await defaultExport.setup(host.ctx as never);

    await expect(cleanup?.()).resolves.toBeUndefined();
    await expect(cleanup?.()).resolves.toBeUndefined();

    expect(host.disposed).toEqual(["execute.before"]);
    await expect(readFile(paths.debugLogPath, "utf8")).resolves.toContain("permission canonicalizer hook dispose failed: already disposed");
  });

  it("propagates a hook registration failure from setup without starting a subscription", async () => {
    const paths = await logPaths();
    const host = await createFakeHost({ homedir: HOME, ...paths });
    const ctx = { ...host.ctx, tool: { hook: async () => Promise.reject(new Error("registry closed")) } };

    await expect(defaultExport.setup(ctx as never)).rejects.toThrow("registry closed");
    expect(host.channel.signals).toEqual([]);
  });
});
