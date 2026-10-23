// OpenCode V2 adapter: `setup(ctx)` for the V2 plugin host.
//
// Host API types are declared structurally here instead of importing
// `@opencode/plugin`, so the emitted declarations and runtime graph never pull
// in the V2 SDK for V1 consumers. src/v2.test-d.ts checks at type level that
// the real `@opencode/plugin@2.0.28` Context and Plugin contracts are
// assignable to these shapes.
import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

import { canonicalizeAndAudit, isRecord, parseOptions, stringArray } from "./core.js";
import { createDebugLog, createDecisionCorrelator } from "./decisions.js";

/** The subset of the V2 `tool` `execute.before` hook event this adapter reads. */
export type V2ToolExecuteBeforeEvent = {
  tool: string;
  readonly sessionID: string;
  readonly agent: string;
  readonly id: string;
  input: unknown;
};

export type V2Registration = {
  readonly dispose: () => Promise<void>;
};

/** The subset of the V2 plugin context this adapter uses. */
export type V2SetupContext = {
  readonly options: unknown;
  readonly tool: {
    readonly hook: (
      name: "execute.before",
      callback: (event: V2ToolExecuteBeforeEvent) => Promise<void> | void,
    ) => Promise<V2Registration>;
  };
  readonly event: {
    readonly subscribe: (options?: { readonly signal?: AbortSignal }) => AsyncIterable<unknown>;
  };
};

export type V2Cleanup = () => Promise<void>;

/** V2 built-in shell tool name (packages/core/src/tool/plugin/shell.ts at v2.0.28). */
const SHELL_TOOL = "shell";

export async function setup(ctx: V2SetupContext): Promise<V2Cleanup | undefined> {
  const parsed = parseOptions(ctx.options);
  const debug = createDebugLog(parsed.debugLogPath);
  if (!parsed.enabled) {
    await debug("permission canonicalizer disabled due to malformed config");
    return undefined;
  }

  await mkdir(dirname(parsed.auditLogPath), { recursive: true }).catch((error) => debug(`audit directory init failed: ${error}`));
  await mkdir(dirname(parsed.debugLogPath), { recursive: true }).catch(() => undefined);
  await mkdir(dirname(parsed.decisionsLogPath), { recursive: true }).catch((error) => debug(`decisions directory init failed: ${error}`));

  let active = true;
  const decisions = createDecisionCorrelator({
    limit: parsed.decisionPendingLimit,
    decisionsLogPath: parsed.decisionsLogPath,
    debug,
  });

  const registration = await ctx.tool.hook("execute.before", async (event) => {
    try {
      if (!active || event.tool !== SHELL_TOOL) return;
      const input = event.input;
      if (!isRecord(input) || typeof input.command !== "string") return;
      const original = input.command;
      const canonical = await canonicalizeAndAudit(original, parsed.canonicalizeOptions, {
        sessionID: typeof event.sessionID === "string" ? event.sessionID : "",
        callID: typeof event.id === "string" ? event.id : "",
        agent: typeof event.agent === "string" ? event.agent : null,
        appendRecord: async (record) => {
          await appendFile(parsed.auditLogPath, `${JSON.stringify(record)}\n`, "utf8");
        },
        debug,
      });
      // Mutate only `command`, and only when it changed.
      if (canonical !== original) input.command = canonical;
      await debug(canonical === original ? `pass-through: ${original}` : `rewrite: ${original} -> ${canonical}`);
    } catch (error) {
      // Normalization is best effort; never fail or alter the host tool call.
      await debug(`permission canonicalizer hook failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  // V2 permission events: asked `data.id` / replied `data.requestID`, joined by
  // session. Best-effort observation of interactive asks only; it is not a
  // stream of automatic allow/deny outcomes.
  async function handleEvent(event: unknown): Promise<void> {
    if (!isRecord(event) || typeof event.type !== "string" || !isRecord(event.data)) return;
    const data = event.data;
    if (event.type === "permission.asked") {
      if (typeof data.id !== "string") return;
      const source = isRecord(data.source) ? data.source : null;
      await decisions.asked({
        requestID: data.id,
        sessionID: typeof data.sessionID === "string" ? data.sessionID : "",
        permission: typeof data.action === "string" ? data.action : "",
        patterns: stringArray(data.resources),
        always: stringArray(data.save ?? []),
        callID: source?.type === "tool" && typeof source.id === "string" ? source.id : null,
      });
      return;
    }
    if (event.type === "permission.replied") {
      if (typeof data.requestID !== "string") return;
      await decisions.replied({
        sessionID: typeof data.sessionID === "string" ? data.sessionID : "",
        requestID: data.requestID,
        reply: data.reply,
      });
    }
  }

  const controller = new AbortController();
  // Consumed in the background so setup never waits on the event stream. Every
  // failure is caught here; this promise never rejects.
  void (async () => {
    try {
      for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
        if (!active) break;
        try {
          await handleEvent(event);
        } catch (error) {
          await debug(`permission decision event failed: ${errorMessage(error)}`);
        }
      }
    } catch (error) {
      if (active) await debug(`permission event subscription failed: ${errorMessage(error)}`);
    }
  })();

  return async () => {
    if (!active) return;
    active = false;
    controller.abort();
    // Releases pending asks for memory only. Once `active` is false no later
    // event is processed, so this is not observable through the public API and
    // has no dedicated test.
    decisions.clear();
    try {
      await registration.dispose();
    } catch (error) {
      await debug(`permission canonicalizer hook dispose failed: ${errorMessage(error)}`);
    }
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
