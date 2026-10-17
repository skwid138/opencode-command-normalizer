// OpenCode V1 adapter: the existing `server` plugin function. Behavior is
// unchanged from the single-file implementation; it now composes src/core.ts
// and the shared decision correlator in src/decisions.ts.
import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { Plugin } from "@opencode-ai/plugin";

import { canonicalizeAndAudit, isRecord, parseOptions, stringArray } from "./core.js";
import { createDebugLog, createDecisionCorrelator } from "./decisions.js";

type RuntimeEventEnvelope = { id?: string; type: string; properties: unknown };

type RuntimePermissionAskedProperties = {
  id?: unknown;
  sessionID?: unknown;
  permission?: unknown;
  patterns?: unknown;
  always?: unknown;
  tool?: unknown;
};

type RuntimePermissionRepliedProperties = {
  sessionID?: unknown;
  requestID?: unknown;
  reply?: unknown;
};

export const PermissionCanonicalizerPlugin: Plugin = async (_ctx, options) => {
  const parsed = parseOptions(options);
  const sessionAgents = new Map<string, string>();
  const debug = createDebugLog(parsed.debugLogPath);
  const decisions = createDecisionCorrelator({
    limit: parsed.decisionPendingLimit,
    decisionsLogPath: parsed.decisionsLogPath,
    debug,
  });

  async function rememberPermissionAsked(properties: RuntimePermissionAskedProperties): Promise<void> {
    if (typeof properties.id !== "string") return;
    const tool = isRecord(properties.tool) ? properties.tool : null;
    // Correlate on permission.asked.properties.id, the inner request id. The
    // outer event.id is only the bus envelope id and does not match replies.
    await decisions.asked({
      requestID: properties.id,
      sessionID: typeof properties.sessionID === "string" ? properties.sessionID : "",
      permission: typeof properties.permission === "string" ? properties.permission : "",
      patterns: stringArray(properties.patterns),
      always: stringArray(properties.always),
      callID: typeof tool?.callID === "string" ? tool.callID : null,
    });
  }

  async function rememberPermissionReplied(properties: RuntimePermissionRepliedProperties): Promise<void> {
    if (typeof properties.requestID !== "string") return;
    await decisions.replied({
      sessionID: typeof properties.sessionID === "string" ? properties.sessionID : "",
      requestID: properties.requestID,
      reply: properties.reply,
    });
  }

  if (!parsed.enabled) {
    await debug("permission canonicalizer disabled due to malformed config");
    return {};
  }

  await mkdir(dirname(parsed.auditLogPath), { recursive: true }).catch((error) => debug(`audit directory init failed: ${error}`));
  await mkdir(dirname(parsed.debugLogPath), { recursive: true }).catch(() => undefined);
  await mkdir(dirname(parsed.decisionsLogPath), { recursive: true }).catch((error) => debug(`decisions directory init failed: ${error}`));

  function rememberAgent(input: unknown): void {
    if (typeof input !== "object" || input === null) return;
    const record = input as { sessionID?: unknown; agent?: unknown };
    if (typeof record.sessionID === "string" && typeof record.agent === "string") {
      sessionAgents.set(record.sessionID, record.agent);
    }
  }

  return {
    "chat.params": async (input: unknown) => {
      rememberAgent(input);
    },
    "chat.message": async (input: unknown) => {
      rememberAgent(input);
    },
    "tool.execute.before": async (input: unknown, output: unknown) => {
      const toolInput = input as { tool?: unknown; sessionID?: unknown; callID?: unknown };
      const toolOutput = output as { args?: { command?: unknown } };
      if (toolInput.tool !== "bash" || typeof toolOutput.args?.command !== "string") return;
      const original = toolOutput.args.command;
      const sessionID = typeof toolInput.sessionID === "string" ? toolInput.sessionID : "";
      const callID = typeof toolInput.callID === "string" ? toolInput.callID : "";
      const canonical = await canonicalizeAndAudit(original, parsed.canonicalizeOptions, {
        sessionID,
        callID,
        agent: sessionAgents.get(sessionID) ?? null,
        appendRecord: async (record) => {
          await appendFile(parsed.auditLogPath, `${JSON.stringify(record)}\n`, "utf8");
        },
        debug,
      });
      toolOutput.args.command = canonical;
      await debug(canonical === original ? `pass-through: ${original}` : `rewrite: ${original} -> ${canonical}`);
    },
    event: async (input: unknown) => {
      try {
        if (!isRecord(input) || !isRecord(input.event)) return;
        const event = input.event as RuntimeEventEnvelope;
        if (typeof event.type !== "string") return;
        if (event.type === "permission.asked") {
          if (!isRecord(event.properties)) return;
          await rememberPermissionAsked(event.properties);
          return;
        }
        if (event.type === "permission.replied") {
          if (!isRecord(event.properties)) return;
          await rememberPermissionReplied(event.properties);
        }
      } catch (error) {
        await debug(`permission decision event failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  };
};
