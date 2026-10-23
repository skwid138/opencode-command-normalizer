// Host-neutral debug logging and permission asked/replied correlation shared by
// the V1 and V2 adapters. Adapters normalize host event fields into
// PermissionAsk / PermissionReplyInput; this module owns the bounded FIFO of
// pending asks and the decisions.log record shape.
import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

import { pendingKey, sanitizeReply, type DecisionRecord } from "./core.js";

export type DebugLog = (message: string) => Promise<void>;

export type PermissionAsk = {
  requestID: string;
  sessionID: string;
  permission: string;
  patterns: string[];
  always: string[];
  callID: string | null;
};

export type PermissionReplyInput = {
  sessionID: string;
  requestID: string;
  reply: unknown;
};

export type DecisionCorrelator = {
  asked: (ask: PermissionAsk) => Promise<void>;
  /** Appends a decision record; rejects on append failure and keeps the pending ask. */
  replied: (reply: PermissionReplyInput) => Promise<void>;
  clear: () => void;
};

type PendingPermission = PermissionAsk & { askedTs: string };

export function createDebugLog(path: string): DebugLog {
  return async (message) => {
    try {
      await mkdir(dirname(path), { recursive: true });
      await appendFile(path, `${new Date().toISOString()} ${message}\n`, "utf8");
    } catch {
      // Debug logging must never affect command execution.
    }
  };
}

export function createDecisionCorrelator(options: {
  limit: number;
  decisionsLogPath: string;
  debug: DebugLog;
}): DecisionCorrelator {
  const { limit, decisionsLogPath, debug } = options;
  const pending = new Map<string, PendingPermission>();

  async function asked(ask: PermissionAsk): Promise<void> {
    const askedTs = new Date().toISOString();
    // Correlate on the inner permission request id, scoped by session. Host
    // bus envelope ids never match replies.
    pending.set(pendingKey(ask.sessionID, ask.requestID), { ...ask, askedTs });
    await debug(`permission asked cached: requestID=${ask.requestID} callID=${ask.callID ?? "null"}`);
    if (ask.callID === null) {
      await debug(`permission asked missing callID: requestID=${ask.requestID}`);
    }
    while (pending.size > limit) {
      const oldestKey = pending.keys().next().value;
      if (typeof oldestKey !== "string") return;
      const evicted = pending.get(oldestKey);
      pending.delete(oldestKey);
      await debug(`permission asked evicted: requestID=${evicted?.requestID ?? "unknown"} askedTs=${evicted?.askedTs ?? "unknown"}`);
    }
  }

  async function replied(input: PermissionReplyInput): Promise<void> {
    const key = pendingKey(input.sessionID, input.requestID);
    const match = pending.get(key);
    if (!match) {
      await debug(`permission replied without pending ask: requestID=${input.requestID}`);
      return;
    }
    const sanitizedReply = sanitizeReply(input.reply);
    if (input.reply !== "once" && input.reply !== "always" && input.reply !== "reject") {
      await debug(`permission replied with unexpected reply: requestID=${input.requestID} reply=${JSON.stringify(sanitizedReply)}`);
    }
    const record: DecisionRecord = {
      ts: new Date().toISOString(),
      sessionID: match.sessionID,
      callID: match.callID,
      requestID: input.requestID,
      permission: match.permission,
      patterns: match.patterns,
      always: match.always,
      reply: sanitizedReply,
      askedTs: match.askedTs,
    };
    await appendFile(decisionsLogPath, `${JSON.stringify(record)}\n`, "utf8");
    pending.delete(key);
  }

  return { asked, replied, clear: () => pending.clear() };
}
