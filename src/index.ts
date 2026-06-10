import { appendFile, mkdir } from "node:fs/promises";
import { homedir as osHomedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import type { Plugin } from "@opencode-ai/plugin";

export type CanonicalizeOptions = {
  roots?: string[];
  expandBraceHome?: boolean;
  homedir?: string;
};

type RuntimeOptions = CanonicalizeOptions & {
  auditLogPath?: string;
  debugLogPath?: string;
  decisionsLogPath?: string;
  __decisionPendingLimit?: number;
};

export type AuditRecord = {
  ts: string;
  sessionID: string;
  agent: string | null;
  callID: string;
  command_node_text: string;
};

export type AuditContext = {
  sessionID: string;
  agent: string | null;
  callID: string;
  appendRecord: (record: AuditRecord) => Promise<void>;
  debug: (message: string) => Promise<void>;
};

export type DecisionRecord = {
  ts: string;
  sessionID: string;
  callID: string | null;
  requestID: string;
  permission: string;
  patterns: string[];
  always: string[];
  reply: unknown;
  askedTs: string;
};

type PendingPermission = {
  callID: string | null;
  requestID: string;
  sessionID: string;
  permission: string;
  patterns: string[];
  always: string[];
  askedTs: string;
};

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

const DEFAULT_PENDING_PERMISSION_LIMIT = 1000;

type Segment = {
  text: string;
  start: number;
  end: number;
};

export function resolveDefaultLogPaths(
  env: Record<string, string | undefined>,
  homedir = osHomedir(),
): { audit: string; debug: string; decisions: string } {
  const xdg = env.XDG_DATA_HOME;
  const base = xdg && isAbsolute(xdg) ? xdg : join(homedir, ".local", "share");
  const dir = join(base, "opencode", "permission-audit-plugin");
  return { audit: join(dir, "audit.log"), debug: join(dir, "debug.log"), decisions: join(dir, "decisions.log") };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string") : [];
}

// opencode session and request ids never contain NUL, so the delimiter is unambiguous.
function pendingKey(sessionID: unknown, requestID: string): string {
  return `${typeof sessionID === "string" ? sessionID : ""}\u0000${requestID}`;
}

function sanitizeReply(reply: unknown): unknown {
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(reply);
  } catch {
    try {
      return String(reply);
    } catch {
      return "[unserializable reply]";
    }
  }
  if (serialized === undefined) return null;
  return reply;
}

function hasUnbalancedQuotes(command: string): boolean {
  let quote: "'" | '"' | null = null;
  let escaped = false;
  for (const char of command) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote === '"' && char === "\\") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (char === quote) quote = null;
      continue;
    }
    if (char === "'" || char === '"') quote = char;
  }
  return quote !== null || escaped;
}

function hasGlobalBailShape(command: string): boolean {
  return (
    hasUnbalancedQuotes(command) ||
    command.includes("<<") ||
    command.includes("$((") ||
    command.includes("$(") ||
    command.includes("`") ||
    command.includes("<(") ||
    command.includes(">(")
  );
}

function separatorLength(command: string, index: number): number {
  const two = command.slice(index, index + 2);
  if (two === "&&" || two === "||" || two === "|&") return 2;
  const one = command[index];
  if (one === "|" || one === ";" || one === "&" || one === "\n") return 1;
  return 0;
}

function commandSegments(command: string): Segment[] | null {
  const segments: Segment[] = [];
  let quote: "'" | '"' | null = null;
  let escaped = false;
  let start = 0;
  for (let index = 0; index < command.length; index += 1) {
    const char = command[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote === '"' && char === "\\") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (char === quote) quote = null;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    const length = separatorLength(command, index);
    if (length > 0) {
      segments.push({ text: command.slice(start, index), start, end: index });
      index += length - 1;
      start = index + 1;
    }
  }
  if (quote !== null || escaped) return null;
  segments.push({ text: command.slice(start), start, end: command.length });
  return segments;
}

export function splitCommandNodes(command: string): string[] {
  return (commandSegments(command) ?? [{ text: command, start: 0, end: command.length }])
    .map((segment) => segment.text.trim())
    .filter(Boolean);
}

function expandHomeForm(argv0: string, home: string, expandBraceHome: boolean): string | null {
  if (argv0 === "~") return home;
  if (argv0.startsWith("~/")) return `${home}${argv0.slice(1)}`;
  if (argv0 === "$HOME") return home;
  if (argv0.startsWith("$HOME/")) return `${home}${argv0.slice("$HOME".length)}`;
  if (expandBraceHome && argv0 === "${HOME}") return home;
  if (expandBraceHome && argv0.startsWith("${HOME}/")) return `${home}${argv0.slice("${HOME}".length)}`;
  return null;
}

function normalizeRoot(root: string, home: string, expandBraceHome: boolean): string | null {
  const expanded = expandHomeForm(root, home, expandBraceHome) ?? root;
  if (!expanded.startsWith("/") || expanded.split("/").includes("..")) return null;
  return expanded.replace(/\/+$/, "");
}

function isUnderRoot(path: string, root: string): boolean {
  return path === root || path.startsWith(`${root}/`);
}

function rewriteSegment(segment: string, options: Required<CanonicalizeOptions> & { normalizedRoots: string[] | null }): string | null {
  const leading = segment.match(/^\s*/)?.[0] ?? "";
  const rest = segment.slice(leading.length);
  if (!rest) return segment;
  if (rest.startsWith("(") || rest.startsWith("{")) return null;
  if (rest.startsWith("'") || rest.startsWith('"')) return null;
  if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(rest)) return null;

  const argv0Match = rest.match(/^\S+/);
  if (!argv0Match) return segment;
  const argv0 = argv0Match[0];
  if (argv0.includes("'") || argv0.includes('"')) return null;
  if (options.normalizedRoots && argv0.includes("..")) return null;

  const expanded = expandHomeForm(argv0, options.homedir, options.expandBraceHome);
  if (!expanded) return segment;
  if (options.normalizedRoots && !options.normalizedRoots.some((root) => isUnderRoot(expanded, root))) {
    return segment;
  }
  return `${leading}${expanded}${rest.slice(argv0.length)}`;
}

export function canonicalize(command: string, opts: CanonicalizeOptions = {}): string {
  if (hasGlobalBailShape(command)) return command;

  const home = opts.homedir ?? osHomedir();
  const expandBraceHome = opts.expandBraceHome ?? false;
  const normalizedRoots = opts.roots
    ? opts.roots.map((root) => normalizeRoot(root, home, expandBraceHome))
    : null;
  if (normalizedRoots?.some((root) => root === null)) return command;

  const segments = commandSegments(command);
  if (!segments) return command;

  const settings = {
    homedir: home,
    expandBraceHome,
    roots: opts.roots ?? [],
    normalizedRoots: normalizedRoots as string[] | null,
  };
  let rewritten = "";
  let cursor = 0;
  for (const segment of segments) {
    const replacement = rewriteSegment(segment.text, settings);
    if (replacement === null) return command;
    rewritten += command.slice(cursor, segment.start) + replacement;
    cursor = segment.end;
  }
  rewritten += command.slice(cursor);
  return rewritten;
}

export async function canonicalizeAndAudit(
  command: string,
  opts: CanonicalizeOptions,
  context: AuditContext,
): Promise<string> {
  const canonical = canonicalize(command, opts);
  const auditNodes =
    canonical === command && hasGlobalBailShape(command) ? [command] : splitCommandNodes(canonical);
  const records = auditNodes.map((node) => ({
    ts: new Date().toISOString(),
    sessionID: context.sessionID,
    agent: context.agent,
    callID: context.callID,
    // Keep the exact node text the plugin saw. The Python join intentionally
    // does not strip trailing redirections from this field because opencode's
    // AST-to-permission-pattern behavior is not specified tightly enough to do
    // that without risking a wrong-agent attribution.
    command_node_text: node,
  }));

  for (const record of records) {
    try {
      await context.appendRecord(record);
    } catch (error) {
      await context.debug(`permission audit append failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return canonical;
}

function parseOptions(options: unknown): {
  enabled: boolean;
  canonicalizeOptions: CanonicalizeOptions;
  auditLogPath: string;
  debugLogPath: string;
  decisionsLogPath: string;
  decisionPendingLimit: number;
} {
  const defaults = resolveDefaultLogPaths(process.env);
  if (options === undefined) {
    return {
      enabled: true,
      canonicalizeOptions: {},
      auditLogPath: defaults.audit,
      debugLogPath: defaults.debug,
      decisionsLogPath: defaults.decisions,
      decisionPendingLimit: DEFAULT_PENDING_PERMISSION_LIMIT,
    };
  }
  if (typeof options !== "object" || options === null || Array.isArray(options)) {
    return {
      enabled: false,
      canonicalizeOptions: {},
      auditLogPath: defaults.audit,
      debugLogPath: defaults.debug,
      decisionsLogPath: defaults.decisions,
      decisionPendingLimit: DEFAULT_PENDING_PERMISSION_LIMIT,
    };
  }
  const raw = options as RuntimeOptions;
  if (raw.roots !== undefined && (!Array.isArray(raw.roots) || !raw.roots.every((root) => typeof root === "string"))) {
    return {
      enabled: false,
      canonicalizeOptions: {},
      auditLogPath: defaults.audit,
      debugLogPath: defaults.debug,
      decisionsLogPath: defaults.decisions,
      decisionPendingLimit: DEFAULT_PENDING_PERMISSION_LIMIT,
    };
  }
  if (raw.expandBraceHome !== undefined && typeof raw.expandBraceHome !== "boolean") {
    return {
      enabled: false,
      canonicalizeOptions: {},
      auditLogPath: defaults.audit,
      debugLogPath: defaults.debug,
      decisionsLogPath: defaults.decisions,
      decisionPendingLimit: DEFAULT_PENDING_PERMISSION_LIMIT,
    };
  }
  const home = typeof raw.homedir === "string" ? raw.homedir : osHomedir();
  const expandBraceHome = raw.expandBraceHome ?? false;
  if (raw.roots?.some((root) => normalizeRoot(root, home, expandBraceHome) === null)) {
    return {
      enabled: false,
      canonicalizeOptions: {},
      auditLogPath: defaults.audit,
      debugLogPath: defaults.debug,
      decisionsLogPath: defaults.decisions,
      decisionPendingLimit: DEFAULT_PENDING_PERMISSION_LIMIT,
    };
  }
  const pendingLimit =
    typeof raw.__decisionPendingLimit === "number" && Number.isInteger(raw.__decisionPendingLimit) && raw.__decisionPendingLimit > 0
      ? raw.__decisionPendingLimit
      : DEFAULT_PENDING_PERMISSION_LIMIT;
  return {
    enabled: true,
    canonicalizeOptions: {
      roots: raw.roots,
      expandBraceHome: raw.expandBraceHome,
      homedir: raw.homedir,
    },
    auditLogPath: typeof raw.auditLogPath === "string" && isAbsolute(raw.auditLogPath) ? raw.auditLogPath : defaults.audit,
    debugLogPath: typeof raw.debugLogPath === "string" && isAbsolute(raw.debugLogPath) ? raw.debugLogPath : defaults.debug,
    decisionsLogPath: typeof raw.decisionsLogPath === "string" && isAbsolute(raw.decisionsLogPath) ? raw.decisionsLogPath : defaults.decisions,
    decisionPendingLimit: pendingLimit,
  };
}

export const PermissionCanonicalizerPlugin: Plugin = async (_ctx, options) => {
  const parsed = parseOptions(options);
  const sessionAgents = new Map<string, string>();
  const pendingPermissions = new Map<string, PendingPermission>();

  async function debug(message: string): Promise<void> {
    try {
      await mkdir(dirname(parsed.debugLogPath), { recursive: true });
      await appendFile(parsed.debugLogPath, `${new Date().toISOString()} ${message}\n`, "utf8");
    } catch {
      // Debug logging must never affect command execution.
    }
  }

  async function appendDecision(record: DecisionRecord): Promise<void> {
    await appendFile(parsed.decisionsLogPath, `${JSON.stringify(record)}\n`, "utf8");
  }

  async function rememberPermissionAsked(properties: RuntimePermissionAskedProperties): Promise<void> {
    if (typeof properties.id !== "string") return;
    const tool = isRecord(properties.tool) ? properties.tool : null;
    const callID = typeof tool?.callID === "string" ? tool.callID : null;
    const askedTs = new Date().toISOString();
    // Correlate on permission.asked.properties.id, the inner request id. The
    // outer event.id is only the bus envelope id and does not match replies.
    const key = pendingKey(properties.sessionID, properties.id);
    pendingPermissions.set(key, {
      callID,
      requestID: properties.id,
      sessionID: typeof properties.sessionID === "string" ? properties.sessionID : "",
      permission: typeof properties.permission === "string" ? properties.permission : "",
      patterns: stringArray(properties.patterns),
      always: stringArray(properties.always),
      askedTs,
    });
    await debug(`permission asked cached: requestID=${properties.id} callID=${callID ?? "null"}`);
    if (callID === null) {
      await debug(`permission asked missing callID: requestID=${properties.id}`);
    }
    while (pendingPermissions.size > parsed.decisionPendingLimit) {
      const oldestKey = pendingPermissions.keys().next().value;
      if (typeof oldestKey !== "string") return;
      const evicted = pendingPermissions.get(oldestKey);
      pendingPermissions.delete(oldestKey);
      await debug(`permission asked evicted: requestID=${evicted?.requestID ?? "unknown"} askedTs=${evicted?.askedTs ?? "unknown"}`);
    }
  }

  async function rememberPermissionReplied(properties: RuntimePermissionRepliedProperties): Promise<void> {
    if (typeof properties.requestID !== "string") return;
    const key = pendingKey(properties.sessionID, properties.requestID);
    const pending = pendingPermissions.get(key);
    if (!pending) {
      await debug(`permission replied without pending ask: requestID=${properties.requestID}`);
      return;
    }
    const sanitizedReply = sanitizeReply(properties.reply);
    if (properties.reply !== "once" && properties.reply !== "always" && properties.reply !== "reject") {
      await debug(`permission replied with unexpected reply: requestID=${properties.requestID} reply=${JSON.stringify(sanitizedReply)}`);
    }
    await appendDecision({
      ts: new Date().toISOString(),
      sessionID: pending.sessionID,
      callID: pending.callID,
      requestID: properties.requestID,
      permission: pending.permission,
      patterns: pending.patterns,
      always: pending.always,
      reply: sanitizedReply,
      askedTs: pending.askedTs,
    });
    pendingPermissions.delete(pendingKey(properties.sessionID, properties.requestID));
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

export default { server: PermissionCanonicalizerPlugin };
