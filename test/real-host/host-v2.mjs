// OpenCode V2 host adapter. Routes, bodies, and event/inventory shapes come
// from @opencode/protocol@2.0.28 and @opencode/schema@2.0.28 in node_modules:
//   POST /api/session                                   { location: { directory } }
//   POST /api/session/:id/prompt                        PromptInput { text }
//   POST /api/session/:id/permission/:requestID/reply   { decision } -> 204
//   POST /api/location/reload                           (no body) -> 204, SERVER-WIDE
//   GET  /api/plugin?location[directory]=...            { location, data: Plugin.Info[] }
//   POST /api/session/:id/interrupt
//   GET  /api/event                                     SSE { id, type, data }
// There is deliberately no config PATCH: /api/experimental/config accepts only
// { shell } (Config.Patch) and cannot add or remove plugins.
// The provider block, shell permission action, and model reference must be
// supplied from the reviewed recipe; they are never invented here.
import { VERIFIED_CONTRACTS } from "./contracts.mjs";
import { assertLoopbackBaseURL } from "./http.mjs";
import { removeDeclaration, restoreDeclaration, serveArgv } from "./plugin-decl.mjs";

const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
const str = (value) => (typeof value === "string" ? value : null);
const DENIAL = VERIFIED_CONTRACTS["v2.denial"].value;

const same = (error, shape) => isRecord(error) && error.type === shape.type && error.message === shape.message;

/** Exact {type, message} matches only; anything else is "other" (never a permission outcome). */
export function classifyV2Failure(error) {
  if (same(error, DENIAL.rejected)) return "rejected";
  if (same(error, DENIAL.aborted)) return "aborted";
  if (same(error, DENIAL.denied)) return "denied";
  return "other";
}

function normalizeEvent(raw) {
  if (!isRecord(raw) || typeof raw.type !== "string") return { kind: "other", type: null };
  const d = isRecord(raw.data) ? raw.data : {};
  switch (raw.type) {
    case "server.connected":
      return { kind: "connected", type: raw.type };
    case "permission.asked": {
      const source = isRecord(d.source) ? d.source : null;
      return {
        kind: "permission-asked",
        type: raw.type,
        requestID: str(d.id),
        sessionID: str(d.sessionID),
        callID: source?.type === "tool" ? str(source.id) : null,
        permission: str(d.action),
        patterns: Array.isArray(d.resources) ? d.resources : [],
      };
    }
    case "permission.replied":
      return { kind: "permission-replied", type: raw.type, requestID: str(d.requestID), sessionID: str(d.sessionID), reply: d.reply };
    case "session.tool.success":
      // Raw `executed` is tool.providerExecuted (contracts "v2.providerExecuted"); a local success is false.
      return { kind: "tool-terminal", type: raw.type, status: "completed", failure: null, sessionID: str(d.sessionID), callID: str(d.id), providerExecuted: d.executed === true };
    case "session.tool.failed":
      return {
        kind: "tool-terminal",
        type: raw.type,
        status: "error",
        failure: classifyV2Failure(d.error),
        error: isRecord(d.error) ? { type: str(d.error.type), message: str(d.error.message) } : null,
        sessionID: str(d.sessionID),
        callID: str(d.id),
        providerExecuted: d.executed === true,
      };
    case "session.tool.called":
      return { kind: "tool-running", type: raw.type, sessionID: str(d.sessionID), callID: str(d.id) };
    case "session.idle":
      return { kind: "session-idle", type: raw.type, sessionID: str(d.sessionID) };
    case "session.status":
      if (isRecord(d.status) && d.status.type === "idle") return { kind: "session-idle", type: raw.type, sessionID: str(d.sessionID) };
      return { kind: "other", type: raw.type };
    case "session.execution.succeeded":
    case "session.execution.failed":
    case "session.execution.interrupted":
      return { kind: "session-final", type: raw.type, sessionID: str(d.sessionID), outcome: raw.type.slice("session.execution.".length) };
    default:
      return { kind: "other", type: raw.type };
  }
}

export const PROVIDER_PLACEHOLDER = "{providerBaseURL}";

/**
 * Binds the reviewed providers template to the harness-allocated endpoint.
 * The template must contain the placeholder as exactly one whole string value,
 * and no other string in it may look like a URL. Other freeform keys are kept
 * as reviewed; nothing is merged over them.
 */
export function bindProviderTemplate(template, providerBaseURL) {
  assertLoopbackBaseURL(providerBaseURL);
  let placeholders = 0;
  const strays = [];
  const visit = (value) => {
    if (typeof value === "string") {
      if (value === PROVIDER_PLACEHOLDER) {
        placeholders += 1;
        return providerBaseURL;
      }
      if (value.includes(PROVIDER_PLACEHOLDER)) placeholders += 2;
      else if (/:\/\//.test(value)) strays.push(value);
      return value;
    }
    if (Array.isArray(value)) return value.map(visit);
    if (isRecord(value)) return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, visit(inner)]));
    return value;
  };
  const bound = visit(template);
  if (placeholders !== 1) throw new Error(`V2 provider template must contain exactly one ${PROVIDER_PLACEHOLDER} placeholder, as a whole string value`);
  if (strays.length > 0) throw new Error(`V2 provider template contains a non-harness URL: ${strays.join(", ")}`);
  return bound;
}

function evaluateInventory(response, { id, target, expect }) {
  const problems = [];
  const list = response.status === 200 && isRecord(response.json) && Array.isArray(response.json.data) ? response.json.data : null;
  if (!list) return { ok: false, problems: [`plugin inventory unavailable (status ${response.status})`] };
  const related = list.filter((entry) => isRecord(entry) && (entry.id === id || (isRecord(entry.source) && entry.source.target === target)));
  if (expect === "absent") {
    if (related.length > 0) problems.push(`plugin still listed after removal: ${JSON.stringify(related)}`);
  } else if (related.length !== 1) problems.push(`expected exactly one inventory entry, found ${related.length}`);
  else {
    const [entry] = related;
    if (entry.id !== id) problems.push(`inventory id ${entry.id} != ${id}`);
    if (!isRecord(entry.source) || entry.source.type !== "package") problems.push("inventory source.type is not package");
    if (!isRecord(entry.source) || entry.source.target !== target) problems.push(`inventory source.target is not ${target}`);
    if (!isRecord(entry.state) || entry.state.status !== "active") problems.push(`inventory state is ${JSON.stringify(entry.state)}`);
    if (!isRecord(entry.features) || entry.features.server !== true) problems.push("inventory features.server is not true");
  }
  return { ok: problems.length === 0, problems };
}

export const v2Host = Object.freeze({
  family: "v2",
  pluginKey: "plugins",
  toolName: "shell",
  launchArgv: serveArgv,
  routes: Object.freeze({
    identity: () => ({ method: "GET", path: "/api/session" }),
    createSession: (directory) => ({ method: "POST", path: "/api/session", body: { location: { directory } } }),
    prompt: ({ sessionID, text }) => ({ method: "POST", path: `/api/session/${encodeURIComponent(sessionID)}/prompt`, body: { text } }),
    reply: ({ sessionID, requestID, decision }) => ({
      method: "POST",
      path: `/api/session/${encodeURIComponent(sessionID)}/permission/${encodeURIComponent(requestID)}/reply`,
      body: { decision },
    }),
    reload: () => ({ method: "POST", path: "/api/location/reload" }),
    plugins: (directory) => ({ method: "GET", path: "/api/plugin", query: { location: { directory } } }),
    cancel: ({ sessionID }) => ({ method: "POST", path: `/api/session/${encodeURIComponent(sessionID)}/interrupt` }),
    events: () => ({ path: "/api/event" }),
    messages: ({ sessionID }) => ({ method: "GET", path: `/api/session/${encodeURIComponent(sessionID)}/message` }),
  }),
  sessionIDFrom: (response) => (isRecord(response.json) && isRecord(response.json.data) ? str(response.json.data.id) : null),
  replyAccepted: (response) => response.status === 204 && response.text === "",
  /** 204 means the reload request settled; it never proves the plugin is active. */
  reloadAccepted: (response) => ({ accepted: response.status === 204, activationProven: false }),
  normalizeEvent,
  evaluateInventory,
  buildConfig({ plugin, rules, reviewed, providerBaseURL }) {
    const missing = [];
    if (!isRecord(reviewed?.providers)) missing.push("v2.providerConfig");
    if (typeof reviewed?.model !== "string" || reviewed.model === "") missing.push("v2.providerConfig (model)");
    if (missing.length > 0) throw new Error(`V2 config needs reviewed contract values: ${missing.join(", ")}`);
    const action = VERIFIED_CONTRACTS["v2.shellPermissionAction"].value;
    const config = {
      model: reviewed.model,
      share: "disabled",
      update: "disable",
      providers: bindProviderTemplate(reviewed.providers, providerBaseURL),
    };
    if (plugin) config.plugins = [{ package: plugin.spec, options: plugin.options }];
    config.permissions = rules.map((rule) => ({ action, resource: rule.pattern, effect: rule.effect }));
    return config;
  },
  removePluginDeclaration: (config, decl) => removeDeclaration(config, "plugins", decl),
  restorePluginDeclaration: (config, decl, index) => restoreDeclaration(config, "plugins", decl, index),
});
