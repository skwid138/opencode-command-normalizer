// OpenCode V1 host adapter: config generation, control requests, and event
// normalization. Route and event shapes come from @opencode-ai/sdk@1.16.2 and
// are review-gated (contracts.mjs "v1.routes", "v1.events"). The provider
// block is a candidate ("v1.providerConfig").
import { VERIFIED_CONTRACTS } from "./contracts.mjs";
import { assertLoopbackBaseURL } from "./http.mjs";
import { removeDeclaration, restoreDeclaration, serveArgv } from "./plugin-decl.mjs";

const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
const str = (value) => (typeof value === "string" ? value : null);

export const FAKE_PROVIDER_ID = "fake";
const DENIAL = VERIFIED_CONTRACTS["v1.denial"].value;

/** Exact source-verified V1 tool failure texts; anything else is "other" (never a permission outcome). */
export function classifyV1Failure(error) {
  if (typeof error !== "string") return "other";
  if (error === DENIAL.rejected) return "rejected";
  if (error.startsWith(DENIAL.deniedPrefix)) return "denied";
  if (error === DENIAL.aborted) return "aborted";
  return "other";
}
export const FAKE_MODEL_ID = "fake-model";

function normalizeEvent(raw) {
  if (!isRecord(raw) || typeof raw.type !== "string") return { kind: "other", type: null };
  const p = isRecord(raw.properties) ? raw.properties : {};
  switch (raw.type) {
    case "server.connected":
      return { kind: "connected", type: raw.type };
    case "permission.asked":
      return {
        kind: "permission-asked",
        type: raw.type,
        requestID: str(p.id),
        sessionID: str(p.sessionID),
        callID: isRecord(p.tool) ? str(p.tool.callID) : null,
        permission: str(p.permission),
        patterns: Array.isArray(p.patterns) ? p.patterns : [],
      };
    case "permission.replied":
      return { kind: "permission-replied", type: raw.type, requestID: str(p.requestID), sessionID: str(p.sessionID), reply: p.reply };
    case "message.part.updated": {
      const part = isRecord(p.part) ? p.part : {};
      if (part.type !== "tool" || !isRecord(part.state)) return { kind: "other", type: raw.type };
      const status = part.state.status;
      const base = { type: raw.type, sessionID: str(part.sessionID) ?? str(p.sessionID), callID: str(part.callID), tool: str(part.tool) };
      if (status === "completed") return { kind: "tool-terminal", status, failure: null, ...base };
      if (status === "error") return { kind: "tool-terminal", status, failure: classifyV1Failure(part.state.error), error: typeof part.state.error === "string" ? part.state.error : null, ...base };
      return { kind: "tool-running", status, ...base };
    }
    case "session.idle":
      return { kind: "session-idle", type: raw.type, sessionID: str(p.sessionID) };
    case "session.status":
      if (isRecord(p.status) && p.status.type === "idle") return { kind: "session-idle", type: raw.type, sessionID: str(p.sessionID) };
      return { kind: "other", type: raw.type };
    default:
      return { kind: "other", type: raw.type };
  }
}

export const v1Host = Object.freeze({
  family: "v1",
  pluginKey: "plugin",
  toolName: "bash",
  launchArgv: serveArgv,
  routes: Object.freeze({
    identity: (directory) => ({ method: "GET", path: "/session", query: { directory } }),
    createSession: (directory) => ({ method: "POST", path: "/session", query: { directory }, body: {} }),
    prompt: ({ sessionID, text, model, directory }) => ({
      method: "POST",
      path: `/session/${encodeURIComponent(sessionID)}/prompt_async`,
      query: { directory },
      body: { parts: [{ type: "text", text }], model },
    }),
    reply: ({ requestID, decision, directory }) => ({
      method: "POST",
      path: `/permission/${encodeURIComponent(requestID)}/reply`,
      query: { directory },
      body: { reply: decision },
    }),
    dispose: (directory) => ({ method: "POST", path: "/instance/dispose", query: { directory } }),
    cancel: ({ sessionID, directory }) => ({ method: "POST", path: `/session/${encodeURIComponent(sessionID)}/abort`, query: { directory } }),
    events: (directory) => ({ path: "/event", query: { directory } }),
    messages: ({ sessionID, directory }) => ({ method: "GET", path: `/session/${encodeURIComponent(sessionID)}/message`, query: { directory } }),
  }),
  sessionIDFrom: (response) => (isRecord(response.json) ? str(response.json.id) : null),
  replyAccepted: (response) => response.status === 200 && response.json === true,
  normalizeEvent,
  /** Candidate config. The provider block is review-gated ("v1.providerConfig"). */
  buildConfig({ providerBaseURL, plugin, rules }) {
    assertLoopbackBaseURL(providerBaseURL);
    const config = {
      $schema: "https://opencode.ai/config.json",
      autoupdate: false,
      share: "disabled",
      model: `${FAKE_PROVIDER_ID}/${FAKE_MODEL_ID}`,
      provider: {
        [FAKE_PROVIDER_ID]: {
          npm: "@ai-sdk/openai-compatible",
          name: "real-host fake provider",
          options: { baseURL: providerBaseURL, apiKey: "fixture-placeholder-not-a-credential" },
          models: { [FAKE_MODEL_ID]: { name: FAKE_MODEL_ID, tool_call: true } },
        },
      },
      permission: { bash: Object.fromEntries(rules.map((rule) => [rule.pattern, rule.effect])) },
    };
    if (plugin) config.plugin = [[plugin.spec, plugin.options]];
    return config;
  },
  removePluginDeclaration: (config, decl) => removeDeclaration(config, "plugin", decl),
  restorePluginDeclaration: (config, decl, index) => restoreDeclaration(config, "plugin", decl, index),
});
