// Host contracts the harness relies on, with provenance. Values marked
// verified were read at the pinned source commits with read-only `gh api`
// (anomalyco/opencode). Unverified contracts are review-gated: the runtime
// gate refuses to launch until each has a review reference in the manifest.
// Nothing here was checked against a running host.

export const PINS = Object.freeze({
  v1Floor: "16747470f976aca3d362ad730bcd3fe82ecc2c9a",
  v1Daily: "53d1eabb61e21162157817bf677da0a4ad3332e3",
  v2: "026b106bc5d41b679ffc413264229c340871e4d3",
});

/** Source-verified contracts. V1 files were also compared at the daily pin (identical unless noted). */
export const VERIFIED_CONTRACTS = Object.freeze({
  "auth": {
    value: { passwordEnv: "OPENCODE_SERVER_PASSWORD", username: "opencode", scheme: "Basic", challenge: 'Basic realm="Secure Area"' },
    source:
      "v1 packages/opencode/src/server/auth.ts + routes/instance/httpapi/middleware/authorization.ts (401 + www-authenticate); " +
      "v2 packages/cli/src/env.ts (OPENCODE_PASSWORD, falls back to OPENCODE_SERVER_PASSWORD), packages/cli/src/server-process.ts (random password when unset), " +
      "packages/server/src/auth.ts (username fixed 'opencode'), packages/server/src/middleware/authorization.ts (401 UnauthorizedError + challenge when sec-fetch-mode is absent)",
  },
  "launchArgv": {
    value: ["serve", "--hostname", "127.0.0.1", "--port", "{port}"],
    source: "v1 packages/opencode/src/cli/cmd/serve.ts + cli/network.ts; v2 packages/cli/src/commands/commands.ts (serve: --hostname, --port)",
  },
  "v1.routes": {
    value: "POST /session; POST /session/:id/prompt_async -> 204; POST /permission/:id/reply {reply,message?} -> boolean; POST /instance/dispose; POST /session/:id/abort; GET /event; ?directory=",
    source: "v1 packages/opencode/src/server/routes/instance/httpapi/groups/{session,permission,instance,event}.ts + middleware/workspace-routing.ts",
  },
  "v1.events": {
    value: "SSE data { id, type, properties }, first event server.connected; tool part state.status error carries state.error string",
    source: "v1 routes/instance/httpapi/handlers/event.ts; packages/opencode/src/session/processor.ts (failToolCall -> errorMessage)",
  },
  "v1.toolArgs": { value: { command: "<string>" }, source: "v1 packages/opencode/src/tool/shell/prompt.ts (command, timeout?, workdir?) and shell/id.ts (ToolID 'bash')" },
  "v2.toolArgs": { value: { command: "<string>" }, source: "v2 packages/core/src/tool/plugin/shell.ts Input (command, workdir?, timeout?, background?)" },
  "v2.shellPermissionAction": { value: "shell", source: "v2 packages/core/src/tool/plugin/shell.ts name = 'shell', permission.assert({ action: name })" },
  "ruleOrder": { value: "last matching rule wins", source: "v1 packages/opencode/src/permission/index.ts evaluate findLast; v2 packages/core/src/permission.ts evaluate findLast" },
  "v2.projectConfigDisable": { value: "OPENCODE_DISABLE_PROJECT_CONFIG", source: "v2 packages/cli/src/server-process.ts config.project" },
  "v1.denial": {
    value: {
      rejected: "The user rejected permission to use this specific tool call.",
      deniedPrefix: "The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules ",
      aborted: "Tool execution aborted",
    },
    source: "v1 packages/core/src/v1/permission.ts RejectedError/DeniedError messages; session/processor.ts errorMessage + abort path",
  },
  "v2.denial": {
    value: {
      rejected: { type: "aborted", message: "The user declined this tool call" },
      aborted: { type: "aborted", message: "Tool execution interrupted" },
      denied: { type: "permission.rejected", message: "Permission denied: shell" },
    },
    source:
      "v2 packages/core/src/session/runner/step.ts (decline -> failTool aborted; TOOLS_INTERRUPTED; Tool.Error -> failTool(toSessionError)). " +
      "Static deny trace: core/src/permission.ts assert -> BlockedError (message 'Permission denied: <action>' when no hook reason); " +
      "core/src/shell.ts create runs before() unwrapped; core/src/tool/plugin/shell.ts execute mapError -> ToolFailure{error}; " +
      "@opencode/ai ToolFailure extends Tool.Error (kept by core/src/tool/runtime.ts); " +
      "core/src/session/to-session-error.ts unwraps .error -> BlockedError -> { type: 'permission.rejected', message }",
  },
  "v2.providerExecuted": {
    value: "session.tool.success/failed `executed` is tool.providerExecuted: false for a locally executed tool",
    source: "v2 packages/core/src/session/runner/publish-llm-event.ts toolExecution (executed: tool.providerExecuted) and tool-call (providerExecuted === true)",
  },
  "versionOutput": {
    value: { v1: "<version>\\n", v2: "opencode v<version>\\n" },
    source:
      "approved Amendment A1 source review: V1 prints the bare version; pinned V2 uses Effect CLI 4.0.1 built-in --version (`<name> v<version>`). " +
      "Whole stdout must match exactly, with at most one final newline",
  },
  "v1.installFastPath": {
    value:
      "plugin: Npm.add('<spec>@latest') skips install when $XDG_CACHE_HOME/opencode/packages/<spec>@latest/node_modules/<name> exists; " +
      "config dir: Npm.install(dir, add @opencode-ai/plugin) skips when node_modules exists and package-lock packages[''] lists every declared name",
    source: "v1 packages/core/src/npm.ts (add, install, directory), packages/opencode/src/plugin/shared.ts resolvePluginTarget, packages/opencode/src/config/config.ts, packages/core/src/global.ts",
  },
});

/** Every contract value the harness uses that the evidence above does not pin. */
export const UNVERIFIED_CONTRACTS = Object.freeze([
  { key: "v1.providerConfig", description: "V1 custom OpenAI-compatible provider block (npm package, options.baseURL); may trigger a runtime install" },
  { key: "v2.providerConfig", description: "V2 providers template; must contain exactly one {providerBaseURL} placeholder that the harness binds" },
  { key: "v1.permissionConfig", description: "V1 `permission.bash` pattern map -> ruleset insertion order (rule evaluation itself is last-match, verified)" },
  { key: "v2.cacheLayout", description: "V2 plugin cache root, spec directory, and generation directory" },
  { key: "v2.installRecipe", description: "V2 dependency regions and offline install behavior" },
  { key: "npm.userconfigTripwire", description: "npm reads $HOME/.npmrc registry (npm defaults, not opencode source) so the fixture registry tripwire is consulted" },
  { key: "hosts.versionArgv", description: "argv that prints the host version without starting a server" },
  { key: "sandbox.machServices", description: "Mach services the host and the fake provider need" },
  { key: "sandbox.network", description: "IPv6 loopback and Unix-socket boundary semantics of the candidate profile" },
  { key: "artifacts.archiveRecipe", description: "exact archive members and expansion limits for the V1 zip and V2 tgz" },
]);

/** Keys of unverified contracts that have no non-empty review reference. */
export function unreviewedContracts(reviewed = {}) {
  return UNVERIFIED_CONTRACTS.map((entry) => entry.key).filter((key) => {
    const review = reviewed?.[key]?.review;
    return typeof review !== "string" || review.trim() === "";
  });
}

export const CONTRACT_SOURCES = Object.freeze({
  pins: PINS,
  v1: `pinned source ${PINS.v1Floor} (compared at ${PINS.v1Daily}); not the @opencode-ai/sdk@1.16.2 client`,
  v2: `pinned source ${PINS.v2}; @opencode/protocol@2.0.28 and @opencode/schema@2.0.28 in node_modules for request/response schemas`,
  normalizer: "this repo's src/v1.ts, src/v2.ts, src/decisions.ts (debug record text)",
});

/** Exact expected version stdout per family (at most one final newline is accepted; nothing else). */
export function expectedVersionOutput(family, version) {
  return family === "v2" ? `opencode v${version}\n` : `${version}\n`;
}

export function versionOutputMatches(family, version, stdout) {
  const expected = expectedVersionOutput(family, version);
  return stdout === expected || stdout === expected.slice(0, -1);
}

/** Debug record the plugin writes when it caches an ask (src/decisions.ts). */
export const ASK_CACHED_DEBUG = (requestID) => `permission asked cached: requestID=${requestID} `;

export const PLUGIN_ID = "skwid138.command-normalizer";
