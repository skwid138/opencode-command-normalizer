import { describe, expect, it } from "vitest";

import { CONTRACT_SOURCES, UNVERIFIED_CONTRACTS, VERIFIED_CONTRACTS, unreviewedContracts } from "./contracts.mjs";
import { v1Host } from "./host-v1.mjs";
import { v2Host } from "./host-v2.mjs";

const PLUGIN = "@skwid138/opencode-command-normalizer";
const OPTIONS = { roots: ["~/bin"], auditLogPath: "/f/logs/audit.log", debugLogPath: "/f/logs/debug.log", decisionsLogPath: "/f/logs/decisions.log" };

describe("contract provenance", () => {
  it("pins V1 and V2 contracts to source commits, not the 1.16.2 SDK client", () => {
    expect(CONTRACT_SOURCES.v1).toMatch(/16747470f976aca3d362ad730bcd3fe82ecc2c9a/);
    expect(CONTRACT_SOURCES.v1).toMatch(/not the @opencode-ai\/sdk@1\.16\.2/);
    expect(CONTRACT_SOURCES.v2).toMatch(/026b106bc5d41b679ffc413264229c340871e4d3/);
    for (const key of ["auth", "launchArgv", "v1.routes", "v1.events", "v1.denial", "v2.denial", "v2.shellPermissionAction", "v1.installFastPath"]) {
      expect(VERIFIED_CONTRACTS[key].source, key).toMatch(/v[12] /);
    }
    const unverified = UNVERIFIED_CONTRACTS.map((entry: { key: string }) => entry.key);
    for (const key of ["v1.providerConfig", "v2.providerConfig", "sandbox.machServices", "hosts.versionArgv"]) expect(unverified).toContain(key);
    expect(unverified).not.toContain("v2.denyShape");
    expect(VERIFIED_CONTRACTS["v2.denial"].value.denied).toEqual({ type: "permission.rejected", message: "Permission denied: shell" });
    expect(VERIFIED_CONTRACTS["v2.denial"].source).toMatch(/to-session-error\.ts/);
    expect(VERIFIED_CONTRACTS["v2.providerExecuted"].source).toMatch(/publish-llm-event\.ts/);
    for (const key of Object.keys(VERIFIED_CONTRACTS)) expect(unverified).not.toContain(key);
  });

  it("reports unverified contracts that lack a review reference", () => {
    const all = UNVERIFIED_CONTRACTS.map((entry: { key: string }) => entry.key);
    expect(unreviewedContracts({})).toEqual(all);
    const reviewed = Object.fromEntries(all.map((key: string) => [key, { review: "ses_x", value: null }]));
    expect(unreviewedContracts(reviewed)).toEqual([]);
    expect(unreviewedContracts({ ...reviewed, "v2.providerConfig": { review: "" } })).toEqual(["v2.providerConfig"]);
  });
});

describe("terminal failure classification (source-verified shapes only)", () => {
  const v1Part = (status: string, error?: string) => ({
    type: "message.part.updated",
    properties: { sessionID: "s", part: { type: "tool", sessionID: "s", callID: "c1", tool: "bash", state: { status, ...(error === undefined ? {} : { error }) } } },
  });
  const v2Failed = (error: unknown, executed = false) => ({ type: "session.tool.failed", data: { sessionID: "s", id: "c1", executed, error } });

  it("V1: classifies only the exact rejected text, the denied-rule prefix, and the abort text", () => {
    const n = v1Host.normalizeEvent;
    expect(n(v1Part("error", "The user rejected permission to use this specific tool call."))).toMatchObject({ failure: "rejected" });
    expect(n(v1Part("error", 'The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules [{"permission":"bash"}]'))).toMatchObject({
      failure: "denied",
    });
    expect(n(v1Part("error", "Tool execution aborted"))).toMatchObject({ failure: "aborted" });
    for (const other of ["/bin/sh: rh-probe: command not found", "Invalid input", "permission denied", ""]) {
      expect(n(v1Part("error", other)), other).toMatchObject({ failure: "other", error: other });
    }
    expect(n(v1Part("error"))).toMatchObject({ failure: "other" });
    expect(n(v1Part("completed"))).toMatchObject({ failure: null });
  });

  it("V2: classifies rejected, aborted, and static deny by the exact traced {type, message}", () => {
    const n = v2Host.normalizeEvent;
    expect(n(v2Failed({ type: "aborted", message: "The user declined this tool call" }))).toMatchObject({ failure: "rejected", providerExecuted: false });
    expect(n(v2Failed({ type: "aborted", message: "Tool execution interrupted" }))).toMatchObject({ failure: "aborted" });
    expect(n(v2Failed({ type: "permission.rejected", message: "Permission denied: shell" }))).toMatchObject({ failure: "denied" });
    for (const other of [
      { type: "tool.execution", message: "Permission denied: shell" },
      { type: "permission.rejected", message: "some hook reason" },
      { type: "tool.execution", message: "spawn ENOENT" },
      { type: "tool.input-json", message: "Tool call arguments were malformed JSON and were not executed. Retry with valid JSON." },
      { type: "aborted", message: "Step interrupted" },
      "Permission denied: shell",
      null,
    ]) {
      expect(n(v2Failed(other)), JSON.stringify(other)).toMatchObject({ failure: "other" });
    }
    expect(n({ type: "session.tool.success", data: { sessionID: "s", id: "c1", executed: true } })).toMatchObject({ failure: null });
  });

  it("V2: maps the raw `executed` flag to providerExecuted (a local success carries executed: false)", () => {
    const local = v2Host.normalizeEvent({ type: "session.tool.success", data: { sessionID: "s", id: "c1", executed: false } });
    expect(local).toMatchObject({ kind: "tool-terminal", status: "completed", providerExecuted: false });
    expect(local).not.toHaveProperty("executed");
    expect(v2Host.normalizeEvent({ type: "session.tool.success", data: { sessionID: "s", id: "c1", executed: true } })).toMatchObject({ providerExecuted: true });
  });
});

describe("V1 host adapter", () => {
  it("builds the session, prompt, reply, dispose, abort, event, and message requests", () => {
    const r = v1Host.routes;
    expect(r.createSession("/fx/project")).toEqual({ method: "POST", path: "/session", query: { directory: "/fx/project" }, body: {} });
    expect(r.prompt({ sessionID: "ses_1", text: "go", model: { providerID: "fake", modelID: "m" }, directory: "/d" })).toEqual({
      method: "POST",
      path: "/session/ses_1/prompt_async",
      query: { directory: "/d" },
      body: { parts: [{ type: "text", text: "go" }], model: { providerID: "fake", modelID: "m" } },
    });
    expect(r.reply({ requestID: "per_1", decision: "once", directory: "/d" })).toEqual({
      method: "POST",
      path: "/permission/per_1/reply",
      query: { directory: "/d" },
      body: { reply: "once" },
    });
    expect(r.dispose("/d")).toEqual({ method: "POST", path: "/instance/dispose", query: { directory: "/d" } });
    expect(r.cancel({ sessionID: "ses_1", directory: "/d" })).toEqual({ method: "POST", path: "/session/ses_1/abort", query: { directory: "/d" } });
    expect(r.events("/d")).toEqual({ path: "/event", query: { directory: "/d" } });
  });

  it("accepts a reply only on a boolean true response", () => {
    expect(v1Host.replyAccepted({ status: 200, json: true, text: "true" })).toBe(true);
    expect(v1Host.replyAccepted({ status: 200, json: false, text: "false" })).toBe(false);
    expect(v1Host.replyAccepted({ status: 204, json: null, text: "" })).toBe(false);
  });

  it("normalizes connected, permission, tool, and idle events", () => {
    const n = v1Host.normalizeEvent;
    expect(n({ type: "server.connected", properties: {} })).toMatchObject({ kind: "connected" });
    expect(
      n({ type: "permission.asked", properties: { id: "per_1", sessionID: "s", permission: "bash", patterns: ["/h/bin/x"], always: [], tool: { messageID: "m", callID: "c1" } } }),
    ).toMatchObject({ kind: "permission-asked", requestID: "per_1", sessionID: "s", callID: "c1", patterns: ["/h/bin/x"] });
    expect(n({ type: "permission.replied", properties: { sessionID: "s", requestID: "per_1", reply: "reject" } })).toMatchObject({
      kind: "permission-replied",
      requestID: "per_1",
      reply: "reject",
    });
    const tool = (status: string) => ({ type: "message.part.updated", properties: { sessionID: "s", part: { type: "tool", sessionID: "s", callID: "c1", tool: "bash", state: { status } } } });
    expect(n(tool("completed"))).toMatchObject({ kind: "tool-terminal", callID: "c1", status: "completed", tool: "bash" });
    expect(n(tool("error"))).toMatchObject({ kind: "tool-terminal", status: "error" });
    expect(n(tool("running"))).toMatchObject({ kind: "tool-running" });
    expect(n({ type: "session.idle", properties: { sessionID: "s" } })).toMatchObject({ kind: "session-idle", sessionID: "s" });
    expect(n({ type: "session.status", properties: { sessionID: "s", status: { type: "idle" } } })).toMatchObject({ kind: "session-idle" });
    expect(n({ type: "session.status", properties: { sessionID: "s", status: { type: "busy" } } })).toMatchObject({ kind: "other" });
    expect(n("garbage")).toMatchObject({ kind: "other" });
  });

  it("generates a candidate config with tuple plugin declaration and bash permission rules, or none when the plugin is absent", () => {
    const config = v1Host.buildConfig({
      providerBaseURL: "http://127.0.0.1:5000/v1",
      plugin: { spec: PLUGIN, options: OPTIONS },
      rules: [
        { pattern: "*", effect: "ask" },
        { pattern: "/fx/home/bin/rh-probe *", effect: "allow" },
      ],
    });
    expect(config.plugin).toEqual([[PLUGIN, OPTIONS]]);
    expect(config.permission).toEqual({ bash: { "*": "ask", "/fx/home/bin/rh-probe *": "allow" } });
    expect(config.provider.fake.options.baseURL).toBe("http://127.0.0.1:5000/v1");
    expect(config.model).toBe("fake/fake-model");
    expect(JSON.stringify(config)).not.toMatch(/--pure/);
    expect(v1Host.buildConfig({ providerBaseURL: "http://127.0.0.1:5000/v1", plugin: null, rules: [] }).plugin).toBeUndefined();
    expect(() => v1Host.buildConfig({ providerBaseURL: "https://api.openai.com/v1", plugin: null, rules: [] })).toThrow(/loopback/);
  });
});

describe("V2 host adapter", () => {
  it("builds requests from the @opencode/protocol@2.0.28 routes", () => {
    const r = v2Host.routes;
    expect(r.createSession("/fx/project")).toEqual({ method: "POST", path: "/api/session", body: { location: { directory: "/fx/project" } } });
    expect(r.prompt({ sessionID: "ses_1", text: "go" })).toEqual({ method: "POST", path: "/api/session/ses_1/prompt", body: { text: "go" } });
    expect(r.reply({ sessionID: "ses_1", requestID: "per_1", decision: "reject" })).toEqual({
      method: "POST",
      path: "/api/session/ses_1/permission/per_1/reply",
      body: { decision: "reject" },
    });
    // Server-wide, bodyless reload: only ever on a dedicated server.
    expect(r.reload()).toEqual({ method: "POST", path: "/api/location/reload" });
    expect(r.plugins("/fx/project")).toEqual({ method: "GET", path: "/api/plugin", query: { location: { directory: "/fx/project" } } });
    expect(r.cancel({ sessionID: "ses_1" })).toEqual({ method: "POST", path: "/api/session/ses_1/interrupt" });
    expect(r.events()).toEqual({ path: "/api/event" });
    expect(r).not.toHaveProperty("patchConfig");
  });

  it("accepts a reply only on 204 No Content, and never treats a reload 204 as activation", () => {
    expect(v2Host.replyAccepted({ status: 204, json: null, text: "" })).toBe(true);
    expect(v2Host.replyAccepted({ status: 200, json: true, text: "true" })).toBe(false);
    expect(v2Host.reloadAccepted({ status: 204, json: null, text: "" })).toEqual({ accepted: true, activationProven: false });
  });

  it("normalizes V2 events", () => {
    const n = v2Host.normalizeEvent;
    expect(n({ id: "evt_1", type: "server.connected", data: {} })).toMatchObject({ kind: "connected" });
    expect(
      n({ type: "permission.asked", data: { id: "per_1", sessionID: "s", action: "shell", resources: ["/h/bin/x"], source: { type: "tool", messageID: "m", id: "c1" } } }),
    ).toMatchObject({ kind: "permission-asked", requestID: "per_1", callID: "c1", patterns: ["/h/bin/x"], permission: "shell" });
    expect(n({ type: "permission.asked", data: { id: "per_2", sessionID: "s", action: "shell", resources: [] } })).toMatchObject({ callID: null });
    expect(n({ type: "permission.replied", data: { sessionID: "s", requestID: "per_1", reply: "once" } })).toMatchObject({ kind: "permission-replied", reply: "once" });
    expect(n({ type: "session.tool.success", data: { sessionID: "s", id: "c1", executed: false } })).toMatchObject({
      kind: "tool-terminal",
      status: "completed",
      callID: "c1",
      providerExecuted: false,
    });
    expect(n({ type: "session.tool.failed", data: { sessionID: "s", id: "c1", executed: false } })).toMatchObject({ kind: "tool-terminal", status: "error" });
    expect(n({ type: "session.tool.called", data: { sessionID: "s", id: "c1" } })).toMatchObject({ kind: "tool-running" });
    expect(n({ type: "session.status", data: { sessionID: "s", status: { type: "idle" } } })).toMatchObject({ kind: "session-idle" });
    expect(n({ type: "session.execution.succeeded", data: { sessionID: "s" } })).toMatchObject({ kind: "session-final", outcome: "succeeded" });
  });

  it("evaluates plugin inventory: exactly one active package entry when present, id and spec absent when removed", () => {
    const active = { id: "skwid138.command-normalizer", source: { type: "package", target: PLUGIN }, features: { server: true }, state: { status: "active" } };
    const body = (data: unknown[]) => ({ status: 200, json: { location: { directory: "/fx" }, data }, text: "" });
    const target = { id: "skwid138.command-normalizer", target: PLUGIN };

    expect(v2Host.evaluateInventory(body([active]), { ...target, expect: "active" })).toEqual({ ok: true, problems: [] });
    expect(v2Host.evaluateInventory(body([active, active]), { ...target, expect: "active" }).ok).toBe(false);
    expect(v2Host.evaluateInventory(body([{ ...active, state: { status: "failed", error: "x" } }]), { ...target, expect: "active" }).ok).toBe(false);
    expect(v2Host.evaluateInventory(body([{ ...active, features: {} }]), { ...target, expect: "active" }).ok).toBe(false);
    expect(v2Host.evaluateInventory(body([]), { ...target, expect: "absent" })).toEqual({ ok: true, problems: [] });
    // A "disposed"-looking entry still present is not removal.
    expect(v2Host.evaluateInventory(body([{ ...active, state: { status: "disposed" } }]), { ...target, expect: "absent" }).ok).toBe(false);
    expect(v2Host.evaluateInventory(body([{ source: { type: "package", target: PLUGIN }, features: {}, state: { status: "failed", error: "x" } }]), { ...target, expect: "absent" }).ok).toBe(false);
    expect(v2Host.evaluateInventory({ status: 500, json: null, text: "" }, { ...target, expect: "absent" }).ok).toBe(false);
  });

  it("binds the reviewed provider template to the harness-allocated loopback endpoint exactly once", () => {
    const base = { plugin: { spec: PLUGIN, options: OPTIONS }, rules: [{ pattern: "*", effect: "ask" }], providerBaseURL: "http://127.0.0.1:41001/v1" };
    expect(() => v2Host.buildConfig({ ...base, reviewed: {} })).toThrow(/v2.providerConfig/);
    const template = { fake: { package: "@ai-sdk/openai-compatible", settings: { baseURL: "{providerBaseURL}", timeout: 5000 }, models: { "fake-model": {} } } };
    const config = v2Host.buildConfig({ ...base, reviewed: { providers: template, model: "fake/fake-model" } });
    expect(config).toEqual({
      model: "fake/fake-model",
      share: "disabled",
      update: "disable",
      providers: { fake: { package: "@ai-sdk/openai-compatible", settings: { baseURL: "http://127.0.0.1:41001/v1", timeout: 5000 }, models: { "fake-model": {} } } },
      plugins: [{ package: PLUGIN, options: OPTIONS }],
      permissions: [{ action: "shell", resource: "*", effect: "ask" }],
    });
    expect(template.fake.settings.baseURL).toBe("{providerBaseURL}");
  });

  it("accepts the Amendment A1 documented V2 provider values unchanged except for the bound endpoint", () => {
    const providers = {
      fake: {
        package: "@opencode/ai/providers/openai-compatible",
        settings: { baseURL: "{providerBaseURL}", provider: "fake", apiKey: "fixture-placeholder-not-a-credential" },
        models: { "fake-model": { capabilities: { tools: true, input: ["text"], output: ["text"] } } },
      },
    };
    const config = v2Host.buildConfig({ plugin: null, rules: [], providerBaseURL: "http://127.0.0.1:41001/v1", reviewed: { providers, model: "fake/fake-model" } });
    expect(config.model).toBe("fake/fake-model");
    expect(config.providers).toEqual({ fake: { ...providers.fake, settings: { ...providers.fake.settings, baseURL: "http://127.0.0.1:41001/v1" } } });
  });

  it.each([
    ["no placeholder", { fake: { settings: { baseURL: "http://127.0.0.1:41001/v1" } } }, /exactly one/],
    ["two placeholders", { fake: { settings: { baseURL: "{providerBaseURL}", fallback: "{providerBaseURL}" } } }, /exactly one/],
    ["an external URL elsewhere", { fake: { settings: { baseURL: "{providerBaseURL}", docs: "https://api.example.com" } } }, /non-harness URL/],
    ["a placeholder embedded in a larger string", { fake: { settings: { baseURL: "{providerBaseURL}/extra" } } }, /exactly one/],
  ])("refuses a provider template with %s", (_label, providers, message) => {
    expect(() =>
      v2Host.buildConfig({ plugin: null, rules: [], providerBaseURL: "http://127.0.0.1:41001/v1", reviewed: { providers, model: "fake/fake-model" } }),
    ).toThrow(message);
  });

  it("refuses a non-loopback harness endpoint", () => {
    expect(() =>
      v2Host.buildConfig({ plugin: null, rules: [], providerBaseURL: "http://10.0.0.5:41001/v1", reviewed: { providers: { fake: { u: "{providerBaseURL}" } }, model: "fake/fake-model" } }),
    ).toThrow(/loopback/);
  });
});

describe("source-verified launch and identity", () => {
  it("launches both hosts with serve --hostname 127.0.0.1 --port <owned port>", () => {
    for (const host of [v1Host, v2Host]) expect(host.launchArgv(41000)).toEqual(["serve", "--hostname", "127.0.0.1", "--port", "41000"]);
    expect(() => v1Host.launchArgv(0)).toThrow(/port/);
  });

  it("uses a protected read-only route for the auth-challenge identity check", () => {
    expect(v1Host.routes.identity("/fx/project")).toEqual({ method: "GET", path: "/session", query: { directory: "/fx/project" } });
    expect(v2Host.routes.identity("/fx/project")).toEqual({ method: "GET", path: "/api/session" });
  });
});

describe("plugin declaration lifecycle edits", () => {
  for (const [label, host, key] of [
    ["V1", v1Host, "plugin"],
    ["V2", v2Host, "plugins"],
  ] as const) {
    it(`${label}: removes and restores exactly one matching declaration at its original position`, () => {
      const decl = key === "plugin" ? [PLUGIN, OPTIONS] : { package: PLUGIN, options: OPTIONS };
      const config = { [key]: ["other-plugin", decl, "third"] };

      const removed = host.removePluginDeclaration(config, decl);
      expect(removed.config[key]).toEqual(["other-plugin", "third"]);
      expect(config[key]).toHaveLength(3);

      const restored = host.restorePluginDeclaration(removed.config, decl, removed.index);
      expect(restored[key]).toEqual(config[key]);

      expect(() => host.removePluginDeclaration({ [key]: [decl, decl] }, decl)).toThrow(/exactly one/);
      expect(() => host.removePluginDeclaration({ [key]: ["other"] }, decl)).toThrow(/exactly one/);
    });
  }
});
