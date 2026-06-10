import { mkdir as makeDir, mkdtemp, readFile, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import defaultExport, {
  canonicalize,
  canonicalizeAndAudit,
  PermissionCanonicalizerPlugin,
  resolveDefaultLogPaths,
  splitCommandNodes,
} from "./index";

const HOME = "/home/example";
const LOG_SUBDIR = join("opencode", "permission-audit-plugin");

type PluginHooks = {
  "chat.params": (input: { sessionID: string; agent: string }) => Promise<void>;
  "tool.execute.before": (
    input: { tool: string; sessionID: string; callID: string },
    output: { args: { command: string } },
  ) => Promise<void>;
  event: (input: unknown) => Promise<void>;
};

function homePath(...parts: string[]): string {
  return join(HOME, ...parts);
}

async function readDecisionRecords(path: string): Promise<Record<string, unknown>[]> {
  try {
    const content = await readFile(path, "utf8");
    return content
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return [];
    throw error;
  }
}

async function createPluginHooks(options: Record<string, unknown> = {}): Promise<PluginHooks> {
  const dir = await mkdtemp(join(tmpdir(), "permission-canon-decisions-"));
  const plugin = await PermissionCanonicalizerPlugin(
    {} as never,
    {
      homedir: HOME,
      auditLogPath: join(dir, "audit.log"),
      debugLogPath: join(dir, "debug.log"),
      decisionsLogPath: join(dir, "decisions.log"),
      ...options,
    },
  );
  return plugin as PluginHooks;
}

describe("permission command canonicalization", () => {
  it("expands only argv0 home forms at command-node starts", () => {
    expect(
      canonicalize(
        "~/workspace/tools/foo.sh --path ~/kept && $HOME/workspace/tools/bar.sh | echo $HOME/arg",
        { homedir: HOME },
      ),
    ).toBe(
      `${homePath("workspace", "tools", "foo.sh")} --path ~/kept && ${homePath("workspace", "tools", "bar.sh")} | echo $HOME/arg`,
    );
  });

  it("does not expand brace HOME unless explicitly opted in", () => {
    expect(canonicalize("${HOME}/workspace/tools/foo.sh", { homedir: HOME })).toBe(
      "${HOME}/workspace/tools/foo.sh",
    );
    expect(
      canonicalize("${HOME}/workspace/tools/foo.sh", {
        homedir: HOME,
        expandBraceHome: true,
      }),
    ).toBe(homePath("workspace", "tools", "foo.sh"));
  });

  it("bails byte-for-byte on uncertain or unsafe shell shapes", () => {
    const commands = [
      "FOO=bar ~/workspace/tools/foo.sh",
      "HOME=/tmp ~/workspace/tools/foo.sh",
      "(~/workspace/tools/foo.sh)",
      "{ ~/workspace/tools/foo.sh; }",
      "echo $(~/workspace/tools/foo.sh)",
      "cat <<EOF\nbody\nEOF",
      '""~/workspace/tools/foo.sh',
      'echo "unterminated',
    ];

    for (const command of commands) {
      expect(canonicalize(command, { homedir: HOME })).toBe(command);
    }
  });

  it("limits configured roots on path-segment boundaries and rejects dot-dot argv0s", () => {
    expect(
      canonicalize("~/workspace/tools/foo.sh", {
        homedir: HOME,
        roots: ["~/workspace"],
      }),
    ).toBe(homePath("workspace", "tools", "foo.sh"));
    expect(
      canonicalize("~/workspace2/tools/foo.sh", {
        homedir: HOME,
        roots: ["~/workspace"],
      }),
    ).toBe("~/workspace2/tools/foo.sh");
    expect(
      canonicalize("~/workspace/../secret.sh", {
        homedir: HOME,
        roots: ["~/workspace"],
      }),
    ).toBe("~/workspace/../secret.sh");
  });

  it("splits command nodes using shell separators without treating groups as starts", () => {
    expect(splitCommandNodes("~/a && ~/b |& ~/c; ~/d & ~/e\n~/f")).toEqual([
      "~/a",
      "~/b",
      "~/c",
      "~/d",
      "~/e",
      "~/f",
    ]);
    expect(splitCommandNodes("(~/a) && ~/b")).toEqual(["(~/a)", "~/b"]);
  });
});

describe("default log path resolution", () => {
  it("uses an absolute XDG_DATA_HOME", () => {
    expect(resolveDefaultLogPaths({ XDG_DATA_HOME: "/var/data" }, HOME)).toEqual({
      audit: join("/var/data", LOG_SUBDIR, "audit.log"),
      debug: join("/var/data", LOG_SUBDIR, "debug.log"),
      decisions: join("/var/data", LOG_SUBDIR, "decisions.log"),
    });
  });

  it("falls back to homedir local share when XDG_DATA_HOME is unset", () => {
    expect(resolveDefaultLogPaths({}, HOME)).toEqual({
      audit: join(HOME, ".local", "share", LOG_SUBDIR, "audit.log"),
      debug: join(HOME, ".local", "share", LOG_SUBDIR, "debug.log"),
      decisions: join(HOME, ".local", "share", LOG_SUBDIR, "decisions.log"),
    });
  });

  it("falls back to homedir local share when XDG_DATA_HOME is an empty string", () => {
    expect(resolveDefaultLogPaths({ XDG_DATA_HOME: "" }, HOME)).toEqual({
      audit: join(HOME, ".local", "share", LOG_SUBDIR, "audit.log"),
      debug: join(HOME, ".local", "share", LOG_SUBDIR, "debug.log"),
      decisions: join(HOME, ".local", "share", LOG_SUBDIR, "decisions.log"),
    });
  });

  it("falls back to homedir local share when XDG_DATA_HOME is relative", () => {
    expect(resolveDefaultLogPaths({ XDG_DATA_HOME: "relative/data" }, HOME)).toEqual({
      audit: join(HOME, ".local", "share", LOG_SUBDIR, "audit.log"),
      debug: join(HOME, ".local", "share", LOG_SUBDIR, "debug.log"),
      decisions: join(HOME, ".local", "share", LOG_SUBDIR, "decisions.log"),
    });
  });

  it("normalizes an absolute XDG_DATA_HOME with a trailing slash", () => {
    expect(resolveDefaultLogPaths({ XDG_DATA_HOME: "/var/data/" }, HOME)).toEqual({
      audit: join("/var/data", LOG_SUBDIR, "audit.log"),
      debug: join("/var/data", LOG_SUBDIR, "debug.log"),
      decisions: join("/var/data", LOG_SUBDIR, "decisions.log"),
    });
  });

  it("includes the default decisions log beside audit and debug logs", () => {
    expect(resolveDefaultLogPaths({ XDG_DATA_HOME: "/var/data" }, HOME).decisions).toBe(
      join("/var/data", LOG_SUBDIR, "decisions.log"),
    );
  });
});

describe("permission canonicalizer audit side effects", () => {
  it("does not let audit append failure affect the canonical command", async () => {
    const appendRecord = vi.fn(async () => {
      throw new Error("disk full");
    });

    const result = await canonicalizeAndAudit(
      "~/workspace/tools/foo.sh && pwd",
      { homedir: HOME },
      {
        sessionID: "ses_test",
        agent: "aragorn",
        callID: "call_test",
        appendRecord,
        debug: vi.fn(async () => undefined),
      },
    );

    expect(result).toBe(`${homePath("workspace", "tools", "foo.sh")} && pwd`);
    expect(appendRecord).toHaveBeenCalledTimes(2);
  });

  it("audits global-bail heredoc commands as one record without splitting body lines", async () => {
    const appendRecord = vi.fn(async () => undefined);
    const command = "cat <<EOF\n~/workspace/tools/fake-body-command.sh\nEOF";

    const result = await canonicalizeAndAudit(command, { homedir: HOME }, {
      sessionID: "ses_test",
      agent: "aragorn",
      callID: "call_test",
      appendRecord,
      debug: vi.fn(async () => undefined),
    });

    expect(result).toBe(command);
    expect(appendRecord).toHaveBeenCalledTimes(1);
    expect(appendRecord).toHaveBeenCalledWith(expect.objectContaining({ command_node_text: command }));
  });

  it("plugin hook mutates bash commands and writes one audit record per command node", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-"));
    const auditPath = join(dir, "audit.log");
    const debugPath = join(dir, "debug.log");
    const plugin = await PermissionCanonicalizerPlugin(
      {} as never,
      { homedir: HOME, auditLogPath: auditPath, debugLogPath: debugPath },
    );
    const hooks = plugin as {
      "chat.params": (input: { sessionID: string; agent: string }) => Promise<void>;
      "tool.execute.before": (
        input: { tool: string; sessionID: string; callID: string },
        output: { args: { command: string } },
      ) => Promise<void>;
    };
    await hooks["chat.params"]({ sessionID: "ses_test", agent: "aragorn" });
    const output = { args: { command: "~/workspace/tools/foo.sh && pwd" } };

    await hooks["tool.execute.before"](
      { tool: "bash", sessionID: "ses_test", callID: "call_test" },
      output,
    );

    expect(output.args.command).toBe(`${homePath("workspace", "tools", "foo.sh")} && pwd`);
    const records = (await readFile(auditPath, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(records).toMatchObject([
      {
        sessionID: "ses_test",
        agent: "aragorn",
        callID: "call_test",
        command_node_text: homePath("workspace", "tools", "foo.sh"),
      },
      {
        sessionID: "ses_test",
        agent: "aragorn",
        callID: "call_test",
        command_node_text: "pwd",
      },
    ]);
  });

  it("ignores relative audit and debug log overrides and uses default paths", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-defaults-"));
    vi.stubEnv("XDG_DATA_HOME", dir);
    try {
      const defaults = resolveDefaultLogPaths({ XDG_DATA_HOME: dir });
      const plugin = await PermissionCanonicalizerPlugin(
        {} as never,
        { homedir: HOME, auditLogPath: "relative-audit.log", debugLogPath: "relative-debug.log" },
      );
      const hooks = plugin as {
        "tool.execute.before": (
          input: { tool: string; sessionID: string; callID: string },
          output: { args: { command: string } },
        ) => Promise<void>;
      };

      await hooks["tool.execute.before"](
        { tool: "bash", sessionID: "ses_test", callID: "call_test" },
        { args: { command: "~/workspace/tools/foo.sh" } },
      );

      await expect(readFile(defaults.audit, "utf8")).resolves.toContain(homePath("workspace", "tools", "foo.sh"));
      await expect(readFile("relative-audit.log", "utf8")).rejects.toThrow();
      await expect(readFile("relative-debug.log", "utf8")).rejects.toThrow();
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("ignores a relative decisions log override and uses the default decisions path", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-default-decisions-"));
    vi.stubEnv("XDG_DATA_HOME", dir);
    try {
      const defaults = resolveDefaultLogPaths({ XDG_DATA_HOME: dir });
      const relativeDecisionsPath = `relative-decisions-${Date.now()}.log`;
      const hooks = await createPluginHooks({ decisionsLogPath: relativeDecisionsPath });

      await hooks.event({
        event: {
          type: "permission.asked",
          properties: { id: "req_default_decisions", sessionID: "ses_test", permission: "bash pwd", patterns: [], always: [], tool: { callID: "call_default_decisions" } },
        },
      });
      await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: "req_default_decisions", reply: "once" } } });

      await expect(readDecisionRecords(defaults.decisions)).resolves.toMatchObject([
        { requestID: "req_default_decisions", callID: "call_default_decisions" },
      ]);
      await expect(readFile(relativeDecisionsPath, "utf8")).rejects.toThrow();
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe("permission decision capture", () => {
  it("writes one decision record when an asked permission receives its reply", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-decisions-"));
    const decisionsPath = join(dir, "decisions.log");
    const plugin = await PermissionCanonicalizerPlugin(
      {} as never,
      {
        homedir: HOME,
        auditLogPath: join(dir, "audit.log"),
        debugLogPath: join(dir, "debug.log"),
        decisionsLogPath: decisionsPath,
      },
    );
    const hooks = plugin as PluginHooks;

    await hooks.event({
      event: {
        id: "outer-event-id",
        type: "permission.asked",
        properties: {
          id: "req_1",
          sessionID: "ses_test",
          permission: "bash ~/workspace/tools/foo.sh",
          patterns: ["/home/example/workspace/tools/foo.sh"],
          always: ["/home/example/workspace/tools/foo.sh*"],
          tool: { messageID: "msg_1", callID: "call_1" },
        },
      },
    });
    await hooks.event({
      event: {
        id: "reply-event-id",
        type: "permission.replied",
        properties: { sessionID: "ses_test", requestID: "req_1", reply: "once" },
      },
    });

    const records = await readDecisionRecords(decisionsPath);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      sessionID: "ses_test",
      callID: "call_1",
      requestID: "req_1",
      permission: "bash ~/workspace/tools/foo.sh",
      patterns: ["/home/example/workspace/tools/foo.sh"],
      always: ["/home/example/workspace/tools/foo.sh*"],
      reply: "once",
    });
    expect(records[0]?.ts).toEqual(expect.any(String));
    expect(records[0]?.askedTs).toEqual(expect.any(String));
    expect(String(records[0]?.askedTs) <= String(records[0]?.ts)).toBe(true);
  });

  it("correlates multiple pending asks by requestID while preserving each callID", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-decisions-"));
    const decisionsPath = join(dir, "decisions.log");
    const plugin = await PermissionCanonicalizerPlugin(
      {} as never,
      {
        homedir: HOME,
        auditLogPath: join(dir, "audit.log"),
        debugLogPath: join(dir, "debug.log"),
        decisionsLogPath: decisionsPath,
      },
    );
    const hooks = plugin as PluginHooks;

    await hooks.event({
      event: {
        id: "outer-a",
        type: "permission.asked",
        properties: {
          id: "req_a",
          sessionID: "ses_test",
          permission: "bash ~/a.sh",
          patterns: ["/home/example/a.sh"],
          always: [],
          tool: { callID: "call_a" },
        },
      },
    });
    await hooks.event({
      event: {
        id: "outer-b",
        type: "permission.asked",
        properties: {
          id: "req_b",
          sessionID: "ses_test",
          permission: "bash ~/b.sh",
          patterns: ["/home/example/b.sh"],
          always: [],
          tool: { callID: "call_b" },
        },
      },
    });

    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: "req_b", reply: "always" } } });
    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: "req_a", reply: "reject" } } });

    const records = await readDecisionRecords(decisionsPath);
    expect(records).toMatchObject([
      { requestID: "req_b", callID: "call_b", reply: "always" },
      { requestID: "req_a", callID: "call_a", reply: "reject" },
    ]);
  });

  it("correlates duplicate request IDs by session without deleting another session's pending ask", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-decisions-"));
    const decisionsPath = join(dir, "decisions.log");
    const debugPath = join(dir, "debug.log");
    const hooks = await createPluginHooks({ decisionsLogPath: decisionsPath, debugLogPath: debugPath });

    await hooks.event({
      event: {
        type: "permission.asked",
        properties: {
          id: "req_dup",
          sessionID: "ses_a",
          permission: "bash ~/a.sh",
          patterns: [],
          always: [],
          tool: { callID: "call_a" },
        },
      },
    });
    await hooks.event({
      event: {
        type: "permission.asked",
        properties: {
          id: "req_dup",
          sessionID: "ses_b",
          permission: "bash ~/b.sh",
          patterns: [],
          always: [],
          tool: { callID: "call_b" },
        },
      },
    });

    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_a", requestID: "req_dup", reply: "once" } } });
    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_a", requestID: "req_dup", reply: "once" } } });
    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_b", requestID: "req_dup", reply: "reject" } } });

    await expect(readDecisionRecords(decisionsPath)).resolves.toMatchObject([
      { sessionID: "ses_a", requestID: "req_dup", callID: "call_a", reply: "once" },
      { sessionID: "ses_b", requestID: "req_dup", callID: "call_b", reply: "reject" },
    ]);
    await expect(readFile(debugPath, "utf8")).resolves.toContain("permission replied without pending ask: requestID=req_dup");
  });

  it("records a null callID when the asked event has no tool", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-decisions-"));
    const decisionsPath = join(dir, "decisions.log");
    const debugPath = join(dir, "debug.log");
    const hooks = await createPluginHooks({ decisionsLogPath: decisionsPath, debugLogPath: debugPath });

    await hooks.event({
      event: {
        type: "permission.asked",
        properties: { id: "req_no_tool", sessionID: "ses_test", permission: "bash pwd", patterns: [], always: [] },
      },
    });
    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: "req_no_tool", reply: "once" } } });

    await expect(readDecisionRecords(decisionsPath)).resolves.toMatchObject([{ requestID: "req_no_tool", callID: null }]);
    await expect(readFile(debugPath, "utf8")).resolves.toContain("permission asked missing callID: requestID=req_no_tool");
  });

  it("ignores orphan replies without writing a decision record", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-decisions-"));
    const decisionsPath = join(dir, "decisions.log");
    const hooks = await createPluginHooks({ decisionsLogPath: decisionsPath });

    await expect(
      hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: "unknown", reply: "once" } } }),
    ).resolves.toBeUndefined();

    await expect(readDecisionRecords(decisionsPath)).resolves.toEqual([]);
  });

  it("evicts the oldest pending ask when the FIFO cap is exceeded", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-decisions-"));
    const decisionsPath = join(dir, "decisions.log");
    const debugPath = join(dir, "debug.log");
    const hooks = await createPluginHooks({ decisionsLogPath: decisionsPath, debugLogPath: debugPath, __decisionPendingLimit: 1 });

    await hooks.event({
      event: {
        type: "permission.asked",
        properties: { id: "req_old", sessionID: "ses_test", permission: "bash old", patterns: [], always: [], tool: { callID: "call_old" } },
      },
    });
    await hooks.event({
      event: {
        type: "permission.asked",
        properties: { id: "req_new", sessionID: "ses_test", permission: "bash new", patterns: [], always: [], tool: { callID: "call_new" } },
      },
    });

    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: "req_old", reply: "once" } } });
    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: "req_new", reply: "once" } } });

    await expect(readDecisionRecords(decisionsPath)).resolves.toMatchObject([
      { requestID: "req_new", callID: "call_new" },
    ]);
    await expect(readFile(debugPath, "utf8")).resolves.toContain("permission asked evicted: requestID=req_old askedTs=");
  });

  it("swallows decision append failures and continues canonicalizing commands", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-decisions-"));
    const blockingFile = join(dir, "not-a-directory");
    const auditPath = join(dir, "audit.log");
    const debugPath = join(dir, "debug.log");
    const decisionsPath = join(blockingFile, "decisions.log");
    await writeFile(blockingFile, "blocks directory creation", "utf8");
    const plugin = await PermissionCanonicalizerPlugin(
      {} as never,
      {
        homedir: HOME,
        auditLogPath: auditPath,
        debugLogPath: debugPath,
        decisionsLogPath: decisionsPath,
      },
    );
    const hooks = plugin as PluginHooks;

    await hooks.event({
      event: {
        type: "permission.asked",
        properties: { id: "req_fail", sessionID: "ses_test", permission: "bash ~/workspace/tools/foo.sh", patterns: [], always: [], tool: { callID: "call_fail" } },
      },
    });
    await expect(
      hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: "req_fail", reply: "once" } } }),
    ).resolves.toBeUndefined();
    await expect(readFile(debugPath, "utf8")).resolves.toContain("permission decision event failed: ENOTDIR");

    await unlink(blockingFile);
    await makeDir(blockingFile);
    await expect(
      hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: "req_fail", reply: "once" } } }),
    ).resolves.toBeUndefined();
    await expect(
      hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: "req_fail", reply: "once" } } }),
    ).resolves.toBeUndefined();
    await expect(readDecisionRecords(decisionsPath)).resolves.toMatchObject([
      { requestID: "req_fail", callID: "call_fail" },
    ]);

    const output = { args: { command: "~/workspace/tools/foo.sh" } };
    await hooks["tool.execute.before"]({ tool: "bash", sessionID: "ses_test", callID: "call_test" }, output);

    expect(output.args.command).toBe(homePath("workspace", "tools", "foo.sh"));
    await expect(readFile(auditPath, "utf8")).resolves.toContain(homePath("workspace", "tools", "foo.sh"));
  });

  it("guards malformed permission event properties without throwing", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-decisions-"));
    const decisionsPath = join(dir, "decisions.log");
    const hooks = await createPluginHooks({ decisionsLogPath: decisionsPath });

    await expect(
      hooks.event({ event: { type: "permission.asked", properties: { id: "req_bad", sessionID: "ses_test", permission: "bash pwd", patterns: "bad", always: 42 } } }),
    ).resolves.toBeUndefined();
    await expect(
      hooks.event({ event: { type: "permission.replied", properties: { requestID: 42, reply: "once" } } }),
    ).resolves.toBeUndefined();
    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: "req_bad", reply: "surprise" } } });

    await expect(readDecisionRecords(decisionsPath)).resolves.toMatchObject([
      { requestID: "req_bad", patterns: [], always: [], reply: "surprise" },
    ]);
  });

  it("normalizes unserializable replies without dropping decision records", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-decisions-"));
    const decisionsPath = join(dir, "decisions.log");
    const hooks = await createPluginHooks({ decisionsLogPath: decisionsPath });
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const throwingToJSON = { toJSON() { throw new Error("nope"); } };
    const cases: Array<{ requestID: string; reply: unknown; expected: unknown; expectString?: boolean }> = [
      { requestID: "req_undefined", reply: undefined, expected: null },
      { requestID: "req_bigint", reply: 10n, expected: "10" },
      { requestID: "req_infinity", reply: Infinity, expected: null },
      { requestID: "req_circular", reply: circular, expected: undefined, expectString: true },
      { requestID: "req_throwing_tojson", reply: throwingToJSON, expected: undefined, expectString: true },
      { requestID: "req_symbol", reply: Symbol("reply"), expected: null },
      { requestID: "req_function", reply: () => "reply", expected: null },
    ];

    for (const testCase of cases) {
      await hooks.event({
        event: {
          type: "permission.asked",
          properties: { id: testCase.requestID, sessionID: "ses_test", permission: "bash pwd", patterns: [], always: [], tool: { callID: testCase.requestID } },
        },
      });
      await expect(
        hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_test", requestID: testCase.requestID, reply: testCase.reply } } }),
      ).resolves.toBeUndefined();
    }

    const records = await readDecisionRecords(decisionsPath);
    expect(records).toHaveLength(cases.length);
    for (const testCase of cases) {
      const record = records.find((candidate) => candidate.requestID === testCase.requestID);
      expect(record).toBeDefined();
      expect(Object.keys(record ?? {})).toContain("reply");
      if (testCase.expectString) {
        expect(typeof record?.reply).toBe("string");
      } else {
        expect(record?.reply).toBe(testCase.expected);
      }
    }
  });

  it("ignores non-permission event types", async () => {
    const dir = await mkdtemp(join(tmpdir(), "permission-canon-decisions-"));
    const decisionsPath = join(dir, "decisions.log");
    const hooks = await createPluginHooks({ decisionsLogPath: decisionsPath });

    await expect(
      hooks.event({ event: { type: "session.updated", properties: { sessionID: "ses_test" } } }),
    ).resolves.toBeUndefined();

    await expect(readDecisionRecords(decisionsPath)).resolves.toEqual([]);
  });
});

describe("package entrypoint shape", () => {
  it("exports a server-keyed default object", () => {
    expect(defaultExport.server).toBe(PermissionCanonicalizerPlugin);
  });
});
