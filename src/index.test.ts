import { mkdtemp, readFile } from "node:fs/promises";
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

function homePath(...parts: string[]): string {
  return join(HOME, ...parts);
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
    });
  });

  it("falls back to homedir local share when XDG_DATA_HOME is unset", () => {
    expect(resolveDefaultLogPaths({}, HOME)).toEqual({
      audit: join(HOME, ".local", "share", LOG_SUBDIR, "audit.log"),
      debug: join(HOME, ".local", "share", LOG_SUBDIR, "debug.log"),
    });
  });

  it("falls back to homedir local share when XDG_DATA_HOME is an empty string", () => {
    expect(resolveDefaultLogPaths({ XDG_DATA_HOME: "" }, HOME)).toEqual({
      audit: join(HOME, ".local", "share", LOG_SUBDIR, "audit.log"),
      debug: join(HOME, ".local", "share", LOG_SUBDIR, "debug.log"),
    });
  });

  it("falls back to homedir local share when XDG_DATA_HOME is relative", () => {
    expect(resolveDefaultLogPaths({ XDG_DATA_HOME: "relative/data" }, HOME)).toEqual({
      audit: join(HOME, ".local", "share", LOG_SUBDIR, "audit.log"),
      debug: join(HOME, ".local", "share", LOG_SUBDIR, "debug.log"),
    });
  });

  it("normalizes an absolute XDG_DATA_HOME with a trailing slash", () => {
    expect(resolveDefaultLogPaths({ XDG_DATA_HOME: "/var/data/" }, HOME)).toEqual({
      audit: join("/var/data", LOG_SUBDIR, "audit.log"),
      debug: join("/var/data", LOG_SUBDIR, "debug.log"),
    });
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
});

describe("package entrypoint shape", () => {
  it("exports a server-keyed default object", () => {
    expect(defaultExport.server).toBe(PermissionCanonicalizerPlugin);
  });
});
