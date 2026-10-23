import { spawnSync } from "node:child_process";
import { stat } from "node:fs/promises";
import { homedir, tmpdir, userInfo } from "node:os";
import { dirname, isAbsolute, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { PermissionCanonicalizerPlugin, resolveDefaultLogPaths } from "../src/index";

const ROOT_VAR = "COMMAND_NORMALIZER_TEST_ROOT";
const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const vitestBin = join(repoRoot, "node_modules", "vitest", "vitest.mjs");

function isInside(path: string | undefined, root: string): boolean {
  if (!path) return false;
  const rel = relative(root, path);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

describe("test environment isolation", () => {
  it("runs with a disposable root owning HOME, all four XDG paths, and temp paths", () => {
    const root = process.env[ROOT_VAR];
    expect(root, `${ROOT_VAR} must be set by the test launcher`).toEqual(expect.any(String));
    const owned = root as string;

    expect(isInside(homedir(), owned)).toBe(true);
    expect(isInside(process.env.HOME, owned)).toBe(true);
    for (const name of ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"]) {
      expect(isInside(process.env[name], owned), name).toBe(true);
    }
    expect(isInside(tmpdir(), owned)).toBe(true);
    for (const name of ["TMPDIR", "TMP", "TEMP"]) {
      expect(isInside(process.env[name], owned), name).toBe(true);
    }
  });

  it("clears inherited OpenCode configuration overrides", () => {
    const leaked = Object.keys(process.env).filter((name) => /^OPENCODE/i.test(name));
    expect(leaked).toEqual([]);
  });

  it("refuses to start vitest at config load when the launcher root is missing", () => {
    const env = { ...process.env };
    delete env[ROOT_VAR];
    const result = spawnSync(process.execPath, [vitestBin, "run", "test/isolation.test.ts", "--testNamePattern", "disposable root"], {
      cwd: repoRoot,
      env,
      encoding: "utf8",
      timeout: 20_000,
    });

    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain("Refusing to run tests without environment isolation");
  });

  it("keeps omitted default audit, debug, and decision log paths inside the fixture", async () => {
    const root = process.env[ROOT_VAR] as string;
    const realUserHome = userInfo().homedir;
    const defaults = resolveDefaultLogPaths(process.env);

    for (const path of Object.values(defaults)) {
      expect(isInside(path, root)).toBe(true);
      expect(isInside(path, realUserHome)).toBe(false);
    }

    await PermissionCanonicalizerPlugin({} as never, undefined);

    await expect(stat(dirname(defaults.decisions))).resolves.toMatchObject({});
    expect(isInside(dirname(defaults.decisions), process.env.XDG_DATA_HOME as string)).toBe(true);
  });

  it("propagates the isolated environment to child processes", () => {
    const probe = spawnSync(
      process.execPath,
      [
        "-e",
        "const os=require('node:os');process.stdout.write(JSON.stringify({home:os.homedir(),tmp:os.tmpdir(),env:process.env}))",
      ],
      { encoding: "utf8", timeout: 10_000 },
    );
    expect(probe.status).toBe(0);
    const seen = JSON.parse(probe.stdout) as { home: string; tmp: string; env: Record<string, string> };
    const root = process.env[ROOT_VAR] as string;

    expect(seen.env[ROOT_VAR]).toBe(root);
    expect(isInside(seen.home, root)).toBe(true);
    expect(isInside(seen.tmp, root)).toBe(true);
    for (const name of ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"]) {
      expect(isInside(seen.env[name], root), name).toBe(true);
    }
    expect(Object.keys(seen.env).filter((name) => /^OPENCODE/i.test(name))).toEqual([]);
    expect(isInside(seen.env.npm_config_userconfig, root)).toBe(true);
    expect(isInside(seen.env.npm_config_cache, root)).toBe(true);
  });
});
