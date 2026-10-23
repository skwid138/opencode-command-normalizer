import { spawnSync } from "node:child_process";
import { mkdtemp, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const repoRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const cli = join(repoRoot, "test", "real-host", "run.mjs");
const created: string[] = [];
afterEach(async () => {
  for (const dir of created.splice(0)) await rm(dir, { recursive: true, force: true });
});

function run(args: string[]) {
  return spawnSync(process.execPath, [cli, ...args], { cwd: repoRoot, encoding: "utf8", timeout: 15_000 });
}

describe("real-host runner CLI", () => {
  it("is closed by default: prints NOT EXECUTED with the gates and unverified contracts, exits 2", () => {
    const result = run([]);
    expect(result.status).toBe(2);
    expect(result.stdout).toMatch(/NOT EXECUTED/);
    expect(result.stdout).toMatch(/Gate 2/);
    expect(result.stdout).toMatch(/Gate 3/);
    expect(result.stdout).toMatch(/v2\.providerConfig/);
  });

  it("prints usage with --help", () => {
    const result = run(["--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/--manifest/);
  });

  it("refuses an unreadable manifest", () => {
    const result = run(["--manifest", "/nonexistent/real-host-manifest.json", "--check"]);
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/cannot read manifest/);
  });

  it("lists gate problems for an unapproved manifest and creates nothing", async () => {
    const dir = await realpath(await mkdtemp(join(tmpdir(), "rh-cli-")));
    created.push(dir);
    const runRoot = join(dir, "runs");
    await writeFile(join(dir, "m.json"), JSON.stringify({ runRoot, canaryRoot: join(dir, "canary"), stagingRoot: join(dir, "staging"), rows: [] }));

    for (const mode of [["--check"], ["--execute"], ["--execute", "--pilot"]]) {
      const result = run(["--manifest", join(dir, "m.json"), ...mode]);
      expect(result.status, mode.join(" ")).toBe(2);
      expect(result.stdout).toMatch(/GATES CLOSED/);
      expect(result.stdout).toMatch(/gate2 approval/);
    }
    expect(await readdir(dir)).toEqual(["m.json"]);
  });

  it("requires an explicit mode once a manifest is given", async () => {
    const dir = await realpath(await mkdtemp(join(tmpdir(), "rh-cli-")));
    created.push(dir);
    await writeFile(join(dir, "m.json"), "{}");
    const result = run(["--manifest", join(dir, "m.json")]);
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/--check or --execute/);
  });
});
