import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const launcher = join(repoRoot, "test", "run-isolated.mjs");

// Each launcher run gets its own parent TMPDIR so the test can prove the
// launcher removed exactly the root it created.
async function launcherParent(): Promise<string> {
  return mkdtemp(join(tmpdir(), "launcher-parent-"));
}

const signalChild = `
for (const name of ["SIGINT", "SIGTERM"]) {
  process.on(name, () => { process.stdout.write("child-got-" + name + "\\n"); process.exit(42); });
}
process.stdout.write("ready\\n");
setInterval(() => {}, 1000);
`;

function runUntilSignal(parent: string, signal: NodeJS.Signals): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [launcher, process.execPath, "-e", signalChild], {
      cwd: repoRoot,
      env: { ...process.env, TMPDIR: parent },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`launcher did not exit; stdout=${stdout}`));
    }, 10_000);
    child.stdout.on("data", (chunk: Buffer) => {
      const before = stdout;
      stdout += chunk.toString();
      if (!before.includes("ready") && stdout.includes("ready")) child.kill(signal);
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout });
    });
  });
}

describe("isolated test launcher", () => {
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    it(`forwards the original ${signal} to the child and removes its root`, async () => {
      const parent = await launcherParent();
      const result = await runUntilSignal(parent, signal);

      expect(result.stdout).toContain(`child-got-${signal}`);
      expect(result.code).toBe(42);
      await expect(readdir(parent)).resolves.toEqual([]);
    });
  }

  it("reports a child that fails to start with exit 127 and still removes its root", async () => {
    const parent = await launcherParent();
    const result = spawnSync(process.execPath, [launcher, "command-normalizer-no-such-command"], {
      cwd: repoRoot,
      env: { ...process.env, TMPDIR: parent },
      encoding: "utf8",
      timeout: 10_000,
    });

    expect(result.status).toBe(127);
    expect(result.stderr).toContain("failed to start command-normalizer-no-such-command");
    await expect(readdir(parent)).resolves.toEqual([]);
  });

  it("maps a child killed by a signal to 128 + signal number", async () => {
    const parent = await launcherParent();
    const result = spawnSync(process.execPath, [launcher, process.execPath, "-e", "process.kill(process.pid, 'SIGTERM')"], {
      cwd: repoRoot,
      env: { ...process.env, TMPDIR: parent },
      encoding: "utf8",
      timeout: 10_000,
    });

    expect(result.status).toBe(128 + 15);
    await expect(readdir(parent)).resolves.toEqual([]);
  });

  it("passes the child's exit code through", async () => {
    const parent = await launcherParent();
    const result = spawnSync(process.execPath, [launcher, process.execPath, "-e", "process.exit(7)"], {
      cwd: repoRoot,
      env: { ...process.env, TMPDIR: parent },
      encoding: "utf8",
      timeout: 10_000,
    });

    expect(result.status).toBe(7);
    await expect(readdir(parent)).resolves.toEqual([]);
  });
});
