import { mkdtemp, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// Deterministic filesystem failure injection for createIsolationRoot's
// post-mkdtemp initialization. Only the named operation fails, only while armed.
const inject = vi.hoisted(() => ({ fail: null as null | "mkdir" | "writeFile" }));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  const injected = (name: "mkdir" | "writeFile") =>
    (async (...args: unknown[]) => {
      if (inject.fail === name) throw Object.assign(new Error(`EIO: injected ${name} failure`), { code: "EIO" });
      return (actual[name] as (...a: unknown[]) => Promise<unknown>)(...args);
    }) as never;
  const mocked = { ...actual, mkdir: injected("mkdir"), writeFile: injected("writeFile") };
  return { ...mocked, default: mocked };
});

// The worker setup file already imported isolated-env.mjs with the real fs;
// reset the registry so this import binds to the mocked module.
vi.resetModules();
const { createIsolationRoot } = await import("./isolated-env.mjs");

afterEach(() => {
  inject.fail = null;
});

describe("createIsolationRoot", () => {
  for (const operation of ["mkdir", "writeFile"] as const) {
    it(`removes only its own root when ${operation} fails after the root was created`, async () => {
      const parent = await mkdtemp(join(tmpdir(), "isolation-root-parent-"));
      await writeFile(join(parent, "sentinel"), "not owned by the helper", "utf8");
      inject.fail = operation;

      await expect(createIsolationRoot(parent)).rejects.toThrow(`injected ${operation} failure`);

      inject.fail = null;
      await expect(readdir(parent)).resolves.toEqual(["sentinel"]);
    });
  }

  it("returns a complete layout under the parent when initialization succeeds", async () => {
    const parent = await mkdtemp(join(tmpdir(), "isolation-root-parent-"));

    const layout = await createIsolationRoot(parent);

    expect(await readdir(parent)).toHaveLength(1);
    expect((await readdir(layout.root)).sort()).toEqual(["home", "npm", "tmp", "xdg"]);
  });
});
