import { createHash } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";

import { PACKAGE_NAME, packageCachePath, readPackedManifest, stagePackage, verifyStagedPackage } from "./package-stage.mjs";

const created: string[] = [];
afterEach(async () => {
  for (const dir of created.splice(0)) await rm(dir, { recursive: true, force: true });
});
async function scratch(): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "rh-pkg-")));
  created.push(dir);
  return dir;
}

function header(name: string, size: number, type = "0"): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100);
  h.write("0000644\0", 100);
  h.write(size.toString(8).padStart(11, "0") + "\0", 124);
  h.write("        ", 148);
  h.write(type, 156);
  h.write("ustar\0", 257);
  h.write("00", 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return h;
}
function npmTarball(files: Record<string, string>, extra: Array<[string, string]> = []): Buffer {
  const parts: Buffer[] = [];
  for (const [name, text] of Object.entries(files)) {
    const data = Buffer.from(text);
    parts.push(header(`package/${name}`, data.length), data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  for (const [name, type] of extra) parts.push(header(name, 0, type));
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const MANIFEST = JSON.stringify({ name: PACKAGE_NAME, version: "0.1.0" });

async function writeTarball(dir: string, files: Record<string, string>, extra: Array<[string, string]> = []) {
  const bytes = npmTarball(files, extra);
  const path = join(dir, "pkg.tgz");
  await writeFile(path, bytes);
  return { path, sha256: sha(bytes) };
}

describe("package cache layouts (internal fixture layouts, not public install proof)", () => {
  it("places V1 under packages/<spec>/node_modules/<name> and V2 under npm/<spec>/<generation>/node_modules/<name>", () => {
    expect(packageCachePath({ family: "v1", cacheRoot: "/c", specDir: "spec" })).toBe(`/c/packages/spec/node_modules/${PACKAGE_NAME}`);
    expect(packageCachePath({ family: "v2", cacheRoot: "/c", specDir: "spec", generation: "3" })).toBe(`/c/npm/spec/3/node_modules/${PACKAGE_NAME}`);
    expect(() => packageCachePath({ family: "v2", cacheRoot: "/c", specDir: "spec", generation: "x" })).toThrow(/generation/);
    expect(() => packageCachePath({ family: "v1", cacheRoot: "/c", specDir: "../escape" })).toThrow(/specDir/);
  });
});

describe("package staging", () => {
  it("stages the exact hashed tarball bytes and verifies identity by file content hashes", async () => {
    const dir = await scratch();
    const tarball = await writeTarball(dir, { "package.json": MANIFEST, "dist/index.js": "export default 1;\n" });
    const cacheRoot = join(dir, "cache");

    const staged = await stagePackage({ tarballPath: tarball.path, tarballSha256: tarball.sha256, family: "v1", cacheRoot, specDir: "spec" });

    expect(staged.tarballSha256).toBe(tarball.sha256);
    expect(await readFile(join(staged.packageDir, "dist", "index.js"), "utf8")).toBe("export default 1;\n");
    await expect(verifyStagedPackage({ packageDir: staged.packageDir, tarballPath: tarball.path, tarballSha256: tarball.sha256 })).resolves.toMatchObject({
      ok: true,
    });
  });

  it("refuses a tarball whose bytes do not match the recorded hash", async () => {
    const dir = await scratch();
    const tarball = await writeTarball(dir, { "package.json": MANIFEST });
    await expect(
      stagePackage({ tarballPath: tarball.path, tarballSha256: "0".repeat(64), family: "v1", cacheRoot: join(dir, "c"), specDir: "s" }),
    ).rejects.toThrow(/hash mismatch/);
  });

  it("refuses link entries and a manifest for a different package", async () => {
    const dir = await scratch();
    const linked = await writeTarball(dir, { "package.json": MANIFEST }, [["package/evil", "2"]]);
    await expect(stagePackage({ tarballPath: linked.path, tarballSha256: linked.sha256, family: "v1", cacheRoot: join(dir, "c"), specDir: "s" })).rejects.toThrow(
      /link entry/,
    );
    const other = await writeTarball(dir, { "package.json": JSON.stringify({ name: "other", version: "0.1.0" }) });
    await expect(stagePackage({ tarballPath: other.path, tarballSha256: other.sha256, family: "v1", cacheRoot: join(dir, "d"), specDir: "s" })).rejects.toThrow(
      /package name/,
    );
  });

  it("detects a same-version package whose content differs (version alone is not identity)", async () => {
    const dir = await scratch();
    const tarball = await writeTarball(dir, { "package.json": MANIFEST, "dist/index.js": "A" });
    const staged = await stagePackage({ tarballPath: tarball.path, tarballSha256: tarball.sha256, family: "v2", cacheRoot: join(dir, "c"), specDir: "s", generation: "0" });

    await writeFile(join(staged.packageDir, "dist", "index.js"), "B");
    await writeFile(join(staged.packageDir, "extra.js"), "C");

    const result = await verifyStagedPackage({ packageDir: staged.packageDir, tarballPath: tarball.path, tarballSha256: tarball.sha256 });
    expect(result.ok).toBe(false);
    expect(result.problems.join("\n")).toMatch(/dist\/index.js/);
    expect(result.problems.join("\n")).toMatch(/extra.js/);
  });
});

describe("hash-verified packed manifest -> exact V2 plugin spec", () => {
  it("derives <name>@<exact version> only from verified tarball bytes", async () => {
    const dir = await scratch();
    const tarball = await writeTarball(dir, { "package.json": JSON.stringify({ name: PACKAGE_NAME, version: "0.1.0" }) });
    await expect(readPackedManifest({ tarballPath: tarball.path, tarballSha256: tarball.sha256 })).resolves.toEqual({
      name: PACKAGE_NAME,
      version: "0.1.0",
      spec: `${PACKAGE_NAME}@0.1.0`,
    });
    const pre = await writeTarball(await scratch(), { "package.json": JSON.stringify({ name: PACKAGE_NAME, version: "1.2.3-rc.1+build.5" }) });
    await expect(readPackedManifest({ tarballPath: pre.path, tarballSha256: pre.sha256 })).resolves.toMatchObject({ spec: `${PACKAGE_NAME}@1.2.3-rc.1+build.5` });
  });

  it.each([
    ["^0.1.0"], ["latest"], ["0.1"], ["01.2.3"], ["0.1.0 || 0.2.0"], [""], [7],
    ["1.2.3-01"], ["1.2.3-0.01"], ["1.2.3-alpha.00"], ["1.2.3\n"], ["1.2.3\r\n"], [" 1.2.3"], ["v1.2.3"], ["1.2.3-"], ["1.2.3+"], ["1.2.3-a..b"], ["1.2.3+b..c"], ["1.2.3-α"], ["9007199254740992.0.0"],
  ])("refuses non-exact version %j", async (version) => {
    const tarball = await writeTarball(await scratch(), { "package.json": JSON.stringify({ name: PACKAGE_NAME, version }) });
    await expect(readPackedManifest({ tarballPath: tarball.path, tarballSha256: tarball.sha256 })).rejects.toThrow(/exact version/);
  });

  it.each([["1.2.3-0"], ["1.2.3-0a"], ["1.2.3-alpha.10"], ["1.2.3-x-y.7"], ["1.2.3+001"], ["1.2.3-rc.1+build.010"], ["10.20.30"], ["9007199254740991.0.0"]])(
    "accepts valid exact SemVer boundary control %j",
    async (version) => {
      const tarball = await writeTarball(await scratch(), { "package.json": JSON.stringify({ name: PACKAGE_NAME, version }) });
      await expect(readPackedManifest({ tarballPath: tarball.path, tarballSha256: tarball.sha256 })).resolves.toMatchObject({ version, spec: `${PACKAGE_NAME}@${version}` });
    },
  );

  it("refuses a missing version, a different package, malformed JSON, and changed bytes", async () => {
    const missing = await writeTarball(await scratch(), { "package.json": JSON.stringify({ name: PACKAGE_NAME }) });
    await expect(readPackedManifest({ tarballPath: missing.path, tarballSha256: missing.sha256 })).rejects.toThrow(/exact version/);
    const other = await writeTarball(await scratch(), { "package.json": JSON.stringify({ name: "other", version: "1.0.0" }) });
    await expect(readPackedManifest({ tarballPath: other.path, tarballSha256: other.sha256 })).rejects.toThrow(/package name/);
    const broken = await writeTarball(await scratch(), { "package.json": "{not json" });
    await expect(readPackedManifest({ tarballPath: broken.path, tarballSha256: broken.sha256 })).rejects.toThrow(/package.json/);
    const good = await writeTarball(await scratch(), { "package.json": MANIFEST });
    await expect(readPackedManifest({ tarballPath: good.path, tarballSha256: "0".repeat(64) })).rejects.toThrow(/hash mismatch/);
  });
});
