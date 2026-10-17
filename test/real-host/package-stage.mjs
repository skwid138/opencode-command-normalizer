// Stages the one hashed packed tarball into a fixture plugin cache and verifies
// staged identity by per-file content hash (never by version alone).
//
// The cache layouts are internal host fixture layouts observed in host source,
// not proof of how a public install behaves. The cache root and the spec
// directory name the host derives from a declaration are review-gated contract
// values (see contracts.mjs); this module only refuses unsafe values.
import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { gunzipSync } from "node:zlib";

import { listTarGz, tarCapFor, validateEntries } from "./artifacts.mjs";

export const PACKAGE_NAME = "@skwid138/opencode-command-normalizer";

/**
 * Exact SemVer 2.0.0 only (the specification's grammar, ASCII): MAJOR.MINOR.PATCH
 * without leading zeros; prerelease identifiers are numeric without leading
 * zeros or alphanumeric; build identifiers are alphanumeric (leading zeros
 * allowed). No ranges, tags, or `v` prefix. `$` without the `m` flag anchors at
 * the true end of input, so a trailing newline does not match.
 */
const NUMERIC = "0|[1-9]\\d*";
const PRERELEASE_ID = `(?:${NUMERIC}|\\d*[a-zA-Z-][0-9a-zA-Z-]*)`;
const BUILD_ID = "[0-9a-zA-Z-]+";
const EXACT_VERSION = new RegExp(
  `^(?:${NUMERIC})\\.(?:${NUMERIC})\\.(?:${NUMERIC})(?:-${PRERELEASE_ID}(?:\\.${PRERELEASE_ID})*)?(?:\\+${BUILD_ID}(?:\\.${BUILD_ID})*)?$`,
);

/** Limits for this repo's own packed tarball (we control its contents). */
export const PACKAGE_LIMITS = Object.freeze({ maxEntries: 200, maxExpandedBytes: 5_000_000, maxFileBytes: 2_000_000 });

const sha256 = (buffer) => createHash("sha256").update(buffer).digest("hex");

function safeSegment(value, label) {
  if (typeof value !== "string" || value === "" || value.startsWith("/") || value.split("/").some((part) => part === ".." || part === "." || part === "")) {
    throw new Error(`unsafe ${label}: ${JSON.stringify(value)}`);
  }
}

export function packageCachePath({ family, cacheRoot, specDir, generation }) {
  safeSegment(specDir, "specDir");
  if (family === "v1") return join(cacheRoot, "packages", specDir, "node_modules", PACKAGE_NAME);
  if (family === "v2") {
    if (!/^\d+$/.test(String(generation))) throw new Error(`V2 generation must be a non-negative integer: ${generation}`);
    return join(cacheRoot, "npm", specDir, String(generation), "node_modules", PACKAGE_NAME);
  }
  throw new Error(`unknown host family: ${family}`);
}

function tarballFiles(gzipped) {
  const entries = listTarGz(gzipped, { maxTarBytes: tarCapFor(PACKAGE_LIMITS) });
  // Our own tarball: every entry must sit under package/; identity is then checked file-by-file by hash.
  const allowed = entries.map((entry) => entry.name).filter((name) => name.startsWith("package/"));
  const validation = validateEntries(entries, { limits: PACKAGE_LIMITS, members: { required: ["package/package.json"], allowed } });
  const problems = [...validation.problems];
  for (const entry of entries) if (!entry.name.startsWith("package/")) problems.push(`entry outside package/: ${entry.name}`);
  if (problems.length > 0) throw new Error(`packed tarball rejected:\n- ${problems.join("\n- ")}`);
  const tar = gunzipSync(gzipped, { maxOutputLength: tarCapFor(PACKAGE_LIMITS) });
  const files = new Map();
  for (const entry of entries) {
    if (entry.type !== "file") continue;
    files.set(entry.name.slice("package/".length), tar.subarray(entry.dataOffset, entry.dataOffset + entry.size));
  }
  return files;
}

async function readTarball(tarballPath, tarballSha256) {
  const bytes = await readFile(tarballPath);
  const actual = sha256(bytes);
  if (actual !== tarballSha256) throw new Error(`tarball hash mismatch: expected ${tarballSha256}, got ${actual}`);
  return bytes;
}

/**
 * Reads package.json from the hash-verified packed tarball and derives the
 * exact V2 plugin spec `<name>@<exact version>`. The same spec is the V2
 * declaration, cache key, and inventory target; a bare name would let the V2
 * supervisor run an update check (Amendment A1).
 */
export async function readPackedManifest({ tarballPath, tarballSha256 }) {
  const files = tarballFiles(await readTarball(tarballPath, tarballSha256));
  let manifest;
  try {
    manifest = JSON.parse(files.get("package.json").toString("utf8"));
  } catch (error) {
    throw new Error(`packed package.json is not valid JSON: ${error.message}`);
  }
  if (manifest?.name !== PACKAGE_NAME) throw new Error(`unexpected package name in packed manifest: ${manifest?.name}`);
  const core = typeof manifest.version === "string" ? manifest.version.split(/[-+]/, 1)[0].split(".") : [];
  // npm's semver also refuses core components above Number.MAX_SAFE_INTEGER.
  if (typeof manifest.version !== "string" || !EXACT_VERSION.test(manifest.version) || core.some((part) => Number(part) > Number.MAX_SAFE_INTEGER)) {
    throw new Error(`packed manifest needs an exact version, got ${JSON.stringify(manifest.version)}`);
  }
  return { name: manifest.name, version: manifest.version, spec: `${manifest.name}@${manifest.version}` };
}

export async function stagePackage({ tarballPath, tarballSha256, family, cacheRoot, specDir, generation }) {
  const bytes = await readTarball(tarballPath, tarballSha256);
  const files = tarballFiles(bytes);
  const manifest = JSON.parse(files.get("package.json").toString("utf8"));
  if (manifest.name !== PACKAGE_NAME) throw new Error(`unexpected package name in tarball: ${manifest.name}`);
  const packageDir = packageCachePath({ family, cacheRoot, specDir, generation });
  for (const [rel, data] of files) {
    const dest = join(packageDir, rel);
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, data, { flag: "wx" });
  }
  return { packageDir, tarballSha256, manifestVersion: manifest.version, files: [...files.keys()].sort() };
}

async function listFiles(root) {
  const out = [];
  async function walk(dir) {
    for (const item of await readdir(dir, { withFileTypes: true })) {
      const full = join(dir, item.name);
      if (item.isDirectory()) await walk(full);
      else out.push(relative(root, full));
    }
  }
  await walk(root);
  return out.sort();
}

/** Compares the staged directory with the tarball file-by-file. */
export async function verifyStagedPackage({ packageDir, tarballPath, tarballSha256 }) {
  const files = tarballFiles(await readTarball(tarballPath, tarballSha256));
  const problems = [];
  const staged = await listFiles(packageDir);
  for (const rel of staged) if (!files.has(rel)) problems.push(`unexpected staged file: ${rel}`);
  for (const [rel, data] of files) {
    if (!staged.includes(rel)) problems.push(`missing staged file: ${rel}`);
    else if (sha256(await readFile(join(packageDir, rel))) !== sha256(data)) problems.push(`content mismatch: ${rel}`);
  }
  return { ok: problems.length === 0, problems, tarballSha256 };
}
