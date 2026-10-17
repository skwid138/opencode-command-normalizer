// Runtime gates. The real-host runner refuses to start anything until every
// gate passes. There is no automatic acquisition: no download, install, or
// staging happens here. Artifacts must already be staged (Gate 2, separately
// approved) at explicit paths with recorded hashes; the runner only verifies.
//
// Provenance is linked, not assumed: an archive row's staged binary digest must
// equal the digest of the reviewed member inside the plan-verified archive,
// and the daily row's digest must equal the approved installed source file.
// The runtime additionally requires a sandboxed version probe before scenarios.
import { createHash } from "node:crypto";
import { access, readFile, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";

import { MATRIX, limitsProblems, listTarGz, listZip, memberDigest, membersProblems, sha256File, tarCapFor, validateEntries, verifyStagedFile } from "./artifacts.mjs";
import { unreviewedContracts } from "./contracts.mjs";
import { EXTRA_ALLOWED_KEYS, HARNESS_SECRET_KEYS } from "./env.mjs";
import { PACKAGE_NAME, packageCachePath, readPackedManifest } from "./package-stage.mjs";
import { SANDBOX_EXEC } from "./sandbox.mjs";
import { forecastCanarySocketPath, socketPathProblem } from "./socket-path.mjs";

const nonEmpty = (value) => typeof value === "string" && value.trim() !== "";
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);

function inside(path, root) {
  const rel = relative(root, path);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

const defaultExists = async (path) => {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
};

/**
 * Canonical form of a possibly nonexistent absolute path: realpath of the
 * nearest existing ancestor plus the remaining components. `.`/`..` segments
 * are refused rather than interpreted.
 */
export async function canonicalPath(path) {
  if (typeof path !== "string" || !isAbsolute(path)) throw new Error(`path must be absolute: ${path}`);
  const parts = path.split(sep).filter(Boolean);
  if (parts.some((part) => part === "." || part === "..")) throw new Error(`path must not contain . or .. segments: ${path}`);
  const rest = [];
  let current = path.replace(/\/+$/, "") || "/";
  for (;;) {
    try {
      return join(await realpath(current), ...rest);
    } catch (error) {
      if (error?.code !== "ENOENT" || current === "/") throw error;
      rest.unshift(basename(current));
      current = dirname(current);
    }
  }
}

const V1_CACHE = { root: "{XDG_CACHE_HOME}/opencode", specDir: `${PACKAGE_NAME}@latest` };
const sri512 = (buffer) => `sha512-${createHash("sha512").update(buffer).digest("base64")}`;
const sha256 = (buffer) => createHash("sha256").update(buffer).digest("hex");

async function provenanceProblems(row, plan, binary, stagingRoot) {
  const problems = [];
  const provenance = row.provenance;
  if (!isRecord(provenance)) return { problems: [`${row.id}: provenance record missing`], record: null };
  if (plan.artifact.kind === "local-copy") {
    const source = provenance.source;
    if (!isRecord(source) || source.path !== plan.artifact.path) return { problems: [`${row.id}: provenance source must be the approved installed path ${plan.artifact.path}`], record: null };
    let actual = null;
    try {
      actual = await sha256File(source.path);
    } catch (error) {
      problems.push(`${row.id}: installed source unreadable: ${error.message}`);
    }
    if (actual && (actual !== source.sha256 || !binary || actual !== binary.sha256)) problems.push(`${row.id}: staged binary digest does not match the installed source digest`);
    return { problems, record: { kind: "installed-source", path: source.path, sha256: actual } };
  }
  const archive = provenance.archive;
  if (!isRecord(archive) || !nonEmpty(archive.path)) return { problems: [`${row.id}: provenance archive missing`], record: null };
  let buffer;
  try {
    const verifiedArchive = await verifyStagedFile({ path: archive.path, sha256: archive.sha256 ?? sha256(await readFile(archive.path)), root: stagingRoot });
    buffer = await readFile(verifiedArchive.path);
  } catch (error) {
    return { problems: [`${row.id}: provenance archive: ${error.message}`], record: null };
  }
  if (plan.artifact.kind === "zip") {
    if (sha256(buffer) !== plan.artifact.sha256) problems.push(`${row.id}: provenance archive sha256 is not the plan artifact`);
    if (plan.artifact.size !== undefined && buffer.length !== plan.artifact.size) problems.push(`${row.id}: provenance archive size ${buffer.length} is not the plan size ${plan.artifact.size}`);
  } else if (sri512(buffer) !== plan.artifact.integrity) problems.push(`${row.id}: provenance archive integrity is not the plan artifact`);
  if (problems.length > 0) return { problems, record: null };
  let entries;
  try {
    const schema = [...limitsProblems(provenance.limits), ...membersProblems(provenance.members)];
    if (schema.length > 0) return { problems: schema.map((problem) => `${row.id}: provenance ${problem}`), record: null };
    entries = plan.artifact.kind === "zip" ? listZip(buffer) : listTarGz(buffer, { maxTarBytes: tarCapFor(provenance.limits) });
    const full = validateEntries(entries, { limits: provenance.limits, members: provenance.members });
    if (!full.ok) return { problems: full.problems.map((problem) => `${row.id}: provenance archive: ${problem}`), record: null };
    if (!provenance.members.required.includes(provenance.member)) return { problems: [`${row.id}: provenance member ${provenance.member} is not a reviewed required member`], record: null };
    const digest = memberDigest({ kind: plan.artifact.kind, buffer, entries, name: provenance.member, limits: provenance.limits });
    if (!binary || digest !== binary.sha256) problems.push(`${row.id}: provenance: staged binary digest is not the digest of archive member ${provenance.member}`);
    return { problems, record: { kind: "archive-member", archiveSha256: sha256(buffer), member: provenance.member, memberSha256: digest } };
  } catch (error) {
    return { problems: [`${row.id}: provenance archive: ${error.message}`], record: null };
  }
}

export async function checkRuntimeGates(manifest, { platform = process.platform, arch = process.arch, realHome, exists = defaultExists, matrix = MATRIX, canonicalize = canonicalPath } = {}) {
  const problems = [];
  const verified = { node: null, tarball: null, packageSpec: null, rows: [], roots: {} };
  if (!isRecord(manifest)) {
    return { ok: false, problems: ["no run manifest: Gate 2 (exact downloads/staging) and Gate 3 (sandbox pilot/runtime) are not approved"], verified };
  }

  if (!nonEmpty(manifest.approvals?.gate2)) problems.push("missing gate2 approval reference (exact downloads and staging)");
  if (!nonEmpty(manifest.approvals?.gate3)) problems.push("missing gate3 approval reference (safety pilot and runtime)");
  if (platform !== "darwin" || manifest.platform?.os !== "darwin") problems.push(`platform must be darwin (host ${platform}, manifest ${manifest.platform?.os})`);
  if (arch !== "arm64" || manifest.platform?.arch !== "arm64") problems.push(`arch must be arm64 (host ${arch}, manifest ${manifest.platform?.arch}); verify the exact architecture before acquisition`);
  if (!(await exists(SANDBOX_EXEC))) problems.push(`${SANDBOX_EXEC} not found`);

  let home = null;
  if (realHome) {
    try {
      home = await canonicalize(realHome);
    } catch (error) {
      problems.push(`real home cannot be canonicalized: ${error.message}`);
    }
  }
  const roots = ["runRoot", "canaryRoot", "stagingRoot"];
  for (const key of roots) {
    try {
      const canonical = await canonicalize(manifest[key]);
      verified.roots[key] = canonical;
      if (home && inside(canonical, home)) problems.push(`${key} is inside the real home: ${manifest[key]} -> ${canonical}`);
    } catch (error) {
      problems.push(`${key}: ${error.message}`);
    }
  }
  for (let i = 0; i < roots.length; i += 1) {
    for (let j = i + 1; j < roots.length; j += 1) {
      const [a, b] = [verified.roots[roots[i]], verified.roots[roots[j]]];
      if (a && b && (inside(a, b) || inside(b, a))) problems.push(`${roots[i]} and ${roots[j]} overlap after canonicalization; roots must be disjoint`);
    }
  }
  if (verified.roots.canaryRoot) {
    // Amendment A2: forecast the preflight canary socket from the CANONICAL root, with the
    // same constants runtime uses. Not the sole proof: runtime re-checks the actual path.
    const socketProblem = socketPathProblem(forecastCanarySocketPath(verified.roots.canaryRoot));
    if (socketProblem) problems.push(`canaryRoot: forecast canary socket: ${socketProblem}`);
  }
  if (!nonEmpty(manifest.reportPath) || !isAbsolute(manifest.reportPath)) problems.push("reportPath must be an absolute path");

  const staged = async (label, entry) => {
    if (!entry || !nonEmpty(entry.path)) {
      problems.push(`${label}: no staged path`);
      return null;
    }
    if (nonEmpty(manifest.stagingRoot) && !inside(entry.path, manifest.stagingRoot)) {
      problems.push(`${label}: ${entry.path} is outside the staging root`);
      return null;
    }
    try {
      return await verifyStagedFile({ path: entry.path, sha256: entry.sha256, root: manifest.stagingRoot });
    } catch (error) {
      problems.push(`${label}: ${error.message}`);
      return null;
    }
  };
  verified.node = await staged("node executable", manifest.node);
  if (manifest.node && !nonEmpty(manifest.node.version)) problems.push("node executable: version not recorded");
  verified.tarball = await staged("packed tarball", manifest.tarball);
  if (verified.tarball) {
    // The exact V2 plugin spec comes only from the hash-verified packed manifest (Amendment A1).
    try {
      verified.packageSpec = await readPackedManifest({ tarballPath: verified.tarball.path, tarballSha256: verified.tarball.sha256 });
    } catch (error) {
      problems.push(`packed tarball: ${error.message}`);
    }
  }

  const rows = Array.isArray(manifest.rows) ? manifest.rows : [];
  if (rows.length === 0) problems.push("no matrix rows");
  for (const row of rows) {
    const plan = matrix.find((candidate) => candidate.id === row.id);
    if (!plan) {
      problems.push(`unknown matrix row ${row.id}`);
      continue;
    }
    if (row.launchArgv !== undefined) problems.push(`${row.id}: launchArgv is harness-owned (source-verified serve --hostname 127.0.0.1 --port); remove it from the manifest`);
    if (plan.family === "v1" && (row.cache?.root !== V1_CACHE.root || row.cache?.specDir !== V1_CACHE.specDir || row.cache?.generation !== undefined)) {
      problems.push(`${row.id}: cache must be the source-verified V1 layout ${V1_CACHE.root} + ${V1_CACHE.specDir}`);
    }
    if (plan.family === "v2" && verified.packageSpec && row.cache?.specDir !== verified.packageSpec.spec) {
      problems.push(`${row.id}: cache spec must be the exact packed spec ${verified.packageSpec.spec} (shared with the declaration and inventory target)`);
    }
    try {
      packageCachePath({ family: plan.family, cacheRoot: "/x", specDir: row.cache?.specDir, generation: row.cache?.generation });
      if (!nonEmpty(row.cache?.root)) throw new Error("cache root missing");
    } catch (error) {
      problems.push(`${row.id}: cache: ${error.message}`);
    }
    const binary = await staged(`${row.id} binary`, row.binary);
    const provenance = await provenanceProblems(row, plan, binary, manifest.stagingRoot);
    problems.push(...provenance.problems);
    verified.rows.push({ id: row.id, family: plan.family, version: plan.version, sourceCommit: plan.sourceCommit, binary, provenance: provenance.record });
  }

  const unreviewed = unreviewedContracts(manifest.reviewedContracts);
  if (unreviewed.length > 0) problems.push(`unreviewed contract(s): ${unreviewed.join(", ")}`);
  if (!Array.isArray(manifest.sandbox?.machServices)) problems.push("sandbox Mach services unresolved");
  const versionArgv = manifest.reviewedContracts?.["hosts.versionArgv"]?.value;
  if (!Array.isArray(versionArgv) || versionArgv.length === 0 || !versionArgv.every(nonEmpty) || versionArgv.includes("serve")) {
    problems.push("reviewed hosts.versionArgv value must be a non-empty argv that does not start a server");
  }
  for (const [family, extra] of Object.entries(manifest.hostEnv ?? {})) {
    for (const key of Object.keys(extra ?? {})) {
      if (!EXTRA_ALLOWED_KEYS.includes(key) || HARNESS_SECRET_KEYS[key] || key === "OPENCODE_CONFIG") problems.push(`hostEnv.${family}.${key} is not a manifest-settable key`);
    }
  }
  if (rows.some((row) => row.id === "v2")) {
    for (const key of ["providers", "model"]) if (manifest.v2?.[key] === undefined) problems.push(`missing reviewed v2.${key}`);
    const regions = manifest.v2?.dependencyRegions;
    const safeRegion = (region) => nonEmpty(region) && !isAbsolute(region) && !region.split("/").some((part) => part === ".." || part === "." || part === "");
    if (!Array.isArray(regions) || regions.length === 0 || !regions.every(safeRegion)) problems.push("reviewed v2.dependencyRegions must be non-empty safe relative paths under the fixture xdg dir");
  }
  return { ok: problems.length === 0, problems, verified };
}
