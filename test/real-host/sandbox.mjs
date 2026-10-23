// Candidate macOS sandbox profile and the preflight that must prove it before
// any host launch.
//
// STATUS: candidate. `sandbox-exec` is deprecated and whether a native profile
// is viable is unknown. The Mach services the host needs, and how the
// "localhost:<port>" rules treat IPv6 loopback and Unix sockets, are not
// proven. Passing unit tests here proves only how the profile text is built
// and how preflight evidence is judged — never that isolation is ready. The
// runtime gate requires a passing preflight on the real profile, and a failed
// preflight stops the run; nothing is relaxed to get past it.
import { isAbsolute, relative } from "node:path";

export const PROFILE_STATUS = "candidate";
export const SANDBOX_EXEC = "/usr/bin/sandbox-exec";

/** Read-only system locations a dynamically linked macOS binary is expected to need (candidate list). */
export const SYSTEM_READ_SUBPATHS = ["/System", "/usr/lib", "/usr/share", "/private/etc", "/Library/Preferences/Logging", "/private/var/db/timezone"];
export const DEVICE_LITERALS = ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/dtracehelper"];

const SAFE = /^[A-Za-z0-9_./@+-]+$/;

function safePath(value, label) {
  if (typeof value !== "string" || !isAbsolute(value)) throw new Error(`${label} must be an absolute path: ${value}`);
  if (!SAFE.test(value)) throw new Error(`unsafe characters in ${label}: ${JSON.stringify(value)}`);
  return value;
}

function isInside(path, root) {
  const rel = relative(root, path);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

export function candidateProfile({ fixtureRoot, executables, loopbackPorts, machServices }) {
  safePath(fixtureRoot, "fixture root");
  if (fixtureRoot.split("/").filter(Boolean).length < 2) throw new Error(`fixture root is too broad: ${fixtureRoot}`);
  if (!Array.isArray(machServices)) throw new Error("Mach services unresolved: the candidate profile cannot be generated (contract sandbox.machServices)");
  const exes = executables.map((exe) => safePath(exe, "executable"));
  for (const port of loopbackPorts) if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid loopback port: ${port}`);
  for (const service of machServices) if (typeof service !== "string" || !/^[A-Za-z0-9_.-]+$/.test(service)) throw new Error(`unsafe Mach service name: ${service}`);
  const lines = [
    "(version 1)",
    "(deny default)",
    "(allow process-fork)",
    "(allow signal (target same-sandbox))",
    "(allow sysctl-read)",
    ...exes.map((exe) => `(allow process-exec (literal "${exe}"))`),
    ...exes.map((exe) => `(allow file-read* (literal "${exe}"))`),
    `(allow file-read* ${SYSTEM_READ_SUBPATHS.map((path) => `(subpath "${path}")`).join(" ")})`,
    `(allow file-read-metadata (literal "/") (literal "/private") (literal "/private/var"))`,
    `(allow file-read* file-write* ${DEVICE_LITERALS.map((path) => `(literal "${path}")`).join(" ")})`,
    `(allow file-read* file-write* (subpath "${fixtureRoot}"))`,
    ...machServices.map((service) => `(allow mach-lookup (global-name "${service}"))`),
    ...loopbackPorts.flatMap((port) => [
      `(allow network-bind (local ip "localhost:${port}"))`,
      `(allow network-inbound (local ip "localhost:${port}"))`,
      `(allow network-outbound (remote ip "localhost:${port}"))`,
    ]),
  ];
  return `${lines.join("\n")}\n`;
}

export function sandboxArgv(profilePath, argv) {
  if (!isAbsolute(profilePath)) throw new Error(`sandbox profile path must be absolute: ${profilePath}`);
  return [SANDBOX_EXEC, "-f", profilePath, ...argv];
}

/** errno codes that count as a sandbox denial; anything else is infrastructure failure. */
export const DENIAL_CODES = Object.freeze(["EPERM", "EACCES"]);

/**
 * The preflight check list. Canary files live in a harness-created canary
 * root outside the fixture and contain only a generated token; secrets are
 * never probed. The provider positive control must reach the fresh fake
 * provider's identity endpoint and see its per-instance token.
 */
export function preflightPlan({ fixtureRoot, canaryRoot, provider, forbidden }) {
  if (isInside(canaryRoot, fixtureRoot) || isInside(fixtureRoot, canaryRoot)) throw new Error("canary root must be outside the fixture (and not contain it)");
  if (typeof provider?.token !== "string" || provider.token.length < 8) throw new Error("provider identity token is required");
  return [
    { id: "positive-read", kind: "positive", op: "read", target: `${fixtureRoot}/run/preflight-read` },
    { id: "positive-write", kind: "positive", op: "write", target: `${fixtureRoot}/run/preflight-write` },
    { id: "positive-provider", kind: "positive-identity", op: "http-get", target: provider.url, token: provider.token },
    { id: "canary-read", kind: "negative-file", op: "read", target: `${canaryRoot}/canary-read` },
    { id: "canary-write", kind: "negative-file", op: "write", target: `${canaryRoot}/canary-write` },
    { id: "forbidden-ipv4", kind: "negative-listener", op: "connect", target: `${forbidden.ipv4.host}:${forbidden.ipv4.port}` },
    { id: "forbidden-ipv6", kind: "negative-listener", op: "connect", target: `[${forbidden.ipv6.host}]:${forbidden.ipv6.port}` },
    { id: "forbidden-unix", kind: "negative-listener", op: "connect-unix", target: forbidden.unix.path },
  ];
}

const describeResult = (result) => JSON.stringify({ completed: result.completed, outcome: result.outcome, code: result.code, reason: result.reason });

/**
 * Judges preflight observations. A probe result is { completed, outcome:
 * "allowed" | "denied" | "error" | "infrastructure", code?, status?, body? }.
 * Only a completed probe that reports an expected denial code counts as a
 * denial; no result, unparseable output, a nonzero exit, a timeout, or an
 * unexpected errno is infrastructure failure and fails the check.
 */
export function evaluatePreflight(plan, observations) {
  const failures = [];
  for (const check of plan) {
    const observed = observations[check.id];
    if (!observed || !observed.sandboxed) {
      failures.push(`${check.id}: missing observation`);
      continue;
    }
    const sandboxed = observed.sandboxed;
    if (check.kind === "positive" || check.kind === "positive-identity") {
      if (sandboxed.completed !== true || sandboxed.outcome !== "allowed") {
        failures.push(`${check.id}: sandboxed operation was not allowed ${describeResult(sandboxed)}`);
        continue;
      }
      if (check.kind === "positive-identity") {
        let token = null;
        try {
          token = JSON.parse(sandboxed.body ?? "").token;
        } catch {
          token = null;
        }
        if (sandboxed.status !== 200) failures.push(`${check.id}: provider answered status ${sandboxed.status}, expected 200`);
        else if (token !== check.token) failures.push(`${check.id}: provider identity token does not match this run`);
      }
      continue;
    }
    if (!observed.control || observed.control.completed !== true || observed.control.outcome !== "allowed") {
      failures.push(`${check.id}: control could not reach the target, so a denial proves nothing ${describeResult(observed.control ?? {})}`);
    }
    if (sandboxed.completed !== true) failures.push(`${check.id}: probe did not complete (${sandboxed.reason ?? "unknown"}); infrastructure failure is not a denial`);
    else if (sandboxed.outcome === "allowed") failures.push(`${check.id}: sandbox allowed the operation`);
    else if (sandboxed.outcome !== "denied" || !DENIAL_CODES.includes(sandboxed.code)) failures.push(`${check.id}: ${describeResult(sandboxed)} is not an expected denial (${DENIAL_CODES.join("/")})`);
    if (check.kind === "negative-listener" && observed.listenerRequests !== 0) {
      failures.push(`${check.id}: listener received ${observed.listenerRequests ?? "unknown"} request(s) from the sandboxed probe`);
    }
  }
  return { ok: failures.length === 0, failures };
}
