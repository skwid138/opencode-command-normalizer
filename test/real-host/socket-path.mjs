// Unix socket pathname guard for the preflight canary socket (Amendment A2).
//
// Darwin's sockaddr_un.sun_path holds 104 bytes including the terminating NUL,
// so the harness uses a conservative limit of 103 UTF-8 bytes for the
// pathname. This is a Darwin harness limit, NOT a portable Unix claim.
//
// The same constants drive both runtime construction (mkdtemp prefix + socket
// file name) and the gate forecast, so the two cannot drift. The forecast
// assumes Node's mkdtemp appends exactly six characters; it is not the sole
// proof: runtime re-checks the actual path before the first preflight listener.
import { join } from "node:path";

export const CANARY_PREFIX = "rh-canary-";
export const CANARY_SUFFIX_LENGTH = 6;
export const FORBIDDEN_SOCKET_NAME = "forbidden.sock";
export const DARWIN_SOCKET_PATH_MAX_BYTES = 103;

/** The actual canary socket path inside a created canary directory. */
export function canarySocketPath(canaryDir) {
  return join(canaryDir, FORBIDDEN_SOCKET_NAME);
}

/** The canary socket path runtime will construct under a canonical canary root. */
export function forecastCanarySocketPath(canaryRoot) {
  return canarySocketPath(join(canaryRoot, `${CANARY_PREFIX}${"X".repeat(CANARY_SUFFIX_LENGTH)}`));
}

/** Null when the pathname fits the Darwin harness limit; otherwise a plain problem string. */
export function socketPathProblem(path) {
  if (typeof path !== "string") return `Unix socket path is not a string: ${String(path)}`;
  if (path.includes("\0")) return `Unix socket path contains NUL: ${JSON.stringify(path)}`;
  const bytes = Buffer.byteLength(path, "utf8");
  if (bytes > DARWIN_SOCKET_PATH_MAX_BYTES) {
    return `Unix socket path is ${bytes} UTF-8 bytes; the Darwin harness limit is ${DARWIN_SOCKET_PATH_MAX_BYTES} (sun_path holds 104 including the terminating NUL): ${path}`;
  }
  return null;
}
