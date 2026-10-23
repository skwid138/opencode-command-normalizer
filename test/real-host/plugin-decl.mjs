// Exact plugin-declaration remove/restore for lifecycle scenarios. Shared by
// the V1 (`plugin`) and V2 (`plugins`) adapters; never edits in place.
import { isDeepStrictEqual } from "node:util";

export function removeDeclaration(config, key, decl) {
  const list = Array.isArray(config[key]) ? config[key] : [];
  const matches = list.flatMap((item, index) => (isDeepStrictEqual(item, decl) ? [index] : []));
  if (matches.length !== 1) throw new Error(`expected exactly one matching ${key} declaration, found ${matches.length}`);
  const index = matches[0];
  return { config: { ...config, [key]: list.filter((_, i) => i !== index) }, index };
}

export function restoreDeclaration(config, key, decl, index) {
  const list = Array.isArray(config[key]) ? [...config[key]] : [];
  if (list.some((item) => isDeepStrictEqual(item, decl))) throw new Error(`${key} declaration is already present`);
  list.splice(index, 0, decl);
  return { ...config, [key]: list };
}

/** Source-verified serve argv for both hosts (contracts "launchArgv"), bound to an owned port. */
export function serveArgv(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`launch needs an owned port, got ${port}`);
  return ["serve", "--hostname", "127.0.0.1", "--port", String(port)];
}
