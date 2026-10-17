// Public entrypoint. Named exports are the stable V1 public API. The default
// export is one dual-host object: OpenCode V1 calls `server`, V2 calls `setup`.
import { PermissionCanonicalizerPlugin } from "./v1.js";
import { setup } from "./v2.js";

export {
  canonicalize,
  canonicalizeAndAudit,
  resolveDefaultLogPaths,
  splitCommandNodes,
  type AuditContext,
  type AuditRecord,
  type CanonicalizeOptions,
  type DecisionRecord,
} from "./core.js";
export { PermissionCanonicalizerPlugin };

export default {
  id: "skwid138.command-normalizer",
  server: PermissionCanonicalizerPlugin,
  setup,
};
