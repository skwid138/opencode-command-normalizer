// Worker-side guard: runs before each test file's imports so no test module
// resolves home, XDG, or temp paths outside the launcher-owned root.
import { assertIsolated } from "./isolated-env.mjs";

assertIsolated();
