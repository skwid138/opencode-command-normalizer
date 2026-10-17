import { defineConfig } from "vitest/config";

import { assertIsolated } from "./test/isolated-env.mjs";

// Fail before any test module (or anything that resolves home/XDG/temp paths)
// is imported when tests are not launched through test/run-isolated.mjs.
assertIsolated();

export default defineConfig({
  test: {
    globals: false,
    setupFiles: ["./test/setup-isolation.mjs"],
    typecheck: {
      enabled: true,
      include: ["src/**/*.test-d.ts"],
      tsconfig: "./tsconfig.json",
    },
  },
});
