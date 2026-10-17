import { describe, expect, it } from "vitest";

import { CANARY_PREFIX, CANARY_SUFFIX_LENGTH, DARWIN_SOCKET_PATH_MAX_BYTES, FORBIDDEN_SOCKET_NAME, canarySocketPath, forecastCanarySocketPath, socketPathProblem } from "./socket-path.mjs";

// Pure path arithmetic: nothing here touches the filesystem or opens a socket.
const pathOfBytes = (bytes: number) => `/${"a".repeat(bytes - 1)}`;

describe("Unix socket pathname limit (Darwin harness limit, not a portable Unix claim)", () => {
  it("accepts a 103-byte pathname and rejects a 104-byte one", () => {
    expect(DARWIN_SOCKET_PATH_MAX_BYTES).toBe(103);
    expect(socketPathProblem(pathOfBytes(103))).toBeNull();
    expect(socketPathProblem(pathOfBytes(104))).toMatch(/104 UTF-8 bytes.*limit is 103/);
  });

  it("counts UTF-8 bytes, not characters", () => {
    const multibyte = `/${"é".repeat(51)}`; // 52 characters, 103 bytes
    expect(multibyte.length).toBe(52);
    expect(socketPathProblem(multibyte)).toBeNull();
    const over = `/${"é".repeat(51)}a`; // 53 characters, 104 bytes
    expect(socketPathProblem(over)).toMatch(/104 UTF-8 bytes/);
  });

  it("rejects a pathname containing NUL even when it is short", () => {
    expect(socketPathProblem("/fixture/a\0b.sock")).toMatch(/NUL/);
  });

  it("rejects a non-string pathname", () => {
    expect(socketPathProblem(undefined)).toMatch(/not a string/);
  });
});

describe("canary socket forecast and construction share the same constants", () => {
  it("forecasts the exact shape runtime constructs (prefix + six mkdtemp characters + socket name)", () => {
    expect([CANARY_PREFIX, CANARY_SUFFIX_LENGTH, FORBIDDEN_SOCKET_NAME]).toEqual(["rh-canary-", 6, "forbidden.sock"]);
    const forecast = forecastCanarySocketPath("/r");
    expect(forecast).toBe("/r/rh-canary-XXXXXX/forbidden.sock");
    expect(Buffer.byteLength(forecast)).toBe(Buffer.byteLength(canarySocketPath("/r/rh-canary-2bRpW4")));
    expect(canarySocketPath("/r/rh-canary-2bRpW4")).toBe("/r/rh-canary-2bRpW4/forbidden.sock");
  });

  it("rejects the failed pilot's canary root (119-byte socket path) and accepts the 99-byte short candidate", () => {
    const failedRoot = "/private/var/folders/q1/zwn7qv6n4xd9wx2hvrz6cm5m0000gn/T/opencode/rh-v2-canary-fBFEBx6w";
    expect(Buffer.byteLength(forecastCanarySocketPath(failedRoot))).toBe(119);
    expect(socketPathProblem(forecastCanarySocketPath(failedRoot))).toMatch(/119 UTF-8 bytes/);
    const candidate = "/private/var/folders/q1/zwn7qv6n4xd9wx2hvrz6cm5m0000gn/T/opencode/c";
    expect(Buffer.byteLength(forecastCanarySocketPath(candidate))).toBe(99);
    expect(socketPathProblem(forecastCanarySocketPath(candidate))).toBeNull();
  });
});
