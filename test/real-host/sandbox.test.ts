import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { runProbe } from "./probe.mjs";
import { PROFILE_STATUS, candidateProfile, evaluatePreflight, preflightPlan, sandboxArgv } from "./sandbox.mjs";

const created: string[] = [];
afterEach(async () => {
  for (const dir of created.splice(0)) await rm(dir, { recursive: true, force: true });
});
async function scratch(): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "rh-sb-")));
  created.push(dir);
  return dir;
}

const BASE = {
  fixtureRoot: "/private/var/fx/rh-v1-abc",
  executables: ["/private/var/fx/rh-v1-abc/stage/opencode", "/bin/bash", "/bin/sh"],
  loopbackPorts: [41000, 41001],
  machServices: ["com.apple.system.notification_center"],
};

describe("candidate sandbox profile", () => {
  it("is explicitly a candidate, not a validated boundary", () => {
    expect(PROFILE_STATUS).toBe("candidate");
  });

  it("denies by default and allows only the fixture, listed executables, listed loopback ports, and listed Mach services", () => {
    const profile = candidateProfile(BASE);
    expect(profile).toMatch(/^\(version 1\)\n\(deny default\)/);
    expect(profile).not.toMatch(/\(allow default\)/);
    expect(profile).toContain('(allow file-read* file-write* (subpath "/private/var/fx/rh-v1-abc"))');
    expect(profile).toContain('(allow process-exec (literal "/bin/bash"))');
    expect(profile).toContain('(allow network-outbound (remote ip "localhost:41000"))');
    expect(profile).toContain('(allow mach-lookup (global-name "com.apple.system.notification_center"))');
    expect(profile).not.toMatch(/remote unix-socket/);
    expect(profile).not.toMatch(/\(remote ip "\*/);
    expect(profile).not.toContain("/Users/");
  });

  it("fails closed while Mach services are unresolved", () => {
    expect(() => candidateProfile({ ...BASE, machServices: null })).toThrow(/Mach services unresolved/);
  });

  it("rejects values that could inject profile syntax or widen access", () => {
    expect(() => candidateProfile({ ...BASE, executables: ['/bin/x") (allow default'] })).toThrow(/unsafe/);
    expect(() => candidateProfile({ ...BASE, fixtureRoot: "relative" })).toThrow(/absolute/);
    expect(() => candidateProfile({ ...BASE, fixtureRoot: "/" })).toThrow(/fixture root/);
    expect(() => candidateProfile({ ...BASE, loopbackPorts: [0] })).toThrow(/port/);
    expect(() => candidateProfile({ ...BASE, machServices: ["*"] })).toThrow(/unsafe/);
  });

  it("wraps argv with the system sandbox-exec and an absolute profile path", () => {
    expect(sandboxArgv("/fx/run/profile.sb", ["/fx/stage/opencode", "serve"])).toEqual(["/usr/bin/sandbox-exec", "-f", "/fx/run/profile.sb", "/fx/stage/opencode", "serve"]);
    expect(() => sandboxArgv("profile.sb", ["x"])).toThrow(/absolute/);
  });
});

describe("sandbox preflight", () => {
  const plan = preflightPlan({
    fixtureRoot: "/fx",
    canaryRoot: "/canary",
    provider: { url: "http://127.0.0.1:41001/__rh/identity", token: "tok-abcdefgh" },
    forbidden: { ipv4: { host: "127.0.0.1", port: 42000 }, ipv6: { host: "::1", port: 42001 }, unix: { path: "/canary/forbidden.sock" } },
  });
  const ids = plan.map((check: { id: string }) => check.id);
  const allowed = (extra: Record<string, unknown> = {}) => ({ completed: true, outcome: "allowed", ...extra });
  const denied = (code = "EPERM") => ({ completed: true, outcome: "denied", code });

  it("includes positive controls and negative read+write canary and IPv4/IPv6/Unix forbidden-listener checks", () => {
    expect(ids).toEqual(["positive-read", "positive-write", "positive-provider", "canary-read", "canary-write", "forbidden-ipv4", "forbidden-ipv6", "forbidden-unix"]);
    expect(plan.find((check: { id: string }) => check.id === "positive-provider").target).toBe("http://127.0.0.1:41001/__rh/identity");
    expect(() =>
      preflightPlan({ fixtureRoot: "/fx", canaryRoot: "/fx/inside", provider: { url: "http://127.0.0.1:1/__rh/identity", token: "tok-abcdefgh" }, forbidden: { ipv4: { host: "127.0.0.1", port: 1 }, ipv6: { host: "::1", port: 2 }, unix: { path: "/canary/s" } } }),
    ).toThrow(/canary root must be outside the fixture/);
  });

  function passing() {
    const obs: Record<string, any> = {
      "positive-read": { sandboxed: allowed() },
      "positive-write": { sandboxed: allowed() },
      "positive-provider": { sandboxed: allowed({ status: 200, body: JSON.stringify({ token: "tok-abcdefgh" }) }) },
      "canary-read": { control: allowed(), sandboxed: denied("EPERM") },
      "canary-write": { control: allowed(), sandboxed: denied("EACCES") },
    };
    for (const id of ["forbidden-ipv4", "forbidden-ipv6", "forbidden-unix"]) obs[id] = { control: allowed(), sandboxed: denied(), listenerRequests: 0 };
    return obs;
  }

  it("passes only when every check has the required control and sandboxed evidence", () => {
    expect(evaluatePreflight(plan, passing())).toEqual({ ok: true, failures: [] });
  });

  it.each([
    ["a missing observation", (o: any) => delete o["forbidden-ipv6"], /forbidden-ipv6: missing/],
    ["a canary the control could not reach", (o: any) => (o["canary-write"].control = { completed: true, outcome: "error", code: "ENOENT" }), /canary-write: control could not/],
    ["a canary the sandbox could read", (o: any) => (o["canary-read"].sandboxed = allowed()), /canary-read: sandbox allowed/],
    ["a probe that produced no result (not a denial)", (o: any) => (o["canary-read"].sandboxed = { completed: false, outcome: "infrastructure", reason: "no probe result" }), /canary-read: probe did not complete/],
    ["a probe that timed out (not a denial)", (o: any) => (o["forbidden-unix"].sandboxed = { completed: false, outcome: "infrastructure", reason: "timeout" }), /forbidden-unix: probe did not complete/],
    ["a probe that exited nonzero (not a denial)", (o: any) => (o["forbidden-ipv4"].sandboxed = { completed: false, outcome: "infrastructure", reason: "exit 1" }), /forbidden-ipv4: probe did not complete/],
    ["an infrastructure error code (not a denial)", (o: any) => (o["canary-read"].sandboxed = { completed: true, outcome: "error", code: "ENOENT" }), /canary-read: .*not an expected denial/],
    ["a refused connection (not a denial)", (o: any) => (o["forbidden-ipv6"].sandboxed = { completed: true, outcome: "error", code: "ECONNREFUSED" }), /forbidden-ipv6: .*not an expected denial/],
    ["a forbidden listener that saw a request", (o: any) => (o["forbidden-unix"].listenerRequests = 1), /forbidden-unix: listener received 1/],
    ["a provider 404 treated as success", (o: any) => (o["positive-provider"].sandboxed = allowed({ status: 404, body: "not found" })), /positive-provider: .*status 404/],
    ["a provider with the wrong identity", (o: any) => (o["positive-provider"].sandboxed = allowed({ status: 200, body: JSON.stringify({ token: "other" }) })), /positive-provider: .*identity/],
    ["a positive control that did not complete", (o: any) => (o["positive-write"].sandboxed = { completed: false, outcome: "infrastructure", reason: "no probe result" }), /positive-write: sandboxed operation was not allowed/],
  ])("fails on %s", (_label, mutate, message) => {
    const observations = passing();
    mutate(observations);
    const result = evaluatePreflight(plan, observations);
    expect(result.ok).toBe(false);
    expect(result.failures.join("\n")).toMatch(message);
  });
});

describe("preflight probe (file operations only in unit tests)", () => {
  it("classifies allowed, denied, and infrastructure outcomes for file operations", async () => {
    const dir = await scratch();
    await writeFile(join(dir, "canary"), "token");
    await writeFile(join(dir, "locked"), "token");
    await chmod(join(dir, "locked"), 0o000);

    expect(await runProbe("read", join(dir, "canary"))).toEqual({ completed: true, op: "read", outcome: "allowed" });
    expect(await runProbe("read", join(dir, "locked"))).toEqual({ completed: true, op: "read", outcome: "denied", code: "EACCES" });
    expect(await runProbe("read", join(dir, "missing"))).toEqual({ completed: true, op: "read", outcome: "error", code: "ENOENT" });
    expect(await runProbe("write", join(dir, "written"))).toEqual({ completed: true, op: "write", outcome: "allowed" });
    expect(await readFile(join(dir, "written"), "utf8")).toBe("real-host-probe\n");
    expect(await runProbe("bogus", "x")).toEqual({ completed: true, op: "bogus", outcome: "error", code: "unknown probe operation" });
    await chmod(join(dir, "locked"), 0o600);
  });
});
