// Type-level contract checks against the real host type packages. These run
// under vitest typecheck (tsc); nothing here executes or imports host runtime.
import type { Plugin as V1Plugin } from "@opencode-ai/plugin";
import type { Plugin as V2 } from "@opencode/plugin";
import { describe, expectTypeOf, it } from "vitest";

import defaultExport from "./index";
import type { V2SetupContext } from "./v2";

type HostEvent = V2.Context["event"]["subscribe"] extends (...args: never[]) => AsyncIterable<infer Event> ? Event : never;
type AskedData = Extract<HostEvent, { type: "permission.asked" }>["data"];
type RepliedData = Extract<HostEvent, { type: "permission.replied" }>["data"];

describe("@opencode/plugin@2.0.28 contract", () => {
  it("the dual default export is assignable to the V2 Plugin interface", () => {
    expectTypeOf(defaultExport).toExtend<V2.Plugin>();
  });

  it("the real V2 Context is assignable to the structural setup context", () => {
    expectTypeOf<V2.Context>().toExtend<V2SetupContext>();
  });

  it("permission event fields used by the decision mapping exist on the host event types", () => {
    expectTypeOf<AskedData>().toMatchObjectType<{
      id: string;
      sessionID: string;
      action: string;
      resources: Array<string>;
    }>();
    expectTypeOf<AskedData["save"]>().toEqualTypeOf<Array<string> | undefined>();
    expectTypeOf<NonNullable<AskedData["source"]>>().toMatchObjectType<{ type: "tool"; id: string }>();
    expectTypeOf<RepliedData>().toMatchObjectType<{ sessionID: string; requestID: string }>();
    expectTypeOf<RepliedData["reply"]>().toEqualTypeOf<"once" | "always" | "reject">();
  });
});

describe("@opencode-ai/plugin V1 contract", () => {
  it("default.server is the V1 Plugin function type", () => {
    expectTypeOf(defaultExport.server).toEqualTypeOf<V1Plugin>();
  });
});
