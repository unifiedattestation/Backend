import { describe, it, expect } from "vitest";
import { ReplayCache } from "../src/services/replayCache";

describe("ReplayCache", () => {
  it("consumes once within TTL", () => {
    const cache = new ReplayCache(10);
    const first = cache.consume("dev", "proj", "jti1");
    const second = cache.consume("dev", "proj", "jti1");
    expect(first).toBe(true);
    expect(second).toBe(false);
  });
});
