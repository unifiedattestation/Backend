import { describe, it, expect } from "vitest";
import { ChallengeService } from "../src/services/challenge";
import { loadConfig } from "../src/lib/config";

const config = loadConfig();

describe("ChallengeService", () => {
  it("issues and verifies a challenge token", () => {
    const service = new ChallengeService(config);
    const issued = service.issueChallenge("dev1", "proj1");
    const claims = service.verifyChallengeToken(issued.token);
    expect(claims.did).toBe("dev1");
    expect(claims.pid).toBe("proj1");
  });
});
