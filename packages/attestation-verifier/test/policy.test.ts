import { describe, expect, it } from "vitest";
import { evaluateIntegrity, matchBuildPolicy } from "../src/policy";
import type { BuildPolicyInput, ParsedAttestation } from "../src/types";

function makeAttestation(overrides: Partial<ParsedAttestation["deviceIntegrity"]> = {}): ParsedAttestation {
  return {
    attestationChallengeHex: "aabbcc",
    attestationSecurityLevel: "TEE",
    keymasterSecurityLevel: "TEE",
    app: { packageName: "com.example.app", signerDigests: ["deadbeef"] },
    deviceIntegrity: {
      verifiedBootState: "VERIFIED",
      deviceLocked: true,
      verifiedBootKey: "aa11",
      verifiedBootHash: "bb22",
      osVersion: 140000,
      osPatchLevel: 202410,
      ...overrides
    },
    publicKeySpkiDer: Buffer.alloc(0)
  };
}

describe("evaluateIntegrity", () => {
  it("trusts a fully-verified hardware attestation", () => {
    const verdict = evaluateIntegrity(makeAttestation());
    expect(verdict).toEqual({ isTrusted: true, reasonCodes: [] });
  });

  it("flags BOOT_STATE_UNVERIFIED when boot state is unverified", () => {
    const verdict = evaluateIntegrity(makeAttestation({ verifiedBootState: "UNVERIFIED" }));
    expect(verdict.isTrusted).toBe(false);
    expect(verdict.reasonCodes).toContain("BOOT_STATE_UNVERIFIED");
  });

  it("flags BOOT_STATE_UNVERIFIED when boot state is failed or missing", () => {
    expect(evaluateIntegrity(makeAttestation({ verifiedBootState: "FAILED" })).reasonCodes).toContain(
      "BOOT_STATE_UNVERIFIED"
    );
    expect(evaluateIntegrity(makeAttestation({ verifiedBootState: undefined })).reasonCodes).toContain(
      "BOOT_STATE_UNVERIFIED"
    );
  });

  it("accepts SELF_SIGNED on a locked device (key is pinned by build policy)", () => {
    const verdict = evaluateIntegrity(makeAttestation({ verifiedBootState: "SELF_SIGNED" }));
    expect(verdict).toEqual({ isTrusted: true, reasonCodes: [] });
  });

  it("flags DEVICE_UNLOCKED and BOOT_STATE_UNVERIFIED for an unlocked, unverified device", () => {
    const verdict = evaluateIntegrity(
      makeAttestation({
        verifiedBootState: "UNVERIFIED",
        deviceLocked: false,
        verifiedBootKey: "00".repeat(32)
      })
    );
    expect(verdict.isTrusted).toBe(false);
    expect(verdict.reasonCodes).toContain("DEVICE_UNLOCKED");
    expect(verdict.reasonCodes).toContain("BOOT_STATE_UNVERIFIED");
  });

  it("flags DEVICE_UNLOCKED when lock state is missing", () => {
    const verdict = evaluateIntegrity(makeAttestation({ deviceLocked: undefined }));
    expect(verdict.isTrusted).toBe(false);
    expect(verdict.reasonCodes).toContain("DEVICE_UNLOCKED");
  });

  it("flags ATTESTATION_NOT_HARDWARE for a software attestation level", () => {
    const attestation = makeAttestation();
    attestation.attestationSecurityLevel = "SOFTWARE";
    const verdict = evaluateIntegrity(attestation);
    expect(verdict.isTrusted).toBe(false);
    expect(verdict.reasonCodes).toContain("ATTESTATION_NOT_HARDWARE");
  });

  it("flags KEYMASTER_NOT_HARDWARE for a software keymaster level", () => {
    const attestation = makeAttestation();
    attestation.keymasterSecurityLevel = "SOFTWARE";
    const verdict = evaluateIntegrity(attestation);
    expect(verdict.isTrusted).toBe(false);
    expect(verdict.reasonCodes).toContain("KEYMASTER_NOT_HARDWARE");
  });

  it("flags OS_PATCHLEVEL_MISSING when no patch level is present", () => {
    const verdict = evaluateIntegrity(makeAttestation({ osPatchLevel: undefined }));
    expect(verdict.isTrusted).toBe(false);
    expect(verdict.reasonCodes).toContain("OS_PATCHLEVEL_MISSING");
  });
});

function makePolicy(overrides: Partial<BuildPolicyInput> = {}): BuildPolicyInput {
  return {
    id: "policy-1",
    deviceFamilyId: "family-1",
    buildFingerprint: "acme/foo/foo:14/AAA/1:user/release-keys",
    verifiedBootKeyHex: "aa11",
    verifiedBootHashHex: "bb22",
    osVersionRaw: 140000,
    minOsPatchLevelRaw: 202401,
    enabled: true,
    ...overrides
  };
}

describe("matchBuildPolicy", () => {
  it("matches when everything lines up", () => {
    const match = matchBuildPolicy([makePolicy()], makeAttestation());
    expect(match.buildPolicyId).toBe("policy-1");
  });

  it("skips a disabled policy even if it otherwise matches", () => {
    const match = matchBuildPolicy([makePolicy({ enabled: false })], makeAttestation());
    expect(match.buildPolicyId).toBeUndefined();
  });

  it("rejects on buildFingerprint prefilter mismatch", () => {
    const match = matchBuildPolicy([makePolicy()], makeAttestation(), {
      buildFingerprint: "acme/foo/foo:14/AAA/999:user/release-keys"
    });
    expect(match.buildPolicyId).toBeUndefined();
  });

  it("matches when buildFingerprint prefilter agrees (case/whitespace-insensitive)", () => {
    const match = matchBuildPolicy([makePolicy()], makeAttestation(), {
      buildFingerprint: "  ACME/foo/foo:14/AAA/1:user/release-keys  "
    });
    expect(match.buildPolicyId).toBe("policy-1");
  });

  it("rejects on verifiedBootKey mismatch", () => {
    const match = matchBuildPolicy([makePolicy({ verifiedBootKeyHex: "ff00" })], makeAttestation());
    expect(match.buildPolicyId).toBeUndefined();
  });

  it("rejects on verifiedBootHash mismatch when the policy specifies one", () => {
    const match = matchBuildPolicy([makePolicy({ verifiedBootHashHex: "ff00" })], makeAttestation());
    expect(match.buildPolicyId).toBeUndefined();
  });

  it("ignores verifiedBootHash when the policy leaves it null", () => {
    const match = matchBuildPolicy(
      [makePolicy({ verifiedBootHashHex: null })],
      makeAttestation({ verifiedBootHash: "anything" })
    );
    expect(match.buildPolicyId).toBe("policy-1");
  });

  it("requires an exact osVersion match when the policy specifies one", () => {
    const match = matchBuildPolicy([makePolicy({ osVersionRaw: 150000 })], makeAttestation());
    expect(match.buildPolicyId).toBeUndefined();
  });

  it("accepts a patch level at or above the policy's minimum", () => {
    const match = matchBuildPolicy(
      [makePolicy({ minOsPatchLevelRaw: 202410 })],
      makeAttestation({ osPatchLevel: 202410 })
    );
    expect(match.buildPolicyId).toBe("policy-1");
  });

  it("rejects a patch level below the policy's minimum", () => {
    const match = matchBuildPolicy(
      [makePolicy({ minOsPatchLevelRaw: 202411 })],
      makeAttestation({ osPatchLevel: 202410 })
    );
    expect(match.buildPolicyId).toBeUndefined();
  });

  it("returns no match against an empty policy list", () => {
    expect(matchBuildPolicy([], makeAttestation())).toEqual({});
  });
});
