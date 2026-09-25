import type { BuildPolicyInput, BuildPolicyMatch, DeviceMeta, ParsedAttestation, Verdict } from "./types";

export function evaluateIntegrity(record: ParsedAttestation): Verdict {
  const reasons: string[] = [];
  if (record.deviceIntegrity.deviceLocked !== true) {
    reasons.push("DEVICE_UNLOCKED");
  }
  // SELF_SIGNED (locked bootloader, custom key) is acceptable here: the key is
  // pinned by the mandatory build-policy match the callers apply afterwards.
  const bootState = record.deviceIntegrity.verifiedBootState;
  if (bootState !== "VERIFIED" && bootState !== "SELF_SIGNED") {
    reasons.push("BOOT_STATE_UNVERIFIED");
  }
  if (record.attestationSecurityLevel !== "TEE" && record.attestationSecurityLevel !== "STRONGBOX") {
    reasons.push("ATTESTATION_NOT_HARDWARE");
  }
  if (record.keymasterSecurityLevel !== "TEE" && record.keymasterSecurityLevel !== "STRONGBOX") {
    reasons.push("KEYMASTER_NOT_HARDWARE");
  }
  if (!record.deviceIntegrity.osPatchLevel) {
    reasons.push("OS_PATCHLEVEL_MISSING");
  }
  return { isTrusted: reasons.length === 0, reasonCodes: reasons };
}

export function normalizeMeta(value?: string | null): string {
  return (value || "").trim().toLowerCase();
}

export function matchBuildPolicy(
  policies: BuildPolicyInput[],
  attestation: ParsedAttestation,
  deviceMeta?: DeviceMeta
): BuildPolicyMatch {
  const integrity = attestation.deviceIntegrity;
  const verifiedBootKeyHex = integrity.verifiedBootKey?.toLowerCase();
  const verifiedBootHashHex = integrity.verifiedBootHash?.toLowerCase();
  const osVersionRaw = integrity.osVersion;
  const osPatchLevelRaw = integrity.osPatchLevel;
  const buildFingerprint = normalizeMeta(deviceMeta?.buildFingerprint);

  for (const policy of policies) {
    if (!policy.enabled) {
      continue;
    }
    if (buildFingerprint) {
      if (normalizeMeta(policy.buildFingerprint) !== buildFingerprint) {
        continue;
      }
    }
    if (!verifiedBootKeyHex || policy.verifiedBootKeyHex.toLowerCase() !== verifiedBootKeyHex) {
      continue;
    }
    if (policy.verifiedBootHashHex) {
      if (!verifiedBootHashHex || policy.verifiedBootHashHex.toLowerCase() !== verifiedBootHashHex) {
        continue;
      }
    }
    if (policy.osVersionRaw !== null) {
      if (osVersionRaw === undefined || osVersionRaw !== policy.osVersionRaw) {
        continue;
      }
    }
    if (policy.minOsPatchLevelRaw !== null) {
      if (osPatchLevelRaw === undefined || osPatchLevelRaw < policy.minOsPatchLevelRaw) {
        continue;
      }
    }
    return {
      deviceFamilyId: policy.deviceFamilyId,
      buildPolicyId: policy.id,
      buildFingerprint: policy.buildFingerprint
    };
  }
  return {};
}
