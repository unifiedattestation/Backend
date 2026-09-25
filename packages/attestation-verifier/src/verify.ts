import { getCertificateSerial, parseCertificateChain, verifyCertificateChainStrict } from "./chain";
import { hasAttestationExtension, parseKeyAttestation } from "./parsing";
import { evaluateIntegrity, matchBuildPolicy } from "./policy";
import { AttestationCache, createAttestationCache } from "./cache";
import { fetchDeviceEntry, fetchRevocationStatus, fetchRootCertificates, normalizeBaseUrl } from "./registry";
import { AttestationVerificationError, type DeviceMeta, type ParsedAttestation, type Verdict } from "./types";

export type VerifyDeviceAttestationParams = {
  /** base64 DER attestation chain, leaf-first -- same shape Android-SDK returns. */
  attestationChain: string[];
  requestHash: string;
  /** Backend root URL, e.g. "https://uattest.volla.tech" (no "/api/v1" suffix -- matches Server-SDK-JS's `baseUrl` convention). */
  registryBaseUrl: string;
  /** Device family slug, e.g. "volla-ansuz". */
  deviceSlug: string;
  deviceMeta?: DeviceMeta;
  projectId?: string;
  signerDigestSha256?: string;
  /** Pass a shared instance across calls for a hot request path; otherwise a fresh one is created from cacheTtlMs. */
  cache?: AttestationCache;
  /** Ignored if `cache` is passed. Default 5 minutes. */
  cacheTtlMs?: number;
  /** Testability hook; defaults to now. */
  validationDate?: Date;
};

export type VerifyDeviceAttestationResult = {
  verdict: Verdict;
  requestHash: string;
  claims: {
    projectId?: string;
    requestHash: string;
    app: { packageName?: string; signerDigests: string[] };
    deviceIntegrity: ParsedAttestation["deviceIntegrity"];
  };
};

function normalizeSerial(serial: string, targetCase: "upper" | "lower"): string {
  const stripped = serial.replace(/^0+/, "");
  return targetCase === "upper" ? stripped.toUpperCase() : stripped.toLowerCase();
}

export async function verifyDeviceAttestation(
  params: VerifyDeviceAttestationParams
): Promise<VerifyDeviceAttestationResult> {
  const cache = params.cache ?? createAttestationCache(params.cacheTtlMs);
  const baseUrl = normalizeBaseUrl(params.registryBaseUrl);

  const chain = parseCertificateChain(params.attestationChain);
  if (chain.length === 0) {
    throw new AttestationVerificationError("INVALID_CHAIN", "Empty attestation chain");
  }
  if (chain.length < 2) {
    throw new AttestationVerificationError("INVALID_CHAIN", "Missing issuer certificate");
  }

  const entry = await fetchDeviceEntry(baseUrl, params.deviceSlug, cache);
  if (!entry.enabled) {
    throw new AttestationVerificationError("POLICY_FAIL", "Device disabled");
  }

  // Resolve trust anchor roots. If the registry reports no active anchor for
  // this device family yet, fall back to the backend's own root bundle --
  // this only matters for devices that share the backend's local authority,
  // and still requires *some* root to cryptographically verify a chain (this
  // is not a "build-policy-only, no crypto" mode).
  const rootCertificatesUrl = entry.certificate
    ? entry.certificate.authority.rootCertificatesUrl
    : `${baseUrl}/api/v1/info/root`;
  const rootPems = await fetchRootCertificates(rootCertificatesUrl, cache);
  if (rootPems.length === 0) {
    throw new AttestationVerificationError("ANCHOR_MISSING", "No active anchor for device");
  }

  // Serial cross-check against the registry's currently-active anchor.
  // Intentionally non-fatal (matches routes/device.ts's current behavior,
  // which only logs a warning here rather than rejecting).
  if (entry.certificate) {
    const chainSerials = chain.map((cert) => normalizeSerial(getCertificateSerial(cert), "upper"));
    const requiredSerials = [
      entry.certificate.rsaLeafSerialHex,
      entry.certificate.ecdsaLeafSerialHex,
      entry.certificate.rsaIntermediateSerialHex || undefined,
      entry.certificate.ecdsaIntermediateSerialHex || undefined
    ]
      .filter((serial): serial is string => Boolean(serial))
      .map((serial) => normalizeSerial(serial, "upper"));
    const missingSerials = requiredSerials.filter((serial) => !chainSerials.includes(serial));
    if (missingSerials.length > 0) {
      console.warn(
        `[ua-attestation-verifier] anchor serial mismatch for ${params.deviceSlug} (ignored, matches backend behavior): missing ${missingSerials.join(", ")}`
      );
    }
  }

  try {
    verifyCertificateChainStrict(chain, rootPems, params.validationDate);
  } catch (error) {
    const message = (error as Error).message;
    if (message === "Untrusted certificate chain") {
      throw new AttestationVerificationError("UNTRUSTED_ROOT", message);
    }
    throw new AttestationVerificationError("INVALID_CHAIN", `Attestation chain validation failed: ${message}`);
  }

  let attestation: ParsedAttestation | undefined;
  try {
    attestation = parseKeyAttestation(chain[0]);
  } catch {
    for (let i = 0; i < chain.length; i += 1) {
      try {
        if (!hasAttestationExtension(chain[i])) {
          continue;
        }
        attestation = parseKeyAttestation(chain[i]);
        break;
      } catch {
        continue;
      }
    }
  }
  if (!attestation) {
    throw new AttestationVerificationError("INVALID_ATTESTATION", "Unable to parse attestation");
  }

  const revocationEntries = await fetchRevocationStatus(baseUrl, cache);
  const revokedChainSerial = chain
    .map((cert) => normalizeSerial(getCertificateSerial(cert), "lower"))
    .find((serial) => revocationEntries[serial]?.status === "REVOKED");
  if (revokedChainSerial) {
    throw new AttestationVerificationError("REVOKED_CERT", "Certificate is revoked");
  }

  if (attestation.deviceIntegrity.origin && attestation.deviceIntegrity.origin !== "GENERATED") {
    throw new AttestationVerificationError("INVALID_ATTESTATION", "Key origin is not GENERATED");
  }
  if (attestation.attestationSecurityLevel !== attestation.keymasterSecurityLevel) {
    throw new AttestationVerificationError("INVALID_ATTESTATION", "Security level mismatch");
  }
  if (!attestation.deviceIntegrity.verifiedBootKey || !attestation.deviceIntegrity.verifiedBootState) {
    throw new AttestationVerificationError("INVALID_ATTESTATION", "Missing root of trust");
  }
  if (attestation.attestationChallengeHex !== params.requestHash.toLowerCase()) {
    throw new AttestationVerificationError("CHALLENGE_MISMATCH", "attestationChallenge mismatch");
  }
  if (!attestation.app.packageName || attestation.app.signerDigests.length === 0) {
    throw new AttestationVerificationError("INVALID_ATTESTATION", "Missing app identity in attestation");
  }
  if (params.projectId && attestation.app.packageName !== params.projectId) {
    throw new AttestationVerificationError("APP_ID_MISMATCH", "projectId does not match attestation");
  }
  if (params.signerDigestSha256) {
    const signerDigests = attestation.app.signerDigests.map((digest) => digest.toLowerCase());
    if (!signerDigests.includes(params.signerDigestSha256.toLowerCase())) {
      throw new AttestationVerificationError("APP_ID_MISMATCH", "Signer mismatch");
    }
  }

  const verdict = evaluateIntegrity(attestation);

  // Note: the public registry only lists *enabled* builds, so unlike the
  // internal backend, this can't distinguish "no builds registered" from
  // "all builds disabled" -- both look like an empty `entry.builds`.
  if (entry.builds.length > 0) {
    // The registry only ever lists enabled builds but never sends an
    // `enabled` field on them, so it must be filled in here -- otherwise
    // matchBuildPolicy's `!policy.enabled` guard skips every entry.
    const policies = entry.builds.map((build) => ({ ...build, enabled: true }));
    const match = matchBuildPolicy(policies, attestation, params.deviceMeta);
    // The public registry's builds never carry an `id` (that's a Prisma-only
    // field), so `match.buildPolicyId` is never set here even on a genuine
    // match -- `buildFingerprint` is always populated by matchBuildPolicy on
    // a match (it's a required field on every BuildPolicyInput) and is the
    // right success signal for registry-sourced data.
    if (!match.buildFingerprint) {
      verdict.reasonCodes.push("BUILD_POLICY_MISMATCH");
      verdict.isTrusted = false;
    }
  } else {
    // Fail closed: with no registered build there is nothing to pin the
    // verifiedBootKey against, so the device can't be vouched for.
    verdict.reasonCodes.push(
      params.deviceMeta?.buildFingerprint ? "BUILD_PREFILTER_MISMATCH" : "BUILD_POLICY_MISMATCH"
    );
    verdict.isTrusted = false;
  }

  return {
    verdict,
    requestHash: params.requestHash,
    claims: {
      projectId: params.projectId,
      requestHash: params.requestHash,
      app: attestation.app,
      deviceIntegrity: attestation.deviceIntegrity
    }
  };
}
