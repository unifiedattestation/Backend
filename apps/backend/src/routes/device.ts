import { FastifyInstance } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import { DeviceProcessRequestSchema, DeviceProcessResponseSchema } from "@ua/common";
import { getPrisma } from "../lib/prisma";
import { getActiveSigningKey } from "../lib/config";
import { signIntegrityToken, sha256Hex } from "../lib/crypto";
import { errorResponse } from "../lib/errors";
import {
  getCertificateSerial,
  parseCertificateChain,
  parseKeyAttestation,
  verifyCertificateChain
} from "../lib/attestation";
import {
  getAuthorityForSerial,
  getAuthorityRoots,
  getAuthorityStatus
} from "../services/attestationAuthorities";

function computeScopedDeviceId(backendId: string, projectId: string, spkiDer: Buffer): string {
  return sha256Hex(Buffer.concat([Buffer.from(backendId, "utf8"), Buffer.from(projectId, "utf8"), spkiDer]));
}

function evaluateIntegrity(record: ReturnType<typeof parseKeyAttestation>) {
  const reasons: string[] = [];
  if (record.deviceIntegrity.verifiedBootState && record.deviceIntegrity.verifiedBootState !== "VERIFIED") {
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
  if (!record.deviceIntegrity.vendorPatchLevel) {
    reasons.push("VENDOR_PATCHLEVEL_MISSING");
  }
  if (!record.deviceIntegrity.bootPatchLevel) {
    reasons.push("BOOT_PATCHLEVEL_MISSING");
  }
  if (!record.deviceIntegrity.teePatchLevel) {
    reasons.push("TEE_PATCHLEVEL_MISSING");
  }
  return { isTrusted: reasons.length === 0, reasonCodes: reasons };
}

type BuildPolicyMatch = {
  deviceFamilyId?: string;
  buildPolicyId?: string;
  buildPolicyName?: string;
};

function matchBuildPolicy(
  policies: Array<{
    id: string;
    name: string;
    deviceFamilyId: string;
    verifiedBootKeyHex: string;
    verifiedBootHashHex: string | null;
    osVersionRaw: number | null;
    minOsPatchLevelRaw: number | null;
    minVendorPatchLevelRaw: number | null;
    minBootPatchLevelRaw: number | null;
    expectedDeviceLocked: boolean | null;
    expectedVerifiedBootState: string | null;
  }>,
  attestation: ReturnType<typeof parseKeyAttestation>
): BuildPolicyMatch {
  const integrity = attestation.deviceIntegrity;
  const verifiedBootKeyHex = integrity.verifiedBootKey?.toLowerCase();
  const verifiedBootHashHex = integrity.verifiedBootHash?.toLowerCase();
  const osVersionRaw = integrity.osVersionRaw;
  const osPatchLevelRaw = integrity.osPatchLevelRaw ?? integrity.osPatchLevel;
  const vendorPatchLevelRaw = integrity.vendorPatchLevelRaw ?? integrity.vendorPatchLevel;
  const bootPatchLevelRaw = integrity.bootPatchLevelRaw ?? integrity.bootPatchLevel;
  const verifiedBootState = integrity.verifiedBootState;
  const deviceLocked = integrity.deviceLocked;

  for (const policy of policies) {
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
    if (policy.minVendorPatchLevelRaw !== null) {
      if (vendorPatchLevelRaw === undefined || vendorPatchLevelRaw < policy.minVendorPatchLevelRaw) {
        continue;
      }
    }
    if (policy.minBootPatchLevelRaw !== null) {
      if (bootPatchLevelRaw === undefined || bootPatchLevelRaw < policy.minBootPatchLevelRaw) {
        continue;
      }
    }
    if (policy.expectedVerifiedBootState) {
      if (!verifiedBootState || verifiedBootState !== policy.expectedVerifiedBootState) {
        continue;
      }
    }
    if (policy.expectedDeviceLocked !== null) {
      if (deviceLocked === undefined || deviceLocked !== policy.expectedDeviceLocked) {
        continue;
      }
    }
    return {
      deviceFamilyId: policy.deviceFamilyId,
      buildPolicyId: policy.id,
      buildPolicyName: policy.name
    };
  }
  return {};
}

export default async function deviceRoutes(app: FastifyInstance) {
  app.post(
    "/process",
    {
      schema: {
        body: zodToJsonSchema(DeviceProcessRequestSchema),
        response: {
          200: zodToJsonSchema(DeviceProcessResponseSchema)
        }
      }
    },
    async (request, reply) => {
      const body = DeviceProcessRequestSchema.parse(request.body);
      const prisma = getPrisma();

      const chain = parseCertificateChain(body.attestationChain);
      if (chain.length === 0) {
        reply.code(400).send(errorResponse("INVALID_CHAIN", "Empty attestation chain"));
        return;
      }
      let anchorEntry;
      try {
        anchorEntry = await getAuthorityForSerial(getCertificateSerial(chain[0]));
      } catch (error) {
        reply.code(400).send(errorResponse("INVALID_ATTESTATION", "Unable to read certificate serial"));
        return;
      }
      if (!anchorEntry || !anchorEntry.authority || !anchorEntry.authority.enabled) {
        reply
          .code(400)
          .send(errorResponse("INVALID_ATTESTATION", "Unknown attestation authority"));
        return;
      }
      if (anchorEntry.deviceFamily && anchorEntry.deviceFamily.enabled === false) {
        reply.code(400).send(errorResponse("POLICY_FAIL", "Device disabled"));
        return;
      }
      if (!anchorEntry.rsaRootId || !anchorEntry.ecdsaRootId) {
        reply.code(400).send(errorResponse("UNTRUSTED_ROOT", "No selected root for device"));
        return;
      }
      const roots = await getAuthorityRoots(anchorEntry.authorityId);
      try {
        const serial = getCertificateSerial(chain[0]).toUpperCase();
        const normalized = serial.replace(/^0+/, "");
        const isRsaSerial = normalized === anchorEntry.rsaSerialHex;
        const rootId = isRsaSerial ? anchorEntry.rsaRootId : anchorEntry.ecdsaRootId;
        const selectedRoot = roots.find((root) => root.id === rootId);
        if (!selectedRoot) {
          reply.code(400).send(errorResponse("UNTRUSTED_ROOT", "Selected root not available"));
          return;
        }
        verifyCertificateChain(chain, [selectedRoot.pem]);
      } catch (error) {
        reply.code(400).send(errorResponse("INVALID_CHAIN", "Attestation chain validation failed"));
        return;
      }

      let attestation;
      try {
        attestation = parseKeyAttestation(chain[0]);
      } catch (error) {
        reply.code(400).send(errorResponse("INVALID_ATTESTATION", "Unable to parse attestation"));
        return;
      }
      try {
        const serial = getCertificateSerial(chain[0]).toUpperCase();
        const normalized = serial.replace(/^0+/, "");
        const matchesAnchor =
          normalized === anchorEntry.rsaSerialHex ||
          normalized === anchorEntry.ecdsaSerialHex;
        if (!matchesAnchor) {
          reply.code(400).send(errorResponse("INVALID_ATTESTATION", "Device serial mismatch"));
          return;
        }
        if (anchorEntry.revokedAt) {
          reply.code(400).send(errorResponse("REVOKED_CERT", "Certificate is revoked"));
          return;
        }
        if (!anchorEntry.authority.isLocal) {
          const status = await getAuthorityStatus(anchorEntry.authorityId, anchorEntry.authority.baseUrl);
          if (status.revokedSerials.includes(normalized) || status.suspendedSerials.includes(normalized)) {
            reply.code(400).send(errorResponse("REVOKED_CERT", "Certificate is revoked"));
            return;
          }
        }
      } catch (error) {
        reply.code(400).send(errorResponse("INVALID_ATTESTATION", "Authority status unavailable"));
        return;
      }
      if (attestation.attestationChallengeHex !== body.requestHash.toLowerCase()) {
        reply.code(400).send(errorResponse("CHALLENGE_MISMATCH", "attestationChallenge mismatch"));
        return;
      }
      if (!attestation.app.packageName || attestation.app.signerDigests.length === 0) {
        reply
          .code(400)
          .send(errorResponse("INVALID_ATTESTATION", "Missing app identity in attestation"));
        return;
      }
      if (attestation.app.packageName !== body.projectId) {
        reply.code(400).send(errorResponse("APP_ID_MISMATCH", "projectId does not match attestation"));
        return;
      }
      const appRecord = await prisma.app.findUnique({ where: { projectId: body.projectId } });
      if (appRecord) {
        const signerDigests = attestation.app.signerDigests.map((digest) => digest.toLowerCase());
        if (!signerDigests.includes(appRecord.signerDigestSha256.toLowerCase())) {
          reply.code(400).send(errorResponse("APP_ID_MISMATCH", "Signer mismatch"));
          return;
        }
      }

      const scopedDeviceId = computeScopedDeviceId(
        app.config.backendId,
        body.projectId,
        attestation.publicKeySpkiDer
      );

      const verdict = evaluateIntegrity(attestation);
      const buildPolicies = await prisma.buildPolicy.findMany({
        where: { enabled: true, deviceFamilyId: anchorEntry.deviceFamilyId },
        orderBy: { createdAt: "desc" }
      });
      const match = matchBuildPolicy(buildPolicies, attestation);
      const now = Math.floor(Date.now() / 1000);
      const exp = now + 60;
      const tokenPayload = {
        iss: app.config.backendId,
        iat: now,
        exp,
        projectId: body.projectId,
        requestHash: body.requestHash,
        app: {
          packageName: attestation.app.packageName,
          signerDigests: attestation.app.signerDigests
        },
        deviceIntegrity: attestation.deviceIntegrity,
        verdict
      };
      const signingKey = getActiveSigningKey(app.config);
      const token = signIntegrityToken(tokenPayload, signingKey);

      await prisma.deviceReport.upsert({
        where: {
          projectId_scopedDeviceId: {
            projectId: body.projectId,
            scopedDeviceId
          }
        },
        update: {
          appId: appRecord?.id,
          projectId: body.projectId,
          issuerBackendId: app.config.backendId,
          lastSeen: new Date(),
          lastVerdict: verdict,
          lastState: attestation.deviceIntegrity,
          deviceFamilyId: anchorEntry.deviceFamilyId,
          buildPolicyId: match.buildPolicyId,
          buildPolicyName: match.buildPolicyName
        },
        create: {
          appId: appRecord?.id,
          projectId: body.projectId,
          scopedDeviceId,
          issuerBackendId: app.config.backendId,
          lastSeen: new Date(),
          lastVerdict: verdict,
          lastState: attestation.deviceIntegrity,
          deviceFamilyId: anchorEntry.deviceFamilyId,
          buildPolicyId: match.buildPolicyId,
          buildPolicyName: match.buildPolicyName
        }
      });

      reply.send({
        token,
        expiresAt: new Date(exp * 1000).toISOString(),
        verdict
      });
    }
  );
}
