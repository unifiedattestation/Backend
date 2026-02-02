import { FastifyInstance } from "fastify";
import crypto from "crypto";
import { zodToJsonSchema } from "zod-to-json-schema";
import { DeviceProcessRequestSchema, DeviceProcessResponseSchema } from "@ua/common";
import { getPrisma } from "../lib/prisma";
import { getActiveSigningKey } from "../lib/config";
import { signIntegrityToken, sha256Hex } from "../lib/crypto";
import { errorResponse } from "../lib/errors";
import {
  getCertificateSerial,
  hasAttestationExtension,
  parseCertificateChain,
  parseKeyAttestation,
  verifyCertificateChainStrict
} from "../lib/attestation";
import { getAuthorityStatus } from "../services/attestationAuthorities";

function computeScopedDeviceId(backendId: string, projectId: string, spkiDer: Buffer): string {
  return sha256Hex(Buffer.concat([Buffer.from(backendId, "utf8"), Buffer.from(projectId, "utf8"), spkiDer]));
}

function evaluateIntegrity(record: ReturnType<typeof parseKeyAttestation>) {
  const reasons: string[] = [];
  if (
    record.deviceIntegrity.verifiedBootState &&
    record.deviceIntegrity.verifiedBootState !== "VERIFIED" &&
    record.deviceIntegrity.deviceLocked === true &&
    record.deviceIntegrity.verifiedBootKey &&
    record.deviceIntegrity.verifiedBootHash
  ) {
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

type BuildPolicyMatch = {
  deviceFamilyId?: string;
  buildPolicyId?: string;
  buildFingerprint?: string;
};

type DeviceMeta = {
  manufacturer?: string;
  brand?: string;
  model?: string;
  device?: string;
  buildFingerprint?: string;
};

function normalizeMeta(value?: string | null): string {
  return (value || "").trim().toLowerCase();
}

function matchBuildPolicy(
  policies: Array<{
    id: string;
    buildFingerprint: string;
    deviceFamilyId: string;
    verifiedBootKeyHex: string;
    verifiedBootHashHex: string | null;
    osVersionRaw: number | null;
    minOsPatchLevelRaw: number | null;
    enabled: boolean;
  }>,
  attestation: ReturnType<typeof parseKeyAttestation>,
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
      request.log.info(
        {
          projectId: body.projectId,
          requestHash: body.requestHash,
          chainLength: body.attestationChain.length,
          deviceMetaPresent: Boolean(body.deviceMeta),
          deviceMetaKeys: body.deviceMeta ? Object.keys(body.deviceMeta) : []
        },
        "device.process received"
      );

      const chain = parseCertificateChain(body.attestationChain);
      if (chain.length === 0) {
        request.log.warn("device.process empty certificate chain");
        reply.code(400).send(errorResponse("INVALID_CHAIN", "Empty attestation chain"));
        return;
      }
      try {
      const chainInfo = chain.map((der, index) => {
        const cert = new crypto.X509Certificate(der);
        const serial = cert.serialNumber.toUpperCase();
          const isSelfSigned =
            cert.subject === cert.issuer && cert.verify(cert.publicKey);
          return {
            index,
            serial,
            subject: cert.subject,
            issuer: cert.issuer,
            isSelfSigned,
            hasAttestationExtension: hasAttestationExtension(der)
          };
        });
        request.log.info({ chainInfo }, "device.process chain summary");
      } catch (error) {
        request.log.warn({ err: error }, "device.process unable to summarize chain");
      }
      const deviceMeta = body.deviceMeta as DeviceMeta | undefined;
      if (!deviceMeta) {
        request.log.warn(
          { deviceMeta, rawBody: body },
          "device.process missing device metadata"
        );
        reply
          .code(400)
          .send(errorResponse("DEVICE_PREFILTER_MISSING", "Missing device metadata"));
        return;
      }
      const families = await prisma.deviceFamily.findMany({
        where: { enabled: true },
        include: { oemOrg: true },
        orderBy: { createdAt: "desc" }
      });
      const deviceFamily = families.find((family) => {
        const manufacturer = family.manufacturer || family.oemOrg?.manufacturer || undefined;
        const brand = family.brand || family.oemOrg?.brand || undefined;
        if (manufacturer && normalizeMeta(manufacturer) !== normalizeMeta(deviceMeta.manufacturer)) {
          return false;
        }
        if (brand && normalizeMeta(brand) !== normalizeMeta(deviceMeta.brand)) {
          return false;
        }
        if (family.model && normalizeMeta(family.model) !== normalizeMeta(deviceMeta.model)) {
          return false;
        }
        if (family.codename && normalizeMeta(family.codename) !== normalizeMeta(deviceMeta.device)) {
          return false;
        }
        return true;
      });
      if (!deviceFamily) {
        const attempted = families.map((family) => ({
          id: family.id,
          codename: family.codename,
          model: family.model,
          manufacturer: family.manufacturer || family.oemOrg?.manufacturer || null,
          brand: family.brand || family.oemOrg?.brand || null
        }));
        request.log.warn(
          { deviceMeta, candidates: attempted },
          "device.process device prefilter mismatch"
        );
        reply
          .code(400)
          .send(errorResponse("DEVICE_PREFILTER_MISMATCH", "Device metadata mismatch"));
        return;
      }
      let anchorEntry;
      let leafSerial = "";
      let issuerSerial = "";
      try {
        leafSerial = getCertificateSerial(chain[0]).toUpperCase();
        if (chain.length < 2) {
          request.log.warn("device.process missing issuer certificate in chain");
          reply.code(400).send(errorResponse("INVALID_CHAIN", "Missing issuer certificate"));
          return;
        }
        issuerSerial = getCertificateSerial(chain[1]).toUpperCase();
      } catch (error) {
        request.log.error({ err: error }, "device.process failed to read leaf serial");
        reply.code(400).send(errorResponse("INVALID_ATTESTATION", "Unable to read certificate serial"));
        return;
      }
      anchorEntry = await prisma.deviceEntry.findFirst({
        where: {
          deviceFamilyId: deviceFamily.id,
          revokedAt: null
        },
        include: {
          authority: { include: { roots: true } },
          deviceFamily: true
        }
      });
      if (!anchorEntry || !anchorEntry.authority || !anchorEntry.authority.enabled) {
        request.log.warn(
          {
            leafSerial,
            issuerSerial,
            deviceFamilyId: deviceFamily.id,
            authorityId: anchorEntry?.authorityId,
            authorityEnabled: anchorEntry?.authority?.enabled
          },
          "device.process missing active anchor"
        );
        reply
          .code(400)
          .send(errorResponse("ANCHOR_MISSING", "No active anchor for device"));
        return;
      }
      if (anchorEntry.deviceFamily && anchorEntry.deviceFamily.enabled === false) {
        request.log.warn(
          { leafSerial, deviceFamilyId: anchorEntry.deviceFamilyId },
          "device.process device disabled"
        );
        reply.code(400).send(errorResponse("POLICY_FAIL", "Device disabled"));
        return;
      }
      const authorityRoots = anchorEntry.authority.roots || [];
      if (authorityRoots.length === 0) {
        request.log.warn(
          { leafSerial, authorityId: anchorEntry.authorityId },
          "device.process missing authority roots"
        );
        reply.code(400).send(errorResponse("UNTRUSTED_ROOT", "Authority missing roots"));
        return;
      }
      const chainSerials = chain.map((cert) =>
        getCertificateSerial(cert).replace(/^0+/, "").toUpperCase()
      );
      const requiredSerials = [
        anchorEntry.rsaSerialHex,
        anchorEntry.ecdsaSerialHex,
        anchorEntry.rsaIntermediateSerialHex || undefined,
        anchorEntry.ecdsaIntermediateSerialHex || undefined
      ]
        .filter((serial): serial is string => Boolean(serial))
        .map((serial) => serial.replace(/^0+/, "").toUpperCase());
      const missingSerials = requiredSerials.filter(
        (serial) => !chainSerials.includes(serial)
      );
      if (missingSerials.length > 0) {
        request.log.warn(
          {
            leafSerial,
            issuerSerial,
            missingSerials,
            chainSerials,
            anchorSerials: {
              rsaLeaf: anchorEntry.rsaSerialHex,
              ecdsaLeaf: anchorEntry.ecdsaSerialHex,
              rsaIntermediate: anchorEntry.rsaIntermediateSerialHex,
              ecdsaIntermediate: anchorEntry.ecdsaIntermediateSerialHex
            }
          },
          "device.process anchor serial mismatch (ignored for now)"
        );
      }
      try {
        const chainRoot = new crypto.X509Certificate(chain[chain.length - 1]);
        const chainRootSpki = chainRoot.publicKey.export({ type: "spki", format: "der" }) as Buffer;
        const selectedRoot = authorityRoots.find((entry) => {
          try {
            const cert = new crypto.X509Certificate(entry.pem);
            const rootSpki = cert.publicKey.export({ type: "spki", format: "der" }) as Buffer;
            return rootSpki.equals(chainRootSpki);
          } catch {
            return false;
          }
        });
        if (!selectedRoot) {
          request.log.warn(
            { leafSerial, issuerSerial, authorityId: anchorEntry.authorityId },
            "device.process selected root not available"
          );
          reply.code(400).send(errorResponse("UNTRUSTED_ROOT", "Selected root not available"));
          return;
        }
        const selectedRootCert = new crypto.X509Certificate(selectedRoot.pem);
        request.log.info(
          {
            leafSerial,
            issuerSerial,
            chainRootSerial: chainRoot.serialNumber.toUpperCase(),
            chainRootSubject: chainRoot.subject,
            selectedRootSerial: selectedRootCert.serialNumber.toUpperCase(),
            selectedRootSubject: selectedRootCert.subject
          },
          "device.process root comparison"
        );
        verifyCertificateChainStrict(chain, authorityRoots.map((entry) => entry.pem));
      } catch (error) {
        request.log.error({ err: error, leafSerial }, "device.process chain verification failed");
        reply.code(400).send(errorResponse("INVALID_CHAIN", "Attestation chain validation failed"));
        return;
      }

      let attestation;
      let attestationIndex = 0;
      let attestationError: string | undefined;
      try {
        try {
          attestation = parseKeyAttestation(chain[0]);
        } catch {
          for (let i = 0; i < chain.length; i += 1) {
            try {
              if (!hasAttestationExtension(chain[i])) {
                continue;
              }
              attestation = parseKeyAttestation(chain[i]);
              attestationIndex = i;
              attestationError = undefined;
              break;
            } catch (error) {
              attestationError = (error as Error).message;
              request.log.warn(
                { err: error, index: i },
                "device.process attestation parse failed for cert"
              );
              continue;
            }
          }
          if (!attestation) {
            throw new Error(attestationError || "No attestation extension found in chain");
          }
        }
        request.log.info(
          { leafSerial, issuerSerial, attestationIndex },
          "device.process attestation parsed"
        );
      } catch (error) {
        request.log.error({ err: error, leafSerial }, "device.process attestation parse failed");
        reply.code(400).send(errorResponse("INVALID_ATTESTATION", "Unable to parse attestation"));
        return;
      }
      try {
        if (anchorEntry.revokedAt) {
          request.log.warn(
            { leafSerial, issuerSerial, anchorId: anchorEntry.id, revokedAt: anchorEntry.revokedAt },
            "device.process certificate revoked"
          );
          reply.code(400).send(errorResponse("REVOKED_CERT", "Certificate is revoked"));
          return;
        }
        if (!anchorEntry.authority.isLocal) {
          const status = await getAuthorityStatus(anchorEntry.authorityId, anchorEntry.authority.baseUrl);
          const chainSerials = chain.map((cert) => getCertificateSerial(cert).replace(/^0+/, "").toUpperCase());
          const isRevoked = chainSerials.some(
            (serial) => status.revokedSerials.includes(serial) || status.suspendedSerials.includes(serial)
          );
          if (isRevoked) {
            request.log.warn(
              { leafSerial, issuerSerial, authorityId: anchorEntry.authorityId },
              "device.process certificate revoked by authority"
            );
            reply.code(400).send(errorResponse("REVOKED_CERT", "Certificate is revoked"));
            return;
          }
        }
      } catch (error) {
        request.log.error({ err: error, leafSerial }, "device.process authority status check failed");
        reply.code(400).send(errorResponse("INVALID_ATTESTATION", "Authority status unavailable"));
        return;
      }
      if (attestation.deviceIntegrity.origin && attestation.deviceIntegrity.origin !== "GENERATED") {
        reply.code(400).send(errorResponse("INVALID_ATTESTATION", "Key origin is not GENERATED"));
        return;
      }
      if (attestation.attestationSecurityLevel !== attestation.keymasterSecurityLevel) {
        reply
          .code(400)
          .send(errorResponse("INVALID_ATTESTATION", "Security level mismatch"));
        return;
      }
      if (!attestation.deviceIntegrity.verifiedBootKey || !attestation.deviceIntegrity.verifiedBootState) {
        reply.code(400).send(errorResponse("INVALID_ATTESTATION", "Missing root of trust"));
        return;
      }
      if (attestation.attestationChallengeHex !== body.requestHash.toLowerCase()) {
        request.log.warn(
          { leafSerial, requestHash: body.requestHash, challenge: attestation.attestationChallengeHex },
          "device.process challenge mismatch"
        );
        reply.code(400).send(errorResponse("CHALLENGE_MISMATCH", "attestationChallenge mismatch"));
        return;
      }
      if (!attestation.app.packageName || attestation.app.signerDigests.length === 0) {
        request.log.warn({ leafSerial }, "device.process missing app identity");
        reply
          .code(400)
          .send(errorResponse("INVALID_ATTESTATION", "Missing app identity in attestation"));
        return;
      }
      if (attestation.app.packageName !== body.projectId) {
        request.log.warn(
          { leafSerial, projectId: body.projectId, packageName: attestation.app.packageName },
          "device.process projectId mismatch"
        );
        reply.code(400).send(errorResponse("APP_ID_MISMATCH", "projectId does not match attestation"));
        return;
      }
      const appRecord = await prisma.app.findUnique({ where: { projectId: body.projectId } });
      if (appRecord) {
        const signerDigests = attestation.app.signerDigests.map((digest) => digest.toLowerCase());
        if (!signerDigests.includes(appRecord.signerDigestSha256.toLowerCase())) {
          request.log.warn(
            { leafSerial, projectId: body.projectId },
            "device.process signer digest mismatch"
          );
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
      let match: BuildPolicyMatch = {};
      let buildPolicies: Array<{
        id: string;
        buildFingerprint: string;
        deviceFamilyId: string;
        verifiedBootKeyHex: string;
        verifiedBootHashHex: string | null;
        osVersionRaw: number | null;
        minOsPatchLevelRaw: number | null;
        enabled: boolean;
      }> = [];
      buildPolicies = await prisma.buildPolicy.findMany({
        where: { enabled: true, deviceFamilyId: anchorEntry.deviceFamilyId },
        orderBy: { createdAt: "desc" }
      });
      if (buildPolicies.length > 0) {
        match = matchBuildPolicy(buildPolicies, attestation, deviceMeta);
        if (!match.buildPolicyId) {
          verdict.reasonCodes.push("BUILD_POLICY_MISMATCH");
          verdict.isTrusted = false;
        }
      } else if (deviceMeta?.buildFingerprint) {
        verdict.reasonCodes.push("BUILD_PREFILTER_MISMATCH");
        verdict.isTrusted = false;
      } else {
        const buildPolicyTotal = await prisma.buildPolicy.count({
          where: { deviceFamilyId: anchorEntry.deviceFamilyId }
        });
        if (buildPolicyTotal > 0) {
          verdict.reasonCodes.push("BUILD_POLICY_MISMATCH");
          verdict.isTrusted = false;
        }
      }
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
      const token = await signIntegrityToken(tokenPayload, signingKey);

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
          buildFingerprint: match.buildFingerprint
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
          buildFingerprint: match.buildFingerprint
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
