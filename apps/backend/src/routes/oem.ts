import crypto from "crypto";
import type * as x509Types from "@peculiar/x509";
import { FastifyInstance } from "fastify";
import { getPrisma } from "../lib/prisma";
import { requireUser } from "../lib/auth";
import { errorResponse } from "../lib/errors";
import { generateKeyboxXmlWithDualRoots } from "../services/keybox";

async function requireOemOrg(userId: string) {
  const prisma = getPrisma();
  const existing = await prisma.oemOrg.findFirst({ where: { ownerUserId: userId } });
  if (existing) {
    return existing;
  }
  return prisma.oemOrg.create({
    data: {
      name: `OEM-${userId}`,
      ownerUserId: userId
    }
  });
}

function requireOemRole(role: string, reply: any) {
  if (role !== "oem" && role !== "admin") {
    reply.code(403).send(errorResponse("FORBIDDEN", "OEM role required"));
    return false;
  }
  return true;
}

function describeRoot(pem: string) {
  const cert = new crypto.X509Certificate(pem);
  return {
    subject: cert.subject,
    serialHex: cert.serialNumber.toUpperCase(),
    keyType: cert.publicKey.asymmetricKeyType || "unknown"
  };
}

async function getLocalAuthority(prisma: ReturnType<typeof getPrisma>) {
  return prisma.attestationAuthority.findFirst({
    where: { isLocal: true, enabled: true },
    include: { roots: true }
  });
}

let x509Module: typeof x509Types | null = null;
let x509CryptoReady = false;

async function loadX509() {
  if (!x509Module) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    x509Module = require("@peculiar/x509") as typeof x509Types;
  }
  if (!x509CryptoReady) {
    if (!crypto.webcrypto) {
      throw new Error("WebCrypto is not available for X.509 generation");
    }
    x509Module.X509CertificateGenerator.crypto = crypto.webcrypto;
    x509CryptoReady = true;
  }
  return x509Module;
}

function toPem(label: string, der: ArrayBuffer) {
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

async function generateSelfSignedRoot(commonName: string, algorithm: "rsa" | "ecdsa") {
  const {
    X509CertificateGenerator,
    Name,
    BasicConstraintsExtension,
    KeyUsagesExtension,
    KeyUsageFlags,
    PemConverter
  } = await loadX509();
  const subtle = crypto.webcrypto.subtle;
  const algorithmParams =
    algorithm === "rsa"
      ? {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: "SHA-256"
        }
      : {
          name: "ECDSA",
          namedCurve: "P-256"
        };
  const keys = await subtle.generateKey(algorithmParams, true, ["sign", "verify"]);
  const serialNumber = crypto.randomBytes(16).toString("hex").toUpperCase();
  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber,
    name: new Name(`CN=${commonName}`),
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000),
    keys,
    extensions: [
      new BasicConstraintsExtension(true, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.digitalSignature, true)
    ]
  });
  const privateKeyDer = await subtle.exportKey("pkcs8", keys.privateKey);
  const certPem =
    PemConverter?.encode?.(cert.rawData, "CERTIFICATE")?.trim() ??
    toPem("CERTIFICATE", cert.rawData);
  const keyPem =
    PemConverter?.encode?.(privateKeyDer, "PRIVATE KEY")?.trim() ??
    toPem("PRIVATE KEY", privateKeyDer);
  return {
    certPem,
    keyPem
  };
}

async function ensureOemRoots(prisma: ReturnType<typeof getPrisma>, org: { id: string; name: string }) {
  const record = await prisma.oemOrg.findUnique({ where: { id: org.id } });
  if (!record) {
    throw new Error("OEM org not found");
  }
  let currentRecord = record;
  let rsaCert = record.rsaRootCertPem;
  let rsaKey = record.rsaRootKeyPem;
  let ecdsaCert = record.ecdsaRootCertPem;
  let ecdsaKey = record.ecdsaRootKeyPem;
  if (!rsaCert || !rsaKey || !ecdsaCert || !ecdsaKey) {
    const rsa = await generateSelfSignedRoot(`UA ${org.name} RSA Root`, "rsa");
    const ecdsa = await generateSelfSignedRoot(`UA ${org.name} ECDSA Root`, "ecdsa");
    const updated = await prisma.oemOrg.update({
      where: { id: org.id },
      data: {
        rsaRootCertPem: rsa.certPem,
        rsaRootKeyPem: rsa.keyPem,
        ecdsaRootCertPem: ecdsa.certPem,
        ecdsaRootKeyPem: ecdsa.keyPem
      }
    });
    currentRecord = updated;
    rsaCert = updated.rsaRootCertPem || rsa.certPem;
    rsaKey = updated.rsaRootKeyPem || rsa.keyPem;
    ecdsaCert = updated.ecdsaRootCertPem || ecdsa.certPem;
    ecdsaKey = updated.ecdsaRootKeyPem || ecdsa.keyPem;
  }
  const localAuthority = await getLocalAuthority(prisma);
  if (!localAuthority) {
    throw new Error("Local authority not configured");
  }
  const existingRoots = await prisma.attestationRoot.findMany({
    where: { authorityId: localAuthority.id, oemOrgId: org.id }
  });
  const hasRsa = existingRoots.some((root) => root.pem.trim() === rsaCert);
  const hasEcdsa = existingRoots.some((root) => root.pem.trim() === ecdsaCert);
  if (!hasRsa || !hasEcdsa) {
    if (!hasRsa) {
      await prisma.attestationRoot.create({
        data: {
          authorityId: localAuthority.id,
          oemOrgId: org.id,
          pem: rsaCert,
          name: `OEM ${org.name} RSA Root`
        }
      });
    }
    if (!hasEcdsa) {
      await prisma.attestationRoot.create({
        data: {
          authorityId: localAuthority.id,
          oemOrgId: org.id,
          pem: ecdsaCert,
          name: `OEM ${org.name} ECDSA Root`
        }
      });
    }
  }
  return currentRecord;
}

function pickRootsForAuthority(roots: Array<{ id: string; pem: string }>) {
  const rsaRoot = roots.find((root) => {
    try {
      const cert = new crypto.X509Certificate(root.pem);
      return cert.publicKey.asymmetricKeyType === "rsa";
    } catch {
      return false;
    }
  });
  const ecdsaRoot = roots.find((root) => {
    try {
      const cert = new crypto.X509Certificate(root.pem);
      return cert.publicKey.asymmetricKeyType === "ec";
    } catch {
      return false;
    }
  });
  return { rsaRoot, ecdsaRoot };
}

export default async function oemRoutes(app: FastifyInstance) {
  app.get("/profile", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    reply.send(org);
  });

  app.put("/profile", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const prisma = getPrisma();
    const body = request.body as { name?: string; manufacturer?: string; brand?: string };
    const org = await requireOemOrg(user.sub as string);
    const updated = await prisma.oemOrg.update({
      where: { id: org.id },
      data: {
        name: body.name ?? org.name,
        manufacturer: body.manufacturer,
        brand: body.brand
      }
    });
    reply.send(updated);
  });

  app.get("/device-families", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const families = await prisma.deviceFamily.findMany({
      where: { oemOrgId: org.id }
    });
    const response = families.map((family) => ({
      id: family.id,
      name: family.codename || family.name,
      codename: family.codename,
      model: family.model,
      manufacturer: family.manufacturer,
      brand: family.brand,
      enabled: family.enabled,
      createdAt: family.createdAt
    }));
    reply.send(response);
  });

  app.post("/device-families", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const body = request.body as {
      codename?: string;
      model?: string;
    };
    if (!body.codename) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing device codename"));
      return;
    }
    if (!org.manufacturer || !org.brand) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "OEM profile must include manufacturer and brand"));
      return;
    }
    const family = await prisma.deviceFamily.create({
      data: {
        name: body.codename,
        codename: body.codename,
        model: body.model,
        oemOrgId: org.id
      }
    });
    reply.send({
      id: family.id,
      name: family.codename || family.name,
      codename: family.codename,
      model: family.model,
      enabled: family.enabled,
      createdAt: family.createdAt
    });
  });

  app.put("/device-families/:familyId", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId } = request.params as { familyId: string };
    const body = request.body as {
      enabled?: boolean;
    };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device not found"));
      return;
    }
    const updated = await prisma.deviceFamily.update({
      where: { id: family.id },
      data: {
        enabled: body.enabled ?? family.enabled
      }
    });
    reply.send({
      id: updated.id,
      name: updated.codename || updated.name,
      codename: updated.codename,
      model: updated.model,
      enabled: updated.enabled,
      createdAt: updated.createdAt
    });
  });

  app.delete("/device-families/:familyId", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId } = request.params as { familyId: string };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device not found"));
      return;
    }
    const anchors = await prisma.deviceEntry.count({ where: { deviceFamilyId: family.id } });
    if (anchors > 0) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Device has anchors; disable instead"));
      return;
    }
    await prisma.buildPolicy.deleteMany({ where: { deviceFamilyId: family.id } });
    await prisma.deviceFamily.delete({ where: { id: family.id } });
    reply.send({ ok: true });
  });

  app.get("/device-families/:familyId/builds", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId } = request.params as { familyId: string };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device not found"));
      return;
    }
    const builds = await prisma.buildPolicy.findMany({
      where: { deviceFamilyId: family.id },
      orderBy: { createdAt: "desc" }
    });
    reply.send(builds);
  });

  app.post("/device-families/:familyId/builds", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId } = request.params as { familyId: string };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device not found"));
      return;
    }
    const body = request.body as {
      name?: string;
      verifiedBootKeyHex?: string;
      verifiedBootHashHex?: string;
      osVersionRaw?: number;
      minOsPatchLevelRaw?: number;
      minVendorPatchLevelRaw?: number;
      minBootPatchLevelRaw?: number;
      expectedDeviceLocked?: boolean;
      expectedVerifiedBootState?: string;
      enabled?: boolean;
    };
    if (!body.name || !body.verifiedBootKeyHex) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing build name or verifiedBootKeyHex"));
      return;
    }
    const created = await prisma.buildPolicy.create({
      data: {
        deviceFamilyId: family.id,
        name: body.name,
        verifiedBootKeyHex: body.verifiedBootKeyHex.toLowerCase(),
        verifiedBootHashHex: body.verifiedBootHashHex?.toLowerCase(),
        osVersionRaw: body.osVersionRaw,
        minOsPatchLevelRaw: body.minOsPatchLevelRaw,
        minVendorPatchLevelRaw: body.minVendorPatchLevelRaw,
        minBootPatchLevelRaw: body.minBootPatchLevelRaw,
        expectedDeviceLocked: body.expectedDeviceLocked,
        expectedVerifiedBootState: body.expectedVerifiedBootState,
        enabled: body.enabled ?? true
      }
    });
    reply.send(created);
  });

  app.put("/device-families/:familyId/builds/:buildId", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId, buildId } = request.params as { familyId: string; buildId: string };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device not found"));
      return;
    }
    const build = await prisma.buildPolicy.findFirst({
      where: { id: buildId, deviceFamilyId: family.id }
    });
    if (!build) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Build policy not found"));
      return;
    }
    const body = request.body as {
      name?: string;
      verifiedBootKeyHex?: string;
      verifiedBootHashHex?: string | null;
      osVersionRaw?: number | null;
      minOsPatchLevelRaw?: number | null;
      minVendorPatchLevelRaw?: number | null;
      minBootPatchLevelRaw?: number | null;
      expectedDeviceLocked?: boolean | null;
      expectedVerifiedBootState?: string | null;
      enabled?: boolean;
    };
    const updated = await prisma.buildPolicy.update({
      where: { id: build.id },
      data: {
        name: body.name ?? build.name,
        verifiedBootKeyHex: body.verifiedBootKeyHex
          ? body.verifiedBootKeyHex.toLowerCase()
          : build.verifiedBootKeyHex,
        verifiedBootHashHex:
          body.verifiedBootHashHex === null
            ? null
            : body.verifiedBootHashHex
            ? body.verifiedBootHashHex.toLowerCase()
            : build.verifiedBootHashHex,
        osVersionRaw: body.osVersionRaw ?? build.osVersionRaw,
        minOsPatchLevelRaw: body.minOsPatchLevelRaw ?? build.minOsPatchLevelRaw,
        minVendorPatchLevelRaw: body.minVendorPatchLevelRaw ?? build.minVendorPatchLevelRaw,
        minBootPatchLevelRaw: body.minBootPatchLevelRaw ?? build.minBootPatchLevelRaw,
        expectedDeviceLocked:
          body.expectedDeviceLocked === undefined ? build.expectedDeviceLocked : body.expectedDeviceLocked,
        expectedVerifiedBootState:
          body.expectedVerifiedBootState === undefined
            ? build.expectedVerifiedBootState
            : body.expectedVerifiedBootState,
        enabled: body.enabled ?? build.enabled
      }
    });
    reply.send(updated);
  });

  app.delete("/device-families/:familyId/builds/:buildId", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId, buildId } = request.params as { familyId: string; buildId: string };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device not found"));
      return;
    }
    await prisma.buildPolicy.delete({ where: { id: buildId } });
    reply.send({ ok: true });
  });

  app.get("/attestation-servers", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const prisma = getPrisma();
    const authorities = await prisma.attestationAuthority.findMany({
      where: { enabled: true },
      include: { roots: true, status: true },
      orderBy: { createdAt: "desc" }
    });
    const org = await requireOemOrg(user.sub as string);
    const response = authorities.map((authority) => {
      const roots = authority.roots.filter((root) => !root.oemOrgId || root.oemOrgId === org.id);
      const keyTypes = roots.map((root) => {
        try {
          const cert = new crypto.X509Certificate(root.pem);
          return cert.publicKey.asymmetricKeyType || "unknown";
        } catch {
          return "unknown";
        }
      });
      return {
        id: authority.id,
        name: authority.name,
        baseUrl: authority.baseUrl,
        isLocal: authority.isLocal,
        statusCachedAt: authority.status?.fetchedAt || null,
        keyAvailability: {
          rsa: keyTypes.includes("rsa"),
          ecdsa: keyTypes.includes("ec")
        }
      };
    });
    reply.send(response);
  });

  app.get("/anchors", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { deviceFamilyId } = request.query as { deviceFamilyId?: string };
    const anchors = await prisma.deviceEntry.findMany({
      where: {
        oemOrgId: org.id,
        deviceFamilyId: deviceFamilyId || undefined
      },
      include: { authority: true, rsaRoot: true, ecdsaRoot: true, deviceFamily: true },
      orderBy: { createdAt: "desc" }
    });
    const response = anchors.map((anchor) => ({
      id: anchor.id,
      rsaSerialHex: anchor.rsaSerialHex,
      ecdsaSerialHex: anchor.ecdsaSerialHex,
      revokedAt: anchor.revokedAt,
      authorityId: anchor.authorityId,
      authorityName: anchor.authority.name,
      deviceFamilyId: anchor.deviceFamilyId,
      deviceCodename: anchor.deviceFamily.codename,
      createdAt: anchor.createdAt
    }));
    reply.send(response);
  });

  app.post("/anchors", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const body = request.body as {
      deviceFamilyId?: string;
      authorityId?: string;
      rsaSerialHex?: string;
      ecdsaSerialHex?: string;
    };
    if (!body.deviceFamilyId || !body.authorityId || !body.rsaSerialHex || !body.ecdsaSerialHex) {
      reply
        .code(400)
        .send(errorResponse("INVALID_REQUEST", "Missing deviceFamilyId, authority, or serials"));
      return;
    }
    const deviceFamily = await prisma.deviceFamily.findFirst({
      where: { id: body.deviceFamilyId, oemOrgId: org.id }
    });
    if (!deviceFamily) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device not found"));
      return;
    }
    const authority = await prisma.attestationAuthority.findUnique({
      where: { id: body.authorityId },
      include: { roots: true }
    });
    if (!authority || !authority.enabled) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Unknown attestation authority"));
      return;
    }
    const roots = authority.roots.filter((root) => !root.oemOrgId || root.oemOrgId === org.id);
    const { rsaRoot, ecdsaRoot } = pickRootsForAuthority(roots);
    if (!rsaRoot || !ecdsaRoot) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Authority missing RSA/ECDSA roots"));
      return;
    }
    const rsaSerial = body.rsaSerialHex.replace(/^0+/, "").toUpperCase();
    const ecdsaSerial = body.ecdsaSerialHex.replace(/^0+/, "").toUpperCase();
    const created = await prisma.deviceEntry.create({
      data: {
        oemOrgId: org.id,
        deviceFamilyId: deviceFamily.id,
        authorityId: authority.id,
        rsaRootId: rsaRoot.id,
        ecdsaRootId: ecdsaRoot.id,
        rsaSerialHex: rsaSerial,
        ecdsaSerialHex: ecdsaSerial,
        deviceId: deviceFamily.codename
      }
    });
    reply.send(created);
  });

  app.post("/anchors/:id/revoke", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { id } = request.params as { id: string };
    const anchor = await prisma.deviceEntry.findFirst({
      where: { id, oemOrgId: org.id }
    });
    if (!anchor) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Anchor not found"));
      return;
    }
    if (anchor.revokedAt) {
      reply.send({ ok: true, revokedAt: anchor.revokedAt });
      return;
    }
    const updated = await prisma.deviceEntry.update({
      where: { id },
      data: { revokedAt: new Date() }
    });
    reply.send({ ok: true, revokedAt: updated.revokedAt });
  });

  app.post("/anchors/generate-keybox", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const body = request.body as { deviceFamilyId?: string };
    if (!body.deviceFamilyId) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing deviceFamilyId"));
      return;
    }
    const deviceFamily = await prisma.deviceFamily.findFirst({
      where: { id: body.deviceFamilyId, oemOrgId: org.id }
    });
    if (!deviceFamily) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device not found"));
      return;
    }
    const localAuthority = await getLocalAuthority(prisma);
    if (!localAuthority) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Local authority not configured"));
      return;
    }
    const orgWithRoots = await ensureOemRoots(prisma, org);
    const authorityRoots = await prisma.attestationRoot.findMany({
      where: { authorityId: localAuthority.id, oemOrgId: org.id }
    });
    const { rsaRoot, ecdsaRoot } = pickRootsForAuthority(authorityRoots);
    if (!rsaRoot || !ecdsaRoot) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "OEM roots not available"));
      return;
    }
    const rsaSerialHex = crypto.randomBytes(16).toString("hex").toUpperCase();
    const ecdsaSerialHex = crypto.randomBytes(16).toString("hex").toUpperCase();
    const deviceId = deviceFamily.codename || `UA_${Date.now()}`;
    const anchor = await prisma.deviceEntry.create({
      data: {
        oemOrgId: org.id,
        deviceFamilyId: deviceFamily.id,
        authorityId: localAuthority.id,
        rsaRootId: rsaRoot.id,
        ecdsaRootId: ecdsaRoot.id,
        rsaSerialHex,
        ecdsaSerialHex,
        deviceId
      }
    });
    await prisma.auditLog.create({
      data: {
        actorUserId: user.sub as string,
        action: "KEYBOX_GENERATED",
        details: {
          deviceFamilyId: deviceFamily.id,
          anchorId: anchor.id,
          deviceId,
          authorityId: localAuthority.id
        }
      }
    });
    if (!orgWithRoots.rsaRootCertPem || !orgWithRoots.rsaRootKeyPem || !orgWithRoots.ecdsaRootCertPem || !orgWithRoots.ecdsaRootKeyPem) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "OEM roots not initialized"));
      return;
    }
    const xml = await generateKeyboxXmlWithDualRoots(
      {
        rootCertPem: orgWithRoots.rsaRootCertPem,
        rootPrivateKeyPem: orgWithRoots.rsaRootKeyPem
      },
      {
        rootCertPem: orgWithRoots.ecdsaRootCertPem,
        rootPrivateKeyPem: orgWithRoots.ecdsaRootKeyPem
      },
      deviceId,
      rsaSerialHex,
      ecdsaSerialHex
    );
    reply.header("Content-Type", "application/xml").send(xml);
  });

  app.get("/reports/failing-devices", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const prisma = getPrisma();
    const { deviceFamilyId } = request.query as { deviceFamilyId?: string };
    const reports = await prisma.deviceReport.findMany({
      where: {
        deviceFamilyId: deviceFamilyId || undefined,
        lastVerdict: {
          path: ["isTrusted"],
          equals: false
        }
      },
      orderBy: { lastSeen: "desc" }
    });
    reply.send(reports);
  });
}
