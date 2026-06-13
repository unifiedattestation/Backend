import crypto from "crypto";
import { FastifyInstance } from "fastify";
import { getPrisma } from "../lib/prisma";
import { requireUser } from "../lib/auth";
import { errorResponse, HttpError } from "../lib/errors";
import { generateKeyboxXmlWithDualRoots } from "../services/keybox";
import { generateIntermediateSignedByRoot } from "../services/rootAnchors";

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

async function getLocalAuthority(prisma: ReturnType<typeof getPrisma>) {
  return prisma.attestationAuthority.findFirst({
    where: { isLocal: true, enabled: true },
    include: { roots: true }
  });
}

async function ensureBackendRoots(prisma: ReturnType<typeof getPrisma>) {
  const localAuthority = await getLocalAuthority(prisma);
  if (!localAuthority) {
    throw new Error("Local authority not configured");
  }
  const activeRoot = await prisma.backendRootAnchor.findFirst({
    where: { revokedAt: null },
    orderBy: { createdAt: "desc" }
  });
  if (!activeRoot) {
    throw new Error("Backend root anchor not initialized");
  }
  const existingRoots = await prisma.attestationRoot.findMany({
    where: { authorityId: localAuthority.id, oemOrgId: null, backendRootId: activeRoot.id }
  });
  const hasRsa = existingRoots.some((root) => root.pem.trim() === activeRoot.rsaCertPem.trim());
  const hasEcdsa = existingRoots.some((root) => root.pem.trim() === activeRoot.ecdsaCertPem.trim());
  if (!hasRsa) {
    await prisma.attestationRoot.create({
      data: {
        authorityId: localAuthority.id,
        oemOrgId: null,
        backendRootId: activeRoot.id,
        pem: activeRoot.rsaCertPem,
        name: "UA Backend RSA Root"
      }
    });
  }
  if (!hasEcdsa) {
    await prisma.attestationRoot.create({
      data: {
        authorityId: localAuthority.id,
        oemOrgId: null,
        backendRootId: activeRoot.id,
        pem: activeRoot.ecdsaCertPem,
        name: "UA Backend ECDSA Root"
      }
    });
  }
  return {
    localAuthority,
    activeRoot,
    rsaRootCert: activeRoot.rsaCertPem,
    ecdsaRootCert: activeRoot.ecdsaCertPem
  };
}

async function loadOemTrustAnchor(prisma: ReturnType<typeof getPrisma>, org: { id: string; name: string }) {
  const record = await prisma.oemOrg.findUnique({ where: { id: org.id } });
  if (!record) {
    throw new Error("OEM org not found");
  }
  if (!record.rsaRootCertPem || !record.rsaRootKeyPem || !record.ecdsaRootCertPem || !record.ecdsaRootKeyPem) {
    throw new Error("OEM trust anchor not initialized");
  }
  return record;
}

async function generateOemTrustAnchor(
  prisma: ReturnType<typeof getPrisma>,
  org: { id: string; name: string }
) {
  const { rsaRootCert, ecdsaRootCert, activeRoot } = await ensureBackendRoots(prisma);
  const rsa = await generateIntermediateSignedByRoot(
    `UA ${org.name} RSA Intermediate`,
    "rsa",
    rsaRootCert,
    activeRoot.rsaKeyPem
  );
  const ecdsa = await generateIntermediateSignedByRoot(
    `UA ${org.name} ECDSA Intermediate`,
    "ecdsa",
    ecdsaRootCert,
    activeRoot.ecdsaKeyPem
  );
  const rsaSerialHex = new crypto.X509Certificate(rsa.certPem).serialNumber.toUpperCase();
  const ecdsaSerialHex = new crypto.X509Certificate(ecdsa.certPem).serialNumber.toUpperCase();
  const active = await prisma.oemTrustAnchor.findFirst({
    where: { oemOrgId: org.id, revokedAt: null }
  });
  if (active) {
    await prisma.oemTrustAnchor.update({
      where: { id: active.id },
      data: { revokedAt: new Date() }
    });
  }
  const anchor = await prisma.oemTrustAnchor.create({
    data: {
      oemOrgId: org.id,
      backendRootId: activeRoot.id,
      rsaCertPem: rsa.certPem,
      rsaKeyPem: rsa.keyPem,
      rsaSerialHex,
      ecdsaCertPem: ecdsa.certPem,
      ecdsaKeyPem: ecdsa.keyPem,
      ecdsaSerialHex
    }
  });
  const updatedOrg = await prisma.oemOrg.update({
    where: { id: org.id },
    data: {
      rsaRootCertPem: rsa.certPem,
      rsaRootKeyPem: rsa.keyPem,
      ecdsaRootCertPem: ecdsa.certPem,
      ecdsaRootKeyPem: ecdsa.keyPem
    }
  });
  return { anchor, org: updatedOrg };
}

function buildOemTrustAnchorXml(oem: {
  name: string;
  rsaRootCertPem: string;
  rsaRootKeyPem: string;
  ecdsaRootCertPem: string;
  ecdsaRootKeyPem: string;
}) {
  const wrap = (pem: string) => `\n${pem.trim()}\n`;
  return (
    `<?xml version="1.0"?>\n` +
    `<OemTrustAnchor>\n` +
    `  <Name>${oem.name}</Name>\n` +
    `  <Key algorithm="rsa">\n` +
    `    <PrivateKey format="pem">${wrap(oem.rsaRootKeyPem)}</PrivateKey>\n` +
    `    <Certificate format="pem">${wrap(oem.rsaRootCertPem)}</Certificate>\n` +
    `  </Key>\n` +
    `  <Key algorithm="ecdsa">\n` +
    `    <PrivateKey format="pem">${wrap(oem.ecdsaRootKeyPem)}</PrivateKey>\n` +
    `    <Certificate format="pem">${wrap(oem.ecdsaRootCertPem)}</Certificate>\n` +
    `  </Key>\n` +
    `</OemTrustAnchor>`
  );
}

function getRootAlgorithm(pem: string): "rsa" | "ecdsa" | null {
  try {
    const cert = new crypto.X509Certificate(pem);
    const type = cert.publicKey.asymmetricKeyType;
    if (type === "rsa") {
      return "rsa";
    }
    if (type === "ec") {
      return "ecdsa";
    }
  } catch {
    return null;
  }
  return null;
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

type ImportDeviceBody = {
  device?: {
    codename?: string;
    model?: string;
    manufacturer?: string;
    brand?: string;
    buildFingerprint?: string;
  };
  buildPolicy?: {
    verifiedBootKey?: string;
    verifiedBootHash?: string;
    verifiedBootState?: string;
    osVersionRaw?: string;
    osPatchLevelRaw?: string;
  };
  trustAnchor?: {
    ec?: {
      leafCertificatePem?: string;
      intermediateCertificatesPem?: string[];
      rootCertificatePem?: string;
    };
    rsa?: {
      leafCertificatePem?: string;
      intermediateCertificatesPem?: string[];
      rootCertificatePem?: string;
    };
  };
};

async function processDeviceImport(
  body: ImportDeviceBody,
  org: { id: string; name: string },
  prisma: ReturnType<typeof getPrisma>
) {
  const codename = body.device?.codename;
  const buildFingerprint = body.device?.buildFingerprint;
  const verifiedBootKey = body.buildPolicy?.verifiedBootKey;

  if (!codename) throw new HttpError(400, "INVALID_REQUEST", "Missing device.codename");
  if (!buildFingerprint || !verifiedBootKey)
    throw new HttpError(400, "INVALID_REQUEST", "Missing buildFingerprint or verifiedBootKey");

  const ecTa = body.trustAnchor?.ec;
  const rsaTa = body.trustAnchor?.rsa;

  if (!ecTa?.leafCertificatePem)
    throw new HttpError(400, "INVALID_REQUEST", "Missing trustAnchor.ec.leafCertificatePem");
  if (!ecTa.rootCertificatePem)
    throw new HttpError(400, "INVALID_REQUEST", "Missing trustAnchor.ec.rootCertificatePem");

  const ecIntermediates = ecTa.intermediateCertificatesPem ?? [];
  if (ecIntermediates.length === 0)
    throw new HttpError(400, "INVALID_REQUEST", "trustAnchor.ec.intermediateCertificatesPem is empty — expected exactly 2 intermediates");
  if (ecIntermediates.length === 1)
    throw new HttpError(400, "INVALID_REQUEST", "trustAnchor.ec has only 1 intermediate — expected exactly 2 (device-batch cert + Google upper intermediate)");
  if (ecIntermediates.length > 2)
    throw new HttpError(400, "RKP_NOT_SUPPORTED", "trustAnchor.ec has more than 2 intermediates — Remote Key Provisioning (RKP) chains are not supported yet");

  if (rsaTa) {
    if (!rsaTa.leafCertificatePem)
      throw new HttpError(400, "INVALID_REQUEST", "Missing trustAnchor.rsa.leafCertificatePem");
    if (!rsaTa.rootCertificatePem)
      throw new HttpError(400, "INVALID_REQUEST", "Missing trustAnchor.rsa.rootCertificatePem");
    const rsaIntermediates = rsaTa.intermediateCertificatesPem ?? [];
    if (rsaIntermediates.length === 0)
      throw new HttpError(400, "INVALID_REQUEST", "trustAnchor.rsa.intermediateCertificatesPem is empty — expected exactly 2 intermediates");
    if (rsaIntermediates.length === 1)
      throw new HttpError(400, "INVALID_REQUEST", "trustAnchor.rsa has only 1 intermediate — expected exactly 2 (device-batch cert + Google upper intermediate)");
    if (rsaIntermediates.length > 2)
      throw new HttpError(400, "RKP_NOT_SUPPORTED", "trustAnchor.rsa has more than 2 intermediates — Remote Key Provisioning (RKP) chains are not supported yet");
  }

  const ecOemLeafPem      = ecIntermediates[0];
  const ecOemIntermediatePem = ecIntermediates[1];
  const ecRootPem         = ecTa.rootCertificatePem;
  const rsaOemLeafPem     = rsaTa?.intermediateCertificatesPem?.[0] ?? null;
  const rsaOemIntermediatePem = rsaTa?.intermediateCertificatesPem?.[1] ?? null;

  let ecLeafSerial: string;
  let ecIntermediateSerial: string;
  let rsaLeafSerial: string | null = null;
  let rsaIntermediateSerial: string | null = null;

  try {
    const serial = (pem: string) =>
      new crypto.X509Certificate(pem).serialNumber.replace(/^0+/, "").toUpperCase();
    ecLeafSerial = serial(ecOemLeafPem);
    ecIntermediateSerial = serial(ecOemIntermediatePem);
    if (rsaOemLeafPem && rsaOemIntermediatePem) {
      rsaLeafSerial = serial(rsaOemLeafPem);
      rsaIntermediateSerial = serial(rsaOemIntermediatePem);
    }
  } catch (e) {
    throw new HttpError(400, "INVALID_REQUEST", "Failed to parse certificates: " + (e as Error).message);
  }

  const certFingerprint = (pem: string): string | null => {
    try { return new crypto.X509Certificate(pem).fingerprint256; }
    catch { return null; }
  };

  const ecRootFp = certFingerprint(ecRootPem);
  if (!ecRootFp) throw new HttpError(400, "INVALID_REQUEST", "Cannot parse EC root certificate");

  const allRegisteredRoots = await prisma.attestationRoot.findMany({ include: { authority: true } });
  const enabledRoots = allRegisteredRoots.filter((r) => r.authority.enabled);

  let matchedAuthority: (typeof allRegisteredRoots)[0]["authority"] | null = null;
  for (const r of enabledRoots) {
    const fp = certFingerprint(r.pem);
    if (fp !== null && fp === ecRootFp) {
      matchedAuthority = r.authority;
      break;
    }
  }

  if (matchedAuthority === null) {
    let ecSubject = "(unknown)";
    try { ecSubject = new crypto.X509Certificate(ecRootPem).subject; } catch { /* ignore */ }
    throw new HttpError(400, "UNKNOWN_ROOT",
      `Root certificate is not registered on this backend (subject: ${ecSubject}). ` +
      `Add this root under Attestation Authorities before importing devices.`
    );
  }

  const warnings: string[] = [];

  let deviceFamily = await prisma.deviceFamily.findFirst({ where: { oemOrgId: org.id, codename } });
  const familyCreated = !deviceFamily;
  if (!deviceFamily) {
    deviceFamily = await prisma.deviceFamily.create({
      data: { name: codename, codename, model: body.device?.model ?? null, oemOrgId: org.id }
    });
  }

  let buildPolicy = await prisma.buildPolicy.findFirst({
    where: { deviceFamilyId: deviceFamily.id, buildFingerprint, verifiedBootKeyHex: verifiedBootKey.toLowerCase() }
  });
  const policyCreated = !buildPolicy;
  if (!buildPolicy) {
    buildPolicy = await prisma.buildPolicy.create({
      data: {
        deviceFamilyId: deviceFamily.id,
        buildFingerprint,
        verifiedBootKeyHex: verifiedBootKey.toLowerCase(),
        verifiedBootHashHex: body.buildPolicy?.verifiedBootHash?.toLowerCase() ?? null,
        osVersionRaw: body.buildPolicy?.osVersionRaw ? parseInt(body.buildPolicy.osVersionRaw) : null,
        minOsPatchLevelRaw: body.buildPolicy?.osPatchLevelRaw ? parseInt(body.buildPolicy.osPatchLevelRaw) : null
      }
    });
  }

  let anchor: { id: string; rsaSerialHex: string; ecdsaSerialHex: string } | null = null;
  if (rsaLeafSerial) {
    const activeCount = await prisma.deviceEntry.count({ where: { oemOrgId: org.id, revokedAt: null } });
    if (activeCount > 0) {
      warnings.push("Active anchor already exists; revoke it before registering a new one");
    } else {
      try {
        anchor = await prisma.deviceEntry.create({
          data: {
            oemOrgId: org.id,
            deviceFamilyId: deviceFamily.id,
            authorityId: matchedAuthority.id,
            rsaSerialHex: rsaLeafSerial,
            ecdsaSerialHex: ecLeafSerial,
            rsaIntermediateSerialHex: rsaIntermediateSerial ?? null,
            ecdsaIntermediateSerialHex: ecIntermediateSerial ?? null,
            deviceId: codename
          }
        });
      } catch (e: any) {
        if (e?.code === "P2002") {
          warnings.push("Device anchor already registered (serial already exists)");
        } else {
          throw e;
        }
      }
    }
  } else {
    warnings.push("RSA trust anchor not present in JSON; anchor not registered (only EC available)");
  }

  return {
    deviceFamily: { id: deviceFamily.id, codename: deviceFamily.codename, model: deviceFamily.model, created: familyCreated },
    buildPolicy: { id: buildPolicy.id, buildFingerprint: buildPolicy.buildFingerprint, created: policyCreated },
    anchor,
    matchedAuthorityName: matchedAuthority.name,
    warnings
  };
}

export default async function oemRoutes(app: FastifyInstance) {
  app.get("/profile", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const { apiTokenHash: _hash, ...safe } = org as any;
    reply.send(safe);
  });

  app.post("/profile/token", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) return;
    const prisma = getPrisma();
    const org = await requireOemOrg(user.sub as string);
    const raw = `ua_oem_${crypto.randomBytes(24).toString("hex")}`;
    const prefix = raw.slice(0, 12);
    const hash = crypto.createHash("sha256").update(raw).digest("hex");
    await prisma.oemOrg.update({
      where: { id: org.id },
      data: { apiTokenHash: hash, apiTokenPrefix: prefix }
    });
    reply.send({ token: raw, prefix });
  });

  app.delete("/profile/token", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) return;
    const prisma = getPrisma();
    const org = await requireOemOrg(user.sub as string);
    await prisma.oemOrg.update({
      where: { id: org.id },
      data: { apiTokenHash: null, apiTokenPrefix: null }
    });
    reply.send({ ok: true });
  });

  // Public endpoint — authenticated by OEM API token (Bearer), not JWT
  app.post("/device/submit", async (request, reply) => {
    const authHeader = (request.headers["authorization"] as string) || "";
    if (!authHeader.startsWith("Bearer ")) {
      reply.code(401).send(errorResponse("UNAUTHORIZED", "Missing or invalid Authorization header"));
      return;
    }
    const token = authHeader.slice(7).trim();
    const hash = crypto.createHash("sha256").update(token).digest("hex");
    const prisma = getPrisma();
    const org = await prisma.oemOrg.findFirst({ where: { apiTokenHash: hash } });
    if (!org) {
      reply.code(401).send(errorResponse("UNAUTHORIZED", "Invalid OEM API token"));
      return;
    }
    const body = request.body as ImportDeviceBody;
    const result = await processDeviceImport(body, org, prisma);
    reply.send(result);
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

  app.post("/profile/generate-trust-anchor", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const prisma = getPrisma();
    const org = await requireOemOrg(user.sub as string);
    await prisma.deviceEntry.updateMany({
      where: { oemOrgId: org.id, revokedAt: null },
      data: { revokedAt: new Date() }
    });
    let updated;
    let anchor;
    try {
    const result = await generateOemTrustAnchor(prisma, org);
      updated = result.org;
      anchor = result.anchor;
    } catch (error) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", (error as Error).message));
      return;
    }
    await prisma.auditLog.create({
      data: {
        actorUserId: user.sub as string,
        action: "OEM_TRUST_ANCHOR_GENERATED",
        details: { oemOrgId: org.id, anchorId: anchor?.id }
      }
    });
    if (anchor) {
      const xml = buildOemTrustAnchorXml({
        name: org.name,
        rsaRootCertPem: anchor.rsaCertPem,
        rsaRootKeyPem: anchor.rsaKeyPem,
        ecdsaRootCertPem: anchor.ecdsaCertPem,
        ecdsaRootKeyPem: anchor.ecdsaKeyPem
      });
      reply.header("Content-Type", "application/xml").send(xml);
      return;
    }
    reply
      .code(400)
      .send(errorResponse("INVALID_REQUEST", "OEM trust anchor not generated"));
  });

  app.post("/profile/revoke-trust-anchor", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const prisma = getPrisma();
    const org = await requireOemOrg(user.sub as string);
    const current = await prisma.oemOrg.findUnique({ where: { id: org.id } });
    if (!current?.rsaRootCertPem || !current.ecdsaRootCertPem) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "OEM trust anchor not found"));
      return;
    }
    let rsaSerial = "";
    let ecdsaSerial = "";
    try {
      rsaSerial = new crypto.X509Certificate(current.rsaRootCertPem).serialNumber.toUpperCase();
      ecdsaSerial = new crypto.X509Certificate(current.ecdsaRootCertPem).serialNumber.toUpperCase();
    } catch (error) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Failed to parse OEM trust anchor"));
      return;
    }
    await prisma.deviceEntry.updateMany({
      where: {
        oemOrgId: org.id,
        revokedAt: null,
        OR: [
          { rsaIntermediateSerialHex: rsaSerial },
          { ecdsaIntermediateSerialHex: ecdsaSerial }
        ]
      },
      data: { revokedAt: new Date() }
    });
    const activeAnchor = await prisma.oemTrustAnchor.findFirst({
      where: { oemOrgId: org.id, revokedAt: null }
    });
    if (activeAnchor) {
      await prisma.oemTrustAnchor.update({
        where: { id: activeAnchor.id },
        data: { revokedAt: new Date() }
      });
    }
    const updated = await prisma.oemOrg.update({
      where: { id: org.id },
      data: {
        rsaRootCertPem: null,
        rsaRootKeyPem: null,
        ecdsaRootCertPem: null,
        ecdsaRootKeyPem: null
      }
    });
    await prisma.auditLog.create({
      data: {
        actorUserId: user.sub as string,
        action: "OEM_TRUST_ANCHOR_REVOKED",
        details: { oemOrgId: org.id }
      }
    });
    reply.send({
      ok: true,
      rsaReady: Boolean(updated.rsaRootCertPem && updated.rsaRootKeyPem),
      ecdsaReady: Boolean(updated.ecdsaRootCertPem && updated.ecdsaRootKeyPem)
    });
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
      codename?: string;
      model?: string;
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
        enabled: body.enabled ?? family.enabled,
        codename: body.codename ?? family.codename,
        model: body.model ?? family.model,
        name: body.codename ?? family.codename ?? family.name
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
      buildFingerprint?: string;
      verifiedBootKeyHex?: string;
      verifiedBootHashHex?: string;
      osVersionRaw?: number;
      minOsPatchLevelRaw?: number;
      enabled?: boolean;
    };
    if (!body.buildFingerprint || !body.verifiedBootKeyHex) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing build fingerprint or verifiedBootKeyHex"));
      return;
    }
    const created = await prisma.buildPolicy.create({
      data: {
        deviceFamilyId: family.id,
        buildFingerprint: body.buildFingerprint,
        verifiedBootKeyHex: body.verifiedBootKeyHex.toLowerCase(),
        verifiedBootHashHex: body.verifiedBootHashHex?.toLowerCase(),
        osVersionRaw: body.osVersionRaw,
        minOsPatchLevelRaw: body.minOsPatchLevelRaw,
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
      buildFingerprint?: string;
      verifiedBootKeyHex?: string;
      verifiedBootHashHex?: string | null;
      osVersionRaw?: number | null;
      minOsPatchLevelRaw?: number | null;
      enabled?: boolean;
    };
    const updated = await prisma.buildPolicy.update({
      where: { id: build.id },
      data: {
        buildFingerprint: body.buildFingerprint ?? build.buildFingerprint,
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
      include: { authority: true, deviceFamily: true },
      orderBy: { createdAt: "desc" }
    });
    const response = anchors.map((anchor) => ({
      id: anchor.id,
      rsaSerialHex: anchor.rsaSerialHex,
      ecdsaSerialHex: anchor.ecdsaSerialHex,
      rsaIntermediateSerialHex: anchor.rsaIntermediateSerialHex,
      ecdsaIntermediateSerialHex: anchor.ecdsaIntermediateSerialHex,
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
      rsaIntermediateSerialHex?: string;
      ecdsaIntermediateSerialHex?: string;
    };
    if (
      !body.deviceFamilyId ||
      !body.authorityId ||
      !body.rsaSerialHex ||
      !body.ecdsaSerialHex ||
      !body.rsaIntermediateSerialHex ||
      !body.ecdsaIntermediateSerialHex
    ) {
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
    const activeAnchors = await prisma.deviceEntry.count({
      where: { oemOrgId: org.id, revokedAt: null }
    });
    if (activeAnchors > 0) {
      reply
        .code(400)
        .send(errorResponse("INVALID_REQUEST", "Revoke existing anchor before registering a new one"));
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
    if (roots.length === 0) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Authority missing usable roots"));
      return;
    }
    const rsaSerial = body.rsaSerialHex.replace(/^0+/, "").toUpperCase();
    const ecdsaSerial = body.ecdsaSerialHex.replace(/^0+/, "").toUpperCase();
    const rsaIntermediateSerial = body.rsaIntermediateSerialHex.replace(/^0+/, "").toUpperCase();
    const ecdsaIntermediateSerial = body.ecdsaIntermediateSerialHex.replace(/^0+/, "").toUpperCase();
    try {
      const created = await prisma.deviceEntry.create({
        data: {
          oemOrgId: org.id,
          deviceFamilyId: deviceFamily.id,
          authorityId: authority.id,
          rsaSerialHex: rsaSerial,
          ecdsaSerialHex: ecdsaSerial,
          rsaIntermediateSerialHex: rsaIntermediateSerial,
          ecdsaIntermediateSerialHex: ecdsaIntermediateSerial,
          deviceId: deviceFamily.codename
        }
      });
      reply.send(created);
    } catch (error: any) {
      if (error?.code === "P2002") {
        reply
          .code(409)
          .send(errorResponse("DUPLICATE_SERIAL", "Serial already registered"));
        return;
      }
      throw error;
    }
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

  app.delete("/anchors/:id", async (request, reply) => {
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
    await prisma.deviceEntry.delete({ where: { id } });
    reply.send({ ok: true });
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
    const activeAnchors = await prisma.deviceEntry.count({
      where: { oemOrgId: org.id, revokedAt: null }
    });
    if (activeAnchors > 0) {
      reply
        .code(400)
        .send(errorResponse("INVALID_REQUEST", "Revoke existing anchor before generating a new one"));
      return;
    }
    let localAuthority;
    let rsaRootCert: string;
    let ecdsaRootCert: string;
    let orgWithRoots;
    try {
      const backendRoots = await ensureBackendRoots(prisma);
      localAuthority = backendRoots.localAuthority;
      rsaRootCert = backendRoots.rsaRootCert;
      ecdsaRootCert = backendRoots.ecdsaRootCert;
      orgWithRoots = await loadOemTrustAnchor(prisma, org);
    } catch (error) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", (error as Error).message));
      return;
    }
    const authorityRoots = await prisma.attestationRoot.findMany({
      where: { authorityId: localAuthority.id, oemOrgId: null }
    });
    const { rsaRoot, ecdsaRoot } = pickRootsForAuthority(authorityRoots);
    if (!rsaRoot || !ecdsaRoot) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "OEM roots not available"));
      return;
    }
    const rsaSerialHex = crypto.randomBytes(16).toString("hex").toUpperCase();
    const ecdsaSerialHex = crypto.randomBytes(16).toString("hex").toUpperCase();
    const deviceId = deviceFamily.codename || `UA_${Date.now()}`;
    const rsaIntermediateSerialHex = new crypto.X509Certificate(
      orgWithRoots.rsaRootCertPem
    ).serialNumber.toUpperCase();
    const ecdsaIntermediateSerialHex = new crypto.X509Certificate(
      orgWithRoots.ecdsaRootCertPem
    ).serialNumber.toUpperCase();
    const anchor = await prisma.deviceEntry.create({
      data: {
        oemOrgId: org.id,
        deviceFamilyId: deviceFamily.id,
        authorityId: localAuthority.id,
        rsaSerialHex,
        ecdsaSerialHex,
        rsaIntermediateSerialHex,
        ecdsaIntermediateSerialHex,
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
    const xml = await generateKeyboxXmlWithDualRoots(
      {
        issuerCertPem: orgWithRoots.rsaRootCertPem,
        issuerPrivateKeyPem: orgWithRoots.rsaRootKeyPem,
        rootCertPem: rsaRootCert
      },
      {
        issuerCertPem: orgWithRoots.ecdsaRootCertPem,
        issuerPrivateKeyPem: orgWithRoots.ecdsaRootKeyPem,
        rootCertPem: ecdsaRootCert
      },
      deviceId,
      rsaSerialHex,
      ecdsaSerialHex
    );
    reply.header("Content-Type", "application/xml").send(xml);
  });

  app.post("/import-device", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) return;
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const result = await processDeviceImport(request.body as ImportDeviceBody, org, prisma);
    reply.send(result);
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
