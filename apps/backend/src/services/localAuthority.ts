import fs from "fs";
import { Config } from "../lib/config";
import { getPrisma } from "../lib/prisma";

const LOCAL_AUTHORITY_NAME = "Unified Attestation (Local)";

export async function ensureLocalAuthority(config: Config) {
  const rsaRootPath = config.ua_root_rsa_cert_path;
  const ecdsaRootPath = config.ua_root_ecdsa_cert_path;
  if (!rsaRootPath || !ecdsaRootPath || !fs.existsSync(rsaRootPath) || !fs.existsSync(ecdsaRootPath)) {
    return;
  }
  const rsaPem = fs.readFileSync(rsaRootPath, "utf8").trim();
  const ecdsaPem = fs.readFileSync(ecdsaRootPath, "utf8").trim();
  const prisma = getPrisma();
  const existing = await prisma.attestationAuthority.findFirst({
    where: { isLocal: true }
  });
  const baseUrl = `${config.externalUrl || "http://localhost:3001"}/api/v1/info`;
  if (!existing) {
    const authority = await prisma.attestationAuthority.create({
      data: {
        name: LOCAL_AUTHORITY_NAME,
        baseUrl,
        enabled: true,
        isLocal: true,
        roots: {
          create: [
            {
              pem: rsaPem,
              name: "UA Root RSA"
            },
            {
              pem: ecdsaPem,
              name: "UA Root ECDSA"
            }
          ]
        }
      }
    });
    return authority;
  }
  if (existing.baseUrl !== baseUrl || existing.name !== LOCAL_AUTHORITY_NAME) {
    await prisma.attestationAuthority.update({
      where: { id: existing.id },
      data: { baseUrl, name: LOCAL_AUTHORITY_NAME }
    });
  }
  const roots = await prisma.attestationRoot.findMany({
    where: { authorityId: existing.id, oemOrgId: null }
  });
  const hasRsa = roots.some((root) => root.pem.trim() === rsaPem);
  const hasEcdsa = roots.some((root) => root.pem.trim() === ecdsaPem);
  if (!hasRsa || !hasEcdsa) {
    await prisma.attestationRoot.deleteMany({ where: { authorityId: existing.id, oemOrgId: null } });
    await prisma.attestationRoot.createMany({
      data: [
        { authorityId: existing.id, pem: rsaPem, name: "UA Root RSA" },
        { authorityId: existing.id, pem: ecdsaPem, name: "UA Root ECDSA" }
      ]
    });
  }
  return existing;
}
