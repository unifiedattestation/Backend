import fs from "fs";
import { Config } from "../lib/config";
import { getPrisma } from "../lib/prisma";

const LOCAL_AUTHORITY_NAME = "Unified Attestation (Local)";

export async function ensureLocalAuthority(config: Config) {
  const rootPath = config.ua_root_cert_path;
  if (!rootPath || !fs.existsSync(rootPath)) {
    return;
  }
  const pem = fs.readFileSync(rootPath, "utf8").trim();
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
              pem,
              name: "UA Root"
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
    where: { authorityId: existing.id }
  });
  const match = roots.find((root) => root.pem.trim() === pem);
  if (!match) {
    await prisma.attestationRoot.deleteMany({ where: { authorityId: existing.id } });
    await prisma.attestationRoot.create({
      data: {
        authorityId: existing.id,
        pem,
        name: "UA Root"
      }
    });
  }
  return existing;
}
