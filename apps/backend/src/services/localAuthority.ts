import { getPrisma } from "../lib/prisma";

const LOCAL_AUTHORITY_NAME = "Unified Attestation (Local)";

export async function ensureLocalAuthority(baseUrl: string) {
  const prisma = getPrisma();
  const existing = await prisma.attestationAuthority.findFirst({
    where: { isLocal: true }
  });
  const infoUrl = `${baseUrl.replace(/\/+$/, "")}/api/v1/info`;
  if (!existing) {
    const authority = await prisma.attestationAuthority.create({
      data: {
        name: LOCAL_AUTHORITY_NAME,
        baseUrl: infoUrl,
        enabled: true,
        isLocal: true
      }
    });
    return authority;
  }
  if (existing.baseUrl !== infoUrl || existing.name !== LOCAL_AUTHORITY_NAME) {
    await prisma.attestationAuthority.update({
      where: { id: existing.id },
      data: { baseUrl: infoUrl, name: LOCAL_AUTHORITY_NAME }
    });
  }
  return existing;
}
