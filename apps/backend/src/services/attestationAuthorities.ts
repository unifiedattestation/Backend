import { getPrisma } from "../lib/prisma";

const STATUS_TTL_MS = 60 * 60 * 1000;

type AuthorityStatus = {
  revokedSerials: string[];
  suspendedSerials: string[];
};

function normalizeSerial(serial: string): string {
  return serial.replace(/^0+/, "").toUpperCase();
}

export async function getAuthorityForSerial(serialNumber: string) {
  const prisma = getPrisma();
  const normalized = normalizeSerial(serialNumber);
  const entry = await prisma.deviceEntry.findFirst({
    where: {
      OR: [{ rsaSerialHex: normalized }, { ecdsaSerialHex: normalized }]
    },
    include: {
      authority: true,
      rsaRoot: true,
      ecdsaRoot: true,
      deviceFamily: true
    }
  });
  return entry;
}

export async function getAuthorityRoots(authorityId: string) {
  const prisma = getPrisma();
  return prisma.attestationRoot.findMany({ where: { authorityId } });
}

export async function getAuthorityStatus(authorityId: string, baseUrl: string): Promise<AuthorityStatus> {
  const prisma = getPrisma();
  const cache = await prisma.attestationStatusCache.findUnique({ where: { authorityId } });
  if (cache && Date.now() - cache.fetchedAt.getTime() < STATUS_TTL_MS) {
    return {
      revokedSerials: (cache.revokedSerials as string[]) || [],
      suspendedSerials: (cache.suspendedSerials as string[]) || []
    };
  }
  const res = await fetch(`${baseUrl.replace(/\/$/, "")}/status`);
  if (!res.ok) {
    if (cache) {
      return {
        revokedSerials: (cache.revokedSerials as string[]) || [],
        suspendedSerials: (cache.suspendedSerials as string[]) || []
      };
    }
    throw new Error("Failed to fetch authority status");
  }
  const payload = (await res.json()) as AuthorityStatus;
  const normalizedRevoked = (payload.revokedSerials || []).map(normalizeSerial);
  const normalizedSuspended = (payload.suspendedSerials || []).map(normalizeSerial);
  await prisma.attestationStatusCache.upsert({
    where: { authorityId },
    update: {
      revokedSerials: normalizedRevoked,
      suspendedSerials: normalizedSuspended,
      fetchedAt: new Date()
    },
    create: {
      authorityId,
      revokedSerials: normalizedRevoked,
      suspendedSerials: normalizedSuspended,
      fetchedAt: new Date()
    }
  });
  return {
    revokedSerials: normalizedRevoked,
    suspendedSerials: normalizedSuspended
  };
}

export async function refreshAuthorityBundle(authorityId: string, baseUrl: string) {
  const prisma = getPrisma();
  const rootRes = await fetch(`${baseUrl.replace(/\/$/, "")}/root`);
  if (!rootRes.ok) {
    throw new Error("Failed to fetch authority roots");
  }
  const rootPayload = (await rootRes.json()) as { roots?: string[] } | string[];
  const roots = Array.isArray(rootPayload) ? rootPayload : rootPayload.roots || [];
  await prisma.attestationRoot.deleteMany({ where: { authorityId } });
  await prisma.attestationRoot.createMany({
    data: roots.map((pem) => ({
      authorityId,
      pem
    }))
  });
  await getAuthorityStatus(authorityId, baseUrl);
}
