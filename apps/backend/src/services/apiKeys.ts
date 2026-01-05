import crypto from "crypto";
import { getPrisma } from "../lib/prisma";

function hashKey(raw: string): string {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

export function generateApiKey(): { raw: string; prefix: string; hash: string } {
  const raw = `ua_${crypto.randomBytes(24).toString("hex")}`;
  const prefix = raw.slice(0, 8);
  const hash = hashKey(raw);
  return { raw, prefix, hash };
}

export async function verifyApiKey(raw: string) {
  const prisma = getPrisma();
  const hash = hashKey(raw);
  const key = await prisma.projectApiKey.findFirst({
    where: {
      keyHash: hash,
      revokedAt: null
    },
    include: {
      project: {
        include: { org: true }
      }
    }
  });
  return key;
}
