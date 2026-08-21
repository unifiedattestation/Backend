import { PrismaClient } from "@prisma/client";

export function buildDeviceSlugBase(manufacturer: string, codename: string): string {
  const clean = (value: string) =>
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  return `${clean(manufacturer)}-${clean(codename)}`;
}

export async function ensureUniqueDeviceSlug(
  prisma: PrismaClient,
  base: string,
): Promise<string> {
  let candidate = base;
  let n = 2;
  while (await prisma.deviceFamily.findUnique({ where: { slug: candidate } })) {
    candidate = `${base}-${n}`;
    n += 1;
  }
  return candidate;
}
