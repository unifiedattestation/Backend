import { getPrisma } from "../lib/prisma";
import { buildDeviceSlugBase, ensureUniqueDeviceSlug } from "../lib/slug";

const RAW_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function backfillDeviceFamilySlugs() {
  const prisma = getPrisma();
  const families = await prisma.deviceFamily.findMany({
    select: {
      id: true,
      slug: true,
      codename: true,
      oemOrg: { select: { manufacturer: true } }
    }
  });

  for (const family of families) {
    if (!RAW_UUID.test(family.slug)) continue;
    const base = buildDeviceSlugBase(family.oemOrg.manufacturer || "device", family.codename || family.id);
    const slug = await ensureUniqueDeviceSlug(prisma, base);
    await prisma.deviceFamily.update({ where: { id: family.id }, data: { slug } });
  }
}
