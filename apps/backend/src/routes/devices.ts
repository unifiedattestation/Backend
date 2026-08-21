import { FastifyInstance } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import { DeviceDetailResponseSchema, DeviceListQuerySchema, DeviceListResponseSchema } from "@ua/common";
import { getPrisma } from "../lib/prisma";
import { errorResponse } from "../lib/errors";

export default async function devicesRoutes(app: FastifyInstance) {
  app.get(
    "/",
    {
      schema: {
        querystring: {
          type: "object",
          properties: {
            search: { type: "string" },
            page: { type: "string" },
            pageSize: { type: "string" }
          }
        },
        response: { 200: zodToJsonSchema(DeviceListResponseSchema) }
      }
    },
    async (request, reply) => {
      if (!app.publicRateLimiter.take(request.ip)) {
        reply.code(429).send(errorResponse("FORBIDDEN", "Rate limit exceeded"));
        return;
      }

      let query;
      try {
        query = DeviceListQuerySchema.parse(request.query);
      } catch {
        reply.code(400).send(errorResponse("INVALID_REQUEST", "Invalid query parameters"));
        return;
      }

      const prisma = getPrisma();
      const where = {
        enabled: true,
        ...(query.search
          ? {
              OR: [
                { name: { contains: query.search, mode: "insensitive" as const } },
                { codename: { contains: query.search, mode: "insensitive" as const } },
                { model: { contains: query.search, mode: "insensitive" as const } },
                { manufacturer: { contains: query.search, mode: "insensitive" as const } },
                { brand: { contains: query.search, mode: "insensitive" as const } },
                { slug: { contains: query.search, mode: "insensitive" as const } },
                { oemOrg: { name: { contains: query.search, mode: "insensitive" as const } } }
              ]
            }
          : {})
      };

      const [total, families] = await Promise.all([
        prisma.deviceFamily.count({ where }),
        prisma.deviceFamily.findMany({
          where,
          select: {
            slug: true,
            manufacturer: true,
            brand: true,
            model: true,
            codename: true,
            name: true,
            enabled: true,
            createdAt: true,
            oemOrg: { select: { name: true } }
          },
          orderBy: [{ manufacturer: "asc" }, { name: "asc" }],
          skip: (query.page - 1) * query.pageSize,
          take: query.pageSize
        })
      ]);

      reply.send({
        items: families.map((f) => ({
          slug: f.slug,
          manufacturer: f.manufacturer,
          brand: f.brand,
          model: f.model,
          codename: f.codename,
          name: f.name,
          enabled: f.enabled,
          createdAt: f.createdAt.toISOString(),
          oemOrgName: f.oemOrg.name
        })),
        page: query.page,
        pageSize: query.pageSize,
        total,
        totalPages: Math.max(1, Math.ceil(total / query.pageSize))
      });
    }
  );

  app.get(
    "/:slug",
    {
      schema: {
        response: { 200: zodToJsonSchema(DeviceDetailResponseSchema) }
      }
    },
    async (request, reply) => {
      if (!app.publicRateLimiter.take(request.ip)) {
        reply.code(429).send(errorResponse("FORBIDDEN", "Rate limit exceeded"));
        return;
      }

      const { slug } = request.params as { slug: string };
      const prisma = getPrisma();

      const family = await prisma.deviceFamily.findFirst({
        where: { slug, enabled: true },
        select: {
          slug: true,
          manufacturer: true,
          brand: true,
          model: true,
          codename: true,
          name: true,
          enabled: true,
          createdAt: true,
          oemOrg: { select: { name: true } },
          buildPolicies: {
            where: { enabled: true },
            orderBy: { createdAt: "desc" },
            select: {
              buildFingerprint: true,
              verifiedBootKeyHex: true,
              verifiedBootHashHex: true,
              osVersionRaw: true,
              minOsPatchLevelRaw: true,
              createdAt: true
            }
          },
          deviceEntries: {
            where: { revokedAt: null },
            orderBy: { createdAt: "desc" },
            take: 1,
            select: {
              rsaSerialHex: true,
              ecdsaSerialHex: true,
              rsaIntermediateSerialHex: true,
              ecdsaIntermediateSerialHex: true,
              authority: { select: { name: true, baseUrl: true } }
            }
          }
        }
      });

      if (!family) {
        reply.code(404).send(errorResponse("NOT_FOUND", "Device not found"));
        return;
      }

      const entry = family.deviceEntries[0];
      reply.send({
        slug: family.slug,
        manufacturer: family.manufacturer,
        brand: family.brand,
        model: family.model,
        codename: family.codename,
        name: family.name,
        enabled: family.enabled,
        createdAt: family.createdAt.toISOString(),
        oemOrgName: family.oemOrg.name,
        certificate: entry
          ? {
              rsaLeafSerialHex: entry.rsaSerialHex,
              rsaIntermediateSerialHex: entry.rsaIntermediateSerialHex,
              ecdsaLeafSerialHex: entry.ecdsaSerialHex,
              ecdsaIntermediateSerialHex: entry.ecdsaIntermediateSerialHex,
              authority: {
                name: entry.authority.name,
                rootCertificatesUrl: `${entry.authority.baseUrl.replace(/\/+$/, "")}/root`
              }
            }
          : null,
        builds: family.buildPolicies.map((b) => ({
          ...b,
          createdAt: b.createdAt.toISOString()
        }))
      });
    }
  );
}
