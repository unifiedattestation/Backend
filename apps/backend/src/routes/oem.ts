import { FastifyInstance } from "fastify";
import { getPrisma } from "../lib/prisma";
import { requireUser } from "../lib/auth";
import { errorResponse } from "../lib/errors";

export default async function oemRoutes(app: FastifyInstance) {
  app.post("/org", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "oem" && user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "OEM role required"));
      return;
    }
    const prisma = getPrisma();
    const existing = await prisma.oemOrg.findFirst({ where: { ownerUserId: user.sub as string } });
    if (existing) {
      reply.send(existing);
      return;
    }
    const org = await prisma.oemOrg.create({
      data: {
        name: `OEM-${user.sub}`,
        ownerUserId: user.sub as string
      }
    });
    reply.send(org);
  });

  app.get("/trust-roots", async (request, reply) => {
    const user = requireUser(request);
    const prisma = getPrisma();
    const org = await prisma.oemOrg.findFirst({ where: { ownerUserId: user.sub as string } });
    if (!org) {
      reply.code(404).send(errorResponse("FORBIDDEN", "OEM org not found"));
      return;
    }
    const roots = await prisma.deviceTrustRoot.findMany({ where: { oemOrgId: org.id } });
    reply.send(roots);
  });

  app.post("/trust-roots", async (request, reply) => {
    const user = requireUser(request);
    const prisma = getPrisma();
    const org = await prisma.oemOrg.findFirst({ where: { ownerUserId: user.sub as string } });
    if (!org) {
      reply.code(404).send(errorResponse("FORBIDDEN", "OEM org not found"));
      return;
    }
    const body = request.body as {
      name: string;
      publicKeyPem?: string;
      jwksUrl?: string;
      backendId: string;
    };
    if (!body.name) {
      reply.code(400).send(errorResponse("INVALID_ARTIFACT", "Missing trust root name"));
      return;
    }
    const root = await prisma.deviceTrustRoot.create({
      data: {
        name: body.name,
        publicKeyPem: body.publicKeyPem,
        jwksUrl: body.jwksUrl,
        backendId: body.backendId || app.config.backendId,
        oemOrgId: org.id
      }
    });
    reply.send(root);
  });
}
