import { FastifyInstance } from "fastify";
import { getPrisma } from "../lib/prisma";
import { requireUser } from "../lib/auth";
import { errorResponse } from "../lib/errors";

export default async function profileRoutes(app: FastifyInstance) {
  app.get("/", async (request, reply) => {
    const user = requireUser(request);
    const prisma = getPrisma();
    const record = await prisma.user.findUnique({ where: { id: user.sub as string } });
    if (!record) {
      reply.code(404).send(errorResponse("NOT_FOUND", "User not found"));
      return;
    }
    if (record.role === "oem") {
      const org = await prisma.oemOrg.findFirst({ where: { ownerUserId: record.id } });
      reply.send({
        id: record.id,
        email: record.email,
        role: record.role,
        displayName: record.displayName,
        manufacturer: org?.manufacturer || "",
        brand: org?.brand || ""
      });
      return;
    }
    reply.send({
      id: record.id,
      email: record.email,
      role: record.role,
      displayName: record.displayName
    });
  });

  app.patch("/", async (request, reply) => {
    const user = requireUser(request);
    const prisma = getPrisma();
    const body = request.body as { displayName?: string; manufacturer?: string; brand?: string };
    if (!body.displayName) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing displayName"));
      return;
    }
    const updated = await prisma.user.update({
      where: { id: user.sub as string },
      data: { displayName: body.displayName }
    });
    if (updated.role === "oem") {
      if (!body.manufacturer || !body.brand) {
        reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing manufacturer or brand"));
        return;
      }
      await prisma.oemOrg.update({
        where: { ownerUserId: updated.id },
        data: {
          manufacturer: body.manufacturer,
          brand: body.brand
        }
      });
    }
    reply.send({
      id: updated.id,
      email: updated.email,
      role: updated.role,
      displayName: updated.displayName,
      manufacturer: body.manufacturer,
      brand: body.brand
    });
  });
}
