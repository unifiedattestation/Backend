import { FastifyInstance } from "fastify";
import { getPrisma } from "../lib/prisma";
import { requireUser } from "../lib/auth";
import { errorResponse } from "../lib/errors";

async function fetchBackendInfo(url: string) {
  const res = await fetch(`${url.replace(/\/$/, "")}/api/v1/info`);
  if (!res.ok) {
    throw new Error("Failed to fetch backend info");
  }
  return res.json();
}

export default async function federationRoutes(app: FastifyInstance) {
  app.get("/backends", async () => {
    const prisma = getPrisma();
    return prisma.federationBackend.findMany({ orderBy: { createdAt: "desc" } });
  });

  app.post("/backends", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const body = request.body as {
      url?: string;
      name?: string;
      backendId?: string;
      publicKeys?: Array<{ kid: string; alg: string; publicKey: string }>;
    };
    if (!body.url && (!body.backendId || !body.publicKeys)) {
      reply
        .code(400)
        .send(errorResponse("INVALID_REQUEST", "Provide url or backendId+publicKeys"));
      return;
    }
    const prisma = getPrisma();
    let backendId = body.backendId;
    let publicKeys = body.publicKeys || [];
    if (body.url) {
      try {
        const info = await fetchBackendInfo(body.url);
        backendId = info.backendId;
        publicKeys = info.publicKeys || [];
      } catch (err: any) {
        reply.code(502).send(errorResponse("UNREACHABLE", err.message || "Could not reach backend URL"));
        return;
      }
    }
    if (!backendId) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing backendId"));
      return;
    }
    const created = await prisma.federationBackend.create({
      data: {
        backendId,
        name: body.name || body.url || backendId,
        url: body.url,
        publicKeys,
        status: "active"
      }
    });
    reply.send(created);
  });

  app.patch("/backends/:id", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const prisma = getPrisma();
    const { id } = request.params as { id: string };
    const body = request.body as { status?: "active" | "disabled"; name?: string };
    const updated = await prisma.federationBackend.update({
      where: { id },
      data: {
        status: body.status,
        name: body.name
      }
    });
    reply.send(updated);
  });

  app.post("/backends/:id/refresh", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const prisma = getPrisma();
    const { id } = request.params as { id: string };
    const backend = await prisma.federationBackend.findUnique({ where: { id } });
    if (!backend) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Backend not found"));
      return;
    }
    if (!backend.url) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "No URL stored for this backend — cannot refresh"));
      return;
    }
    let info: any;
    try {
      info = await fetchBackendInfo(backend.url);
    } catch (err: any) {
      reply.code(502).send(errorResponse("UNREACHABLE", err.message || "Could not reach backend URL"));
      return;
    }
    const updated = await prisma.federationBackend.update({
      where: { id },
      data: { publicKeys: info.publicKeys || [] }
    });
    reply.send(updated);
  });

  app.delete("/backends/:id", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const prisma = getPrisma();
    const { id } = request.params as { id: string };
    await prisma.federationBackend.delete({ where: { id } });
    reply.send({ ok: true });
  });
}
