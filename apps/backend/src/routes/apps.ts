import { FastifyInstance } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  AppSchema,
  CreateAppRequestSchema,
  CreateAppSecretResponseSchema
} from "@ua/common";
import { getPrisma } from "../lib/prisma";
import { errorResponse } from "../lib/errors";
import { requireUser } from "../lib/auth";
import { generateApiSecret } from "../services/apiSecrets";

export default async function appManagementRoutes(app: FastifyInstance) {
  app.get(
    "/",
    {
      schema: {
        response: {
          200: { type: "array", items: zodToJsonSchema(AppSchema) }
        }
      }
    },
    async (request, reply) => {
      const user = requireUser(request);
      if (user.role !== "app_dev" && user.role !== "admin") {
        reply.code(403).send(errorResponse("FORBIDDEN", "App dev role required"));
        return;
      }
      const prisma = getPrisma();
      const apps = await prisma.app.findMany({
        where: user.role === "admin" ? undefined : { ownerUserId: user.sub as string },
        select: {
          id: true,
          projectId: true,
          name: true,
          signerDigestSha256: true,
          createdAt: true
        }
      });
      reply.send(apps);
    }
  );

  app.post(
    "/",
    {
      schema: {
        body: zodToJsonSchema(CreateAppRequestSchema),
        response: {
          200: zodToJsonSchema(CreateAppSecretResponseSchema)
        }
      }
    },
    async (request, reply) => {
      const user = requireUser(request);
      if (user.role !== "app_dev" && user.role !== "admin") {
        reply.code(403).send(errorResponse("FORBIDDEN", "App dev role required"));
        return;
      }
      const prisma = getPrisma();
      const body = CreateAppRequestSchema.parse(request.body);
      const projectId = body.projectId ?? body.packageName;
      if (!projectId) {
        reply.code(400).send(errorResponse("INVALID_REQUEST", "projectId required"));
        return;
      }
      const secret = generateApiSecret();
      const created = await prisma.app.create({
        data: {
          name: body.name,
          projectId,
          signerDigestSha256: body.signerDigestSha256.toLowerCase(),
          apiSecretHash: secret.hash,
          apiSecretPrefix: secret.prefix,
          ownerUserId: user.sub as string
        }
      });
      reply.send({ apiSecret: secret.raw, prefix: created.apiSecretPrefix, id: created.id });
    }
  );

  app.post(
    "/:appId/rotate-secret",
    {
      schema: {
        response: {
          200: zodToJsonSchema(CreateAppSecretResponseSchema)
        }
      }
    },
    async (request, reply) => {
      const user = requireUser(request);
      if (user.role !== "app_dev" && user.role !== "admin") {
        reply.code(403).send(errorResponse("FORBIDDEN", "App dev role required"));
        return;
      }
      const prisma = getPrisma();
      const { appId } = request.params as { appId: string };
      const appRecord = await prisma.app.findFirst({
        where: user.role === "admin" ? { id: appId } : { id: appId, ownerUserId: user.sub as string }
      });
      if (!appRecord) {
        reply.code(404).send(errorResponse("APP_NOT_FOUND", "App not found"));
        return;
      }
      const secret = generateApiSecret();
      await prisma.app.update({
        where: { id: appRecord.id },
        data: {
          apiSecretHash: secret.hash,
          apiSecretPrefix: secret.prefix
        }
      });
      reply.send({ apiSecret: secret.raw, prefix: secret.prefix, id: appRecord.id });
    }
  );

  app.patch("/:appId", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "app_dev" && user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "App dev role required"));
      return;
    }
    const prisma = getPrisma();
    const { appId } = request.params as { appId: string };
    const body = request.body as {
      name?: string;
      projectId?: string;
      signerDigestSha256?: string;
    };
    const appRecord = await prisma.app.findFirst({
      where: user.role === "admin" ? { id: appId } : { id: appId, ownerUserId: user.sub as string }
    });
    if (!appRecord) {
      reply.code(404).send(errorResponse("APP_NOT_FOUND", "App not found"));
      return;
    }
    const nextName = body.name?.trim();
    const nextProjectId = body.projectId?.trim();
    const nextSigner = body.signerDigestSha256?.trim();
    if (!nextName && !nextProjectId && !nextSigner) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "No updates provided"));
      return;
    }
    if (nextProjectId && nextProjectId !== appRecord.projectId) {
      const existing = await prisma.app.findUnique({ where: { projectId: nextProjectId } });
      if (existing) {
        reply.code(409).send(errorResponse("PROJECT_EXISTS", "projectId already registered"));
        return;
      }
    }
    await prisma.$transaction(async (tx) => {
      await tx.app.update({
        where: { id: appRecord.id },
        data: {
          name: nextName || appRecord.name,
          projectId: nextProjectId || appRecord.projectId,
          signerDigestSha256: nextSigner
            ? nextSigner.toLowerCase()
            : appRecord.signerDigestSha256
        }
      });
      if (nextProjectId && nextProjectId !== appRecord.projectId) {
        await tx.deviceReport.updateMany({
          where: { projectId: appRecord.projectId },
          data: { projectId: nextProjectId }
        });
      }
    });
    reply.send({ ok: true });
  });

  app.delete("/:appId", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "app_dev" && user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "App dev role required"));
      return;
    }
    const prisma = getPrisma();
    const { appId } = request.params as { appId: string };
    const appRecord = await prisma.app.findFirst({
      where: user.role === "admin" ? { id: appId } : { id: appId, ownerUserId: user.sub as string }
    });
    if (!appRecord) {
      reply.code(404).send(errorResponse("APP_NOT_FOUND", "App not found"));
      return;
    }
    await prisma.$transaction([
      prisma.deviceReport.deleteMany({ where: { projectId: appRecord.projectId } }),
      prisma.app.delete({ where: { id: appRecord.id } })
    ]);
    reply.send({ ok: true });
  });

  app.get("/:appId/reports", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "app_dev" && user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "App dev role required"));
      return;
    }
    const prisma = getPrisma();
    const { appId } = request.params as { appId: string };
    const appRecord = await prisma.app.findFirst({
      where: user.role === "admin" ? { id: appId } : { id: appId, ownerUserId: user.sub as string }
    });
    if (!appRecord) {
      reply.code(404).send(errorResponse("APP_NOT_FOUND", "App not found"));
      return;
    }
    const reports = await prisma.deviceReport.findMany({
      where: { projectId: appRecord.projectId },
      orderBy: { lastSeen: "desc" }
    });
    reply.send(reports);
  });
}
