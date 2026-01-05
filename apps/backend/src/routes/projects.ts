import { FastifyInstance } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  ApiKeySchema,
  CreateApiKeyResponseSchema,
  CreateProjectRequestSchema,
  ProjectSchema
} from "@ua/common";
import { getPrisma } from "../lib/prisma";
import { errorResponse } from "../lib/errors";
import { requireUser } from "../lib/auth";
import { generateApiKey } from "../services/apiKeys";

export default async function projectRoutes(app: FastifyInstance) {
  app.get(
    "/",
    {
      schema: {
        response: {
          200: { type: "array", items: zodToJsonSchema(ProjectSchema) }
        }
      }
    },
    async (request, reply) => {
      const user = requireUser(request);
      const prisma = getPrisma();
      const org = await prisma.developerOrg.findFirst({ where: { ownerUserId: user.sub as string } });
      if (!org) {
        reply.code(403).send(errorResponse("FORBIDDEN", "Developer org not found"));
        return;
      }
      const projects = await prisma.project.findMany({ where: { orgId: org.id } });
      reply.send(projects);
    }
  );

  app.post(
    "/",
    {
      schema: {
        body: zodToJsonSchema(CreateProjectRequestSchema),
        response: {
          200: zodToJsonSchema(ProjectSchema)
        }
      }
    },
    async (request, reply) => {
      const user = requireUser(request);
      const prisma = getPrisma();
      const org = await prisma.developerOrg.findFirst({ where: { ownerUserId: user.sub as string } });
      if (!org) {
        reply.code(403).send(errorResponse("FORBIDDEN", "Developer org not found"));
        return;
      }
      const body = CreateProjectRequestSchema.parse(request.body);
      const project = await prisma.project.create({
        data: {
          orgId: org.id,
          name: body.name,
          packageName: body.packageName
        }
      });
      reply.send(project);
    }
  );

  app.post(
    "/:projectId/api-keys",
    {
      schema: {
        response: {
          200: zodToJsonSchema(CreateApiKeyResponseSchema)
        }
      }
    },
    async (request, reply) => {
      const user = requireUser(request);
      const prisma = getPrisma();
      const { projectId } = request.params as { projectId: string };
      const org = await prisma.developerOrg.findFirst({ where: { ownerUserId: user.sub as string } });
      if (!org) {
        reply.code(403).send(errorResponse("FORBIDDEN", "Developer org not found"));
        return;
      }
      const project = await prisma.project.findFirst({ where: { id: projectId, orgId: org.id } });
      if (!project) {
        reply.code(404).send(errorResponse("PROJECT_NOT_FOUND", "Project not found"));
        return;
      }
      const generated = generateApiKey();
      const created = await prisma.projectApiKey.create({
        data: {
          projectId: project.id,
          keyPrefix: generated.prefix,
          keyHash: generated.hash
        }
      });
      reply.send({ apiKey: generated.raw, keyPrefix: created.keyPrefix, id: created.id });
    }
  );

  app.get(
    "/:projectId/api-keys",
    {
      schema: {
        response: {
          200: { type: "array", items: zodToJsonSchema(ApiKeySchema) }
        }
      }
    },
    async (request, reply) => {
      const user = requireUser(request);
      const prisma = getPrisma();
      const { projectId } = request.params as { projectId: string };
      const org = await prisma.developerOrg.findFirst({ where: { ownerUserId: user.sub as string } });
      if (!org) {
        reply.code(403).send(errorResponse("FORBIDDEN", "Developer org not found"));
        return;
      }
      const project = await prisma.project.findFirst({ where: { id: projectId, orgId: org.id } });
      if (!project) {
        reply.code(404).send(errorResponse("PROJECT_NOT_FOUND", "Project not found"));
        return;
      }
      const keys = await prisma.projectApiKey.findMany({ where: { projectId } });
      reply.send(keys);
    }
  );

  app.delete("/:projectId/api-keys/:apiKeyId", async (request, reply) => {
    const user = requireUser(request);
    const prisma = getPrisma();
    const { projectId, apiKeyId } = request.params as { projectId: string; apiKeyId: string };
    const org = await prisma.developerOrg.findFirst({ where: { ownerUserId: user.sub as string } });
    if (!org) {
      reply.code(403).send(errorResponse("FORBIDDEN", "Developer org not found"));
      return;
    }
    const project = await prisma.project.findFirst({ where: { id: projectId, orgId: org.id } });
    if (!project) {
      reply.code(404).send(errorResponse("PROJECT_NOT_FOUND", "Project not found"));
      return;
    }
    await prisma.projectApiKey.update({
      where: { id: apiKeyId },
      data: { revokedAt: new Date() }
    });
    reply.send({ ok: true });
  });
}
