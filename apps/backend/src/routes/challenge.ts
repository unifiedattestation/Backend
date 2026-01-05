import { FastifyInstance } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import { ChallengeRequestSchema, ChallengeResponseSchema } from "@ua/common";
import { errorResponse } from "../lib/errors";
import { requireApiKey } from "../lib/apiKeyAuth";
import { verifyApiKey } from "../services/apiKeys";

export default async function challengeRoutes(app: FastifyInstance) {
  app.post(
    "/",
    {
      schema: {
        body: zodToJsonSchema(ChallengeRequestSchema),
        response: {
          200: {
            ...zodToJsonSchema(ChallengeResponseSchema),
            examples: [
              {
                challengeToken: "eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIn0...",
                expiresAt: "2024-01-01T00:00:00.000Z"
              }
            ]
          }
        }
      }
    },
    async (request, reply) => {
      const apiKeyHeader = app.config.security.apiKeyHeader;
      const rawKey = requireApiKey(request, apiKeyHeader);
      const key = await verifyApiKey(rawKey);
      if (!key) {
        reply.code(401).send(errorResponse("UNAUTHORIZED", "Invalid API key"));
        return;
      }

      const body = ChallengeRequestSchema.parse(request.body);
      if (key.projectId !== body.projectId) {
        reply.code(403).send(errorResponse("PROJECT_MISMATCH", "Project does not match API key"));
        return;
      }
      if (key.project.orgId !== body.developerClientId) {
        reply
          .code(403)
          .send(errorResponse("PROJECT_MISMATCH", "Developer does not match project"));
        return;
      }

      const issued = app.challengeService.issueChallenge(body.developerClientId, body.projectId);
      reply.send({
        challengeToken: issued.token,
        expiresAt: new Date(issued.exp * 1000).toISOString()
      });
    }
  );
}
