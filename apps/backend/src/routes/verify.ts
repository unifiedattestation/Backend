import { FastifyInstance } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import { VerifyRequestSchema, VerifyResponseSchema } from "@ua/common";
import { errorResponse } from "../lib/errors";
import { requireApiKey } from "../lib/apiKeyAuth";
import { verifyApiKey } from "../services/apiKeys";

export default async function verifyRoutes(app: FastifyInstance) {
  app.post(
    "/",
    {
      schema: {
        body: zodToJsonSchema(VerifyRequestSchema),
        response: {
          200: {
            ...zodToJsonSchema(VerifyResponseSchema),
            examples: [
              {
                outcome: true,
                verdict: {
                  checkedAt: "2024-01-01T00:00:00.000Z",
                  issuerBackendId: "eu.unifiedattest.backend",
                  projectId: "proj_123",
                  developerClientId: "dev_123",
                  verifiedChallenge: true,
                  replayDetected: false,
                  signals: { deviceIntegrity: "basic" }
                }
              }
            ]
          }
        }
      }
    },
    async (request, reply) => {
      const allowed = app.verifyRateLimiter.take(`verify:${request.ip}`);
      if (!allowed) {
        reply.code(429).send(errorResponse("FORBIDDEN", "Rate limit exceeded"));
        return;
      }
      const apiKeyHeader = app.config.security.apiKeyHeader;
      const rawKey = requireApiKey(request, apiKeyHeader);
      const key = await verifyApiKey(rawKey);
      if (!key) {
        reply.code(401).send(errorResponse("UNAUTHORIZED", "Invalid API key"));
        return;
      }

      const body = VerifyRequestSchema.parse(request.body);
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

      let claims;
      try {
        claims = app.challengeService.verifyChallengeToken(body.challengeToken);
      } catch (err) {
        reply.code(400).send(errorResponse("INVALID_CHALLENGE", "Invalid challenge token"));
        return;
      }

      if (claims.iss !== app.config.backendId) {
        reply.code(400).send(errorResponse("INVALID_CHALLENGE", "Issuer mismatch"));
        return;
      }
      if (claims.pid !== body.projectId || claims.did !== body.developerClientId) {
        reply.code(400).send(errorResponse("INVALID_CHALLENGE", "Challenge claims mismatch"));
        return;
      }
      const expectedAud = `${body.developerClientId}:${body.projectId}`;
      if (claims.aud !== expectedAud) {
        reply.code(400).send(errorResponse("INVALID_CHALLENGE", "Audience mismatch"));
        return;
      }
      const now = Math.floor(Date.now() / 1000);
      if (claims.exp && claims.exp < now) {
        reply.code(400).send(errorResponse("CHALLENGE_EXPIRED", "Challenge expired"));
        return;
      }

      const consumed = app.replayCache.consume(body.developerClientId, body.projectId, claims.jti);
      if (!consumed) {
        reply.code(409).send(errorResponse("REPLAY_DETECTED", "Challenge replay detected"));
        return;
      }

      let signals: Record<string, unknown> = {};
      if (body.artifact.type === "mock") {
        try {
          signals = JSON.parse(body.artifact.payload);
        } catch {
          reply.code(400).send(errorResponse("INVALID_ARTIFACT", "Invalid mock artifact"));
          return;
        }
      } else {
        reply.code(400).send(errorResponse("INVALID_ARTIFACT", "Unsupported artifact type"));
        return;
      }

      reply.send({
        outcome: true,
        verdict: {
          checkedAt: new Date().toISOString(),
          issuerBackendId: app.config.backendId,
          projectId: body.projectId,
          developerClientId: body.developerClientId,
          verifiedChallenge: true,
          replayDetected: false,
          signals
        }
      });
    }
  );
}
