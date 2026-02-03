import { FastifyInstance } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import { DecodeTokenRequestSchema, DecodeTokenResponseSchema } from "@ua/common";
import { getPrisma } from "../lib/prisma";
import { requireApiSecret } from "../lib/apiSecretAuth";
import { errorResponse } from "../lib/errors";
import { verifyApiSecret } from "../services/apiSecrets";
import jwt from "jsonwebtoken";
import { verifyIntegrityToken } from "../lib/crypto";
import { validateTokenClaims } from "../services/tokenValidation";

export default async function appRoutes(app: FastifyInstance) {
  app.post(
    "/decodeToken",
    {
      schema: {
        body: zodToJsonSchema(DecodeTokenRequestSchema),
        response: {
          200: zodToJsonSchema(DecodeTokenResponseSchema)
        }
      }
    },
    async (request, reply) => {
      const rawSecret = requireApiSecret(request, "x-ua-api-secret");
      const appRecord = await verifyApiSecret(rawSecret);
      if (!appRecord) {
        reply.code(401).send(errorResponse("UNAUTHORIZED", "Invalid API secret"));
        return;
      }

      const body = DecodeTokenRequestSchema.parse(request.body);
      if (body.projectId !== appRecord.projectId) {
        reply.code(403).send(errorResponse("PROJECT_MISMATCH", "projectId mismatch"));
        return;
      }
      const prisma = getPrisma();
      const registered = await prisma.app.findUnique({ where: { projectId: body.projectId } });
      if (!registered) {
        reply.code(404).send(errorResponse("APP_NOT_FOUND", "App not registered"));
        return;
      }

      let decoded;
      try {
        decoded = await decodeTokenWithFederation(app, body.token);
      } catch (error) {
        reply.code(400).send(errorResponse("INVALID_TOKEN", "Token verification failed"));
        return;
      }
      const requestHash = validateTokenClaims(
        decoded.payload,
        body.projectId,
        body.expectedRequestHash
      );

      const tokenApp = decoded.payload.app as {
        packageName?: string;
        signerDigests?: string[];
      };
      if (tokenApp?.packageName && tokenApp.packageName !== appRecord.projectId) {
        reply.code(400).send(errorResponse("PROJECT_MISMATCH", "Token package mismatch"));
        return;
      }
      const signerDigests = (tokenApp?.signerDigests || []).map((digest) => digest.toLowerCase());
      if (!signerDigests.includes(registered.signerDigestSha256.toLowerCase())) {
        reply.code(400).send(errorResponse("SIGNER_MISMATCH", "Token signer mismatch"));
        return;
      }

      reply.send({
        verdict: decoded.payload.verdict,
        requestHash,
        claims: {
          iss: decoded.payload.iss,
          projectId: decoded.payload.projectId,
          requestHash,
          app: decoded.payload.app,
          deviceIntegrity: decoded.payload.deviceIntegrity
        }
      });
    }
  );
}

async function decodeTokenWithFederation(app: FastifyInstance, token: string) {
  const unverified = jwt.decode(token) as jwt.JwtPayload | null;
  const iss = unverified?.iss as string | undefined;
  if (!iss || iss === app.config.backendId) {
    const signingKey = app.config.signingKey;
    if (!signingKey) {
      throw new Error("Local signing key not configured");
    }
    return await verifyIntegrityToken(token, [
      {
        kid: signingKey.kid,
        alg: signingKey.alg,
        publicKey: signingKey.publicKey
      }
    ]);
  }

  const prisma = getPrisma();
  const backend = await prisma.federationBackend.findFirst({
    where: { backendId: iss, status: "active" }
  });
  if (!backend) {
    throw new Error("Unknown federation backend");
  }
  const publicKeys = backend.publicKeys as Array<{ kid: string; alg: string; publicKey: string }>;
  return await verifyIntegrityToken(token, publicKeys);
}
