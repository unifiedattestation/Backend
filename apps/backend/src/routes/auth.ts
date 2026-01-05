import { FastifyInstance } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  AuthResponseSchema,
  LoginRequestSchema,
  RefreshRequestSchema,
  RegisterRequestSchema
} from "@ua/common";
import { errorResponse } from "../lib/errors";
import { issueTokens, registerUser, verifyRefreshToken, verifyUser } from "../services/auth";

export default async function authRoutes(app: FastifyInstance) {
  app.post(
    "/register",
    {
      schema: {
        body: zodToJsonSchema(RegisterRequestSchema),
        response: {
          200: zodToJsonSchema(AuthResponseSchema)
        }
      }
    },
    async (request, reply) => {
      const allowed = app.authRateLimiter.take(`register:${request.ip}`);
      if (!allowed) {
        reply.code(429).send(errorResponse("FORBIDDEN", "Rate limit exceeded"));
        return;
      }
      const body = RegisterRequestSchema.parse(request.body);
      const user = await registerUser(body.email, body.password, body.role);
      const tokens = issueTokens(
        user.id,
        user.role,
        app.config.security.jwt.accessTtlMinutes,
        app.config.security.jwt.refreshTtlDays
      );
      reply.send(tokens);
    }
  );

  app.post(
    "/login",
    {
      schema: {
        body: zodToJsonSchema(LoginRequestSchema),
        response: {
          200: zodToJsonSchema(AuthResponseSchema)
        }
      }
    },
    async (request, reply) => {
      const allowed = app.authRateLimiter.take(`login:${request.ip}`);
      if (!allowed) {
        reply.code(429).send(errorResponse("FORBIDDEN", "Rate limit exceeded"));
        return;
      }
      const body = LoginRequestSchema.parse(request.body);
      const user = await verifyUser(body.email, body.password);
      if (!user) {
        reply.code(401).send(errorResponse("UNAUTHORIZED", "Invalid credentials"));
        return;
      }
      const tokens = issueTokens(
        user.id,
        user.role,
        app.config.security.jwt.accessTtlMinutes,
        app.config.security.jwt.refreshTtlDays
      );
      reply.send(tokens);
    }
  );

  app.post(
    "/refresh",
    {
      schema: {
        body: zodToJsonSchema(RefreshRequestSchema),
        response: {
          200: zodToJsonSchema(AuthResponseSchema)
        }
      }
    },
    async (request, reply) => {
      try {
        const body = RefreshRequestSchema.parse(request.body);
        const payload = verifyRefreshToken(body.refreshToken);
        const tokens = issueTokens(
          payload.sub as string,
          payload.role as string,
          app.config.security.jwt.accessTtlMinutes,
          app.config.security.jwt.refreshTtlDays
        );
        reply.send(tokens);
      } catch {
        reply.code(401).send(errorResponse("UNAUTHORIZED", "Invalid refresh token"));
      }
    }
  );

  app.post("/logout", async (_request, reply) => {
    reply.send({ ok: true });
  });
}
