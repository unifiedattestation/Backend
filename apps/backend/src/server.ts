import Fastify from "fastify";
import crypto from "crypto";
import cors from "@fastify/cors";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import { loadConfig } from "./lib/config";
import { HttpError } from "./lib/errors";
import { RateLimiter } from "./services/rateLimiter";
import { ensureDefaultAdmin } from "./services/auth";
import { ensureLocalAuthority } from "./services/localAuthority";
import authRoutes from "./routes/auth";
import infoRoutes from "./routes/info";
import deviceRoutes from "./routes/device";
import appRoutes from "./routes/app";
import federationRoutes from "./routes/federation";
import oemRoutes from "./routes/oem";
import appManagementRoutes from "./routes/apps";
import adminRoutes from "./routes/admin";
import profileRoutes from "./routes/profile";

export function buildServer() {
  const config = loadConfig();
  let localAuthorityBaseUrl: string | null = null;
  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL || "info"
    }
  });

  app.addHook("onRequest", async (request, reply) => {
    const incoming = request.headers["x-request-id"];
    const requestId = (Array.isArray(incoming) ? incoming[0] : incoming) || crypto.randomUUID();
    reply.header("x-request-id", requestId);
    (request as any).log = request.log.child({ requestId });

    const forwardedHost = request.headers["x-forwarded-host"];
    const host = Array.isArray(forwardedHost)
      ? forwardedHost[0]
      : forwardedHost || request.headers.host;
    if (host) {
      const forwardedProto = request.headers["x-forwarded-proto"];
      const proto = Array.isArray(forwardedProto)
        ? forwardedProto[0]
        : forwardedProto?.split(",")[0]?.trim();
      const scheme = proto || request.protocol || "http";
      const baseUrl = `${scheme}://${host}`;
      if (baseUrl !== localAuthorityBaseUrl) {
        localAuthorityBaseUrl = baseUrl;
        await ensureLocalAuthority(baseUrl);
      }
    }
  });

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof HttpError) {
      reply.code(error.status).send(error.payload);
      return;
    }
    app.log.error(error);
    reply.code(500).send({ code: "INTERNAL_ERROR", message: "Unexpected error" });
  });

  app.decorate("config", config);
  app.decorate("authRateLimiter", new RateLimiter(20, 60));

  app.register(cors, {
    origin: true,
    credentials: true
  });

  app.register(swagger, {
    openapi: {
      info: {
        title: "Unified Attestation Backend",
        version: "0.1.0"
      }
    }
  });

  app.register(swaggerUi, {
    routePrefix: "/docs"
  });

  app.get("/openapi.json", async () => app.swagger());

  app.get("/health", async () => ({ status: "ok" }));

  app.register(authRoutes, { prefix: "/api/v1/auth" });
  app.register(infoRoutes, { prefix: "/api/v1/info" });
  app.register(deviceRoutes, { prefix: "/api/v1/device" });
  app.register(appRoutes, { prefix: "/api/v1/app" });
  app.register(appManagementRoutes, { prefix: "/api/v1/apps" });
  app.register(federationRoutes, { prefix: "/api/v1/federation" });
  app.register(oemRoutes, { prefix: "/api/v1/oem" });
  app.register(adminRoutes, { prefix: "/api/v1/admin" });
  app.register(profileRoutes, { prefix: "/api/v1/profile" });

  app.addHook("onReady", async () => {
    await ensureDefaultAdmin();
  });

  return app;
}

if (require.main === module) {
  const app = buildServer();
  const port = Number(process.env.PORT || 3001);
  app.listen({ port, host: "0.0.0.0" }, (err, address) => {
    if (err) {
      app.log.error(err);
      process.exit(1);
    }
    app.log.info(`UA backend listening on ${address}`);
  });
}

declare module "fastify" {
  interface FastifyInstance {
    config: ReturnType<typeof loadConfig>;
    authRateLimiter: RateLimiter;
  }
}
