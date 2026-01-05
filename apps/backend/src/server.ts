import Fastify from "fastify";
import crypto from "crypto";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import { loadConfig } from "./lib/config";
import { HttpError } from "./lib/errors";
import { ReplayCache } from "./services/replayCache";
import { ChallengeService } from "./services/challenge";
import { RateLimiter } from "./services/rateLimiter";
import authRoutes from "./routes/auth";
import projectRoutes from "./routes/projects";
import challengeRoutes from "./routes/challenge";
import verifyRoutes from "./routes/verify";
import federationRoutes from "./routes/federation";
import oemRoutes from "./routes/oem";

export function buildServer() {
  const config = loadConfig();
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
  app.decorate("challengeService", new ChallengeService(config));
  app.decorate("replayCache", new ReplayCache(config.challenge.ttlSeconds));
  app.decorate("authRateLimiter", new RateLimiter(20, 60));
  app.decorate("verifyRateLimiter", new RateLimiter(60, 60));

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

  app.register(authRoutes, { prefix: "/v1/auth" });
  app.register(projectRoutes, { prefix: "/v1/projects" });
  app.register(challengeRoutes, { prefix: "/v1/challenge" });
  app.register(verifyRoutes, { prefix: "/v1/verify" });
  app.register(federationRoutes, { prefix: "/v1/federation" });
  app.register(oemRoutes, { prefix: "/v1/oem" });

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
    challengeService: ChallengeService;
    replayCache: ReplayCache;
    authRateLimiter: RateLimiter;
    verifyRateLimiter: RateLimiter;
  }
}
