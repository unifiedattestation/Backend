import { FastifyInstance } from "fastify";

export default async function federationRoutes(app: FastifyInstance) {
  app.get("/backends", async () => {
    return app.config.federation.backends;
  });
}
