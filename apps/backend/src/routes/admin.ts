import crypto from "crypto";
import argon2 from "argon2";
import { FastifyInstance } from "fastify";
import { getPrisma } from "../lib/prisma";
import { requireUser } from "../lib/auth";
import { errorResponse } from "../lib/errors";
import { saveConfig } from "../lib/config";
import { registerUser } from "../services/auth";
import { refreshAuthorityBundle } from "../services/attestationAuthorities";

export default async function adminRoutes(app: FastifyInstance) {
  app.get("/settings", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    reply.send({
      backendId: app.config.backendId,
      externalUrl: app.config.externalUrl,
      activeKid: app.config.signingKeys.activeKid
    });
  });

  app.post("/settings/external-url", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const body = request.body as { externalUrl: string };
    app.config.externalUrl = body.externalUrl;
    saveConfig(app.config);
    reply.send({ ok: true });
  });

  app.post("/settings/rotate-key", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const keyPair = crypto.generateKeyPairSync("ed25519");
    const publicKey = keyPair.publicKey.export({ type: "spki", format: "der" }) as Buffer;
    const privateKey = keyPair.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
    const kid = `k${Date.now()}`;
    app.config.signingKeys.keys.push({
      kid,
      alg: "EdDSA",
      publicKey: publicKey.toString("base64"),
      privateKey: privateKey.toString("base64")
    });
    app.config.signingKeys.activeKid = kid;
    saveConfig(app.config);
    reply.send({ kid });
  });

  app.get("/users", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const prisma = getPrisma();
    const users = await prisma.user.findMany({
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        email: true,
        role: true,
        disabledAt: true,
        displayName: true,
        createdAt: true
      }
    });
    reply.send(users);
  });

  app.post("/users", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const body = request.body as { email: string; password: string; role: "app_dev" | "oem" };
    if (!body.email || !body.password || !body.role) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing user fields"));
      return;
    }
    const created = await registerUser(body.email, body.password, body.role);
    reply.send({
      id: created.id,
      email: created.email,
      role: created.role,
      displayName: created.displayName,
      createdAt: created.createdAt
    });
  });

  app.post("/users/:id/disable", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const prisma = getPrisma();
    const { id } = request.params as { id: string };
    const updated = await prisma.user.update({
      where: { id },
      data: { disabledAt: new Date() }
    });
    reply.send({
      id: updated.id,
      email: updated.email,
      role: updated.role,
      disabledAt: updated.disabledAt
    });
  });

  app.post("/users/:id/password", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const { id } = request.params as { id: string };
    const body = request.body as { password?: string };
    if (!body.password || body.password.length < 5) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Password must be at least 5 characters"));
      return;
    }
    const prisma = getPrisma();
    const passwordHash = await argon2.hash(body.password);
    await prisma.user.update({
      where: { id },
      data: { passwordHash }
    });
    reply.send({ ok: true });
  });

  app.delete("/users/:id", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const prisma = getPrisma();
    const { id } = request.params as { id: string };
    await prisma.user.delete({ where: { id } });
    reply.send({ ok: true });
  });

  app.get("/attestation-authorities", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const prisma = getPrisma();
    const authorities = await prisma.attestationAuthority.findMany({
      orderBy: { createdAt: "desc" },
      include: { roots: true, status: true }
    });
    const response = authorities.map((authority) => {
      const keyTypes = authority.roots.map((root) => {
        try {
          const cert = new crypto.X509Certificate(root.pem);
          return cert.publicKey.asymmetricKeyType || "unknown";
        } catch {
          return "unknown";
        }
      });
      const hasRsa = keyTypes.includes("rsa");
      const hasEcdsa = keyTypes.includes("ec");
      return {
        id: authority.id,
        name: authority.name,
        baseUrl: authority.baseUrl,
        enabled: authority.enabled,
        isLocal: authority.isLocal,
        roots: authority.roots,
        statusCachedAt: authority.status?.fetchedAt || null,
        keyAvailability: {
          rsa: hasRsa,
          ecdsa: hasEcdsa
        }
      };
    });
    reply.send(response);
  });

  app.post("/attestation-authorities", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const body = request.body as { name?: string; baseUrl?: string };
    if (!body.name || !body.baseUrl) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing name or baseUrl"));
      return;
    }
    const prisma = getPrisma();
    const created = await prisma.attestationAuthority.create({
      data: { name: body.name, baseUrl: body.baseUrl }
    });
    reply.send(created);
  });

  app.post("/attestation-authorities/:id/refresh", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "Admin role required"));
      return;
    }
    const prisma = getPrisma();
    const { id } = request.params as { id: string };
    const authority = await prisma.attestationAuthority.findUnique({ where: { id } });
    if (!authority) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Authority not found"));
      return;
    }
    await refreshAuthorityBundle(authority.id, authority.baseUrl);
    reply.send({ ok: true });
  });

}
