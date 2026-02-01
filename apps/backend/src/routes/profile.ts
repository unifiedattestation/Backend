import { FastifyInstance } from "fastify";
import { getPrisma } from "../lib/prisma";
import { requireUser } from "../lib/auth";
import { errorResponse } from "../lib/errors";
import crypto from "crypto";
import argon2 from "argon2";

export default async function profileRoutes(app: FastifyInstance) {
  app.get("/", async (request, reply) => {
    const user = requireUser(request);
    const prisma = getPrisma();
    const record = await prisma.user.findUnique({ where: { id: user.sub as string } });
    if (!record) {
      reply.code(404).send(errorResponse("NOT_FOUND", "User not found"));
      return;
    }
    if (record.role === "oem") {
      const org = await prisma.oemOrg.findFirst({ where: { ownerUserId: record.id } });
      const activeDeviceAnchors = org
        ? await prisma.deviceEntry.count({ where: { oemOrgId: org.id, revokedAt: null } })
        : 0;
      let linkedActiveAnchors = 0;
      let trustAnchorHistory: Array<{
        id: string;
        rsaSerialHex: string;
        ecdsaSerialHex: string;
        rsaSubject: string;
        ecdsaSubject: string;
        createdAt: string;
        revokedAt?: string | null;
      }> = [];
      if (org?.rsaRootCertPem && org?.ecdsaRootCertPem) {
        try {
          const rsaCert = new crypto.X509Certificate(org.rsaRootCertPem);
          const ecdsaCert = new crypto.X509Certificate(org.ecdsaRootCertPem);
          linkedActiveAnchors = await prisma.deviceEntry.count({
            where: {
              oemOrgId: org.id,
              revokedAt: null,
              OR: [
                { rsaIntermediateSerialHex: rsaCert.serialNumber.toUpperCase() },
                { ecdsaIntermediateSerialHex: ecdsaCert.serialNumber.toUpperCase() }
              ]
            }
          });
        } catch {
          linkedActiveAnchors = 0;
        }
      }
      if (org) {
        const anchors = await prisma.oemTrustAnchor.findMany({
          where: { oemOrgId: org.id },
          orderBy: { createdAt: "desc" }
        });
        trustAnchorHistory = anchors.map((anchor) => {
          let rsaSubject = "unknown";
          let ecdsaSubject = "unknown";
          try {
            rsaSubject = new crypto.X509Certificate(anchor.rsaCertPem).subject;
          } catch {
            rsaSubject = "unknown";
          }
          try {
            ecdsaSubject = new crypto.X509Certificate(anchor.ecdsaCertPem).subject;
          } catch {
            ecdsaSubject = "unknown";
          }
          return {
            id: anchor.id,
            rsaSerialHex: anchor.rsaSerialHex,
            ecdsaSerialHex: anchor.ecdsaSerialHex,
            rsaSubject,
            ecdsaSubject,
            createdAt: anchor.createdAt.toISOString(),
            revokedAt: anchor.revokedAt ? anchor.revokedAt.toISOString() : null
          };
        });
      }
      let oemTrustAnchor: {
        rsa?: { subject: string; serialHex: string };
        ecdsa?: { subject: string; serialHex: string };
      } | null = null;
      if (org?.rsaRootCertPem && org?.ecdsaRootCertPem) {
        try {
          const rsaCert = new crypto.X509Certificate(org.rsaRootCertPem);
          const ecdsaCert = new crypto.X509Certificate(org.ecdsaRootCertPem);
          oemTrustAnchor = {
            rsa: { subject: rsaCert.subject, serialHex: rsaCert.serialNumber.toUpperCase() },
            ecdsa: { subject: ecdsaCert.subject, serialHex: ecdsaCert.serialNumber.toUpperCase() }
          };
        } catch {
          oemTrustAnchor = null;
        }
      }
      reply.send({
        id: record.id,
        email: record.email,
        role: record.role,
        displayName: record.displayName,
        manufacturer: org?.manufacturer || "",
        brand: org?.brand || "",
        oemTrustAnchorReady: Boolean(
          org?.rsaRootCertPem &&
            org?.rsaRootKeyPem &&
            org?.ecdsaRootCertPem &&
            org?.ecdsaRootKeyPem
        ),
        activeDeviceAnchors,
        linkedActiveAnchors,
        oemTrustAnchor,
        trustAnchorHistory
      });
      return;
    }
    reply.send({
      id: record.id,
      email: record.email,
      role: record.role,
      displayName: record.displayName
    });
  });

  app.patch("/", async (request, reply) => {
    const user = requireUser(request);
    const prisma = getPrisma();
    const body = request.body as { displayName?: string; manufacturer?: string; brand?: string };
    if (!body.displayName) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing displayName"));
      return;
    }
    const updated = await prisma.user.update({
      where: { id: user.sub as string },
      data: { displayName: body.displayName }
    });
    if (updated.role === "oem") {
      if (!body.manufacturer || !body.brand) {
        reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing manufacturer or brand"));
        return;
      }
      await prisma.oemOrg.update({
        where: { ownerUserId: updated.id },
        data: {
          manufacturer: body.manufacturer,
          brand: body.brand
        }
      });
    }
    reply.send({
      id: updated.id,
      email: updated.email,
      role: updated.role,
      displayName: updated.displayName,
      manufacturer: body.manufacturer,
      brand: body.brand
    });
  });

  app.post("/password", async (request, reply) => {
    const user = requireUser(request);
    const prisma = getPrisma();
    const body = request.body as { currentPassword?: string; newPassword?: string };
    if (!body.currentPassword || !body.newPassword) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing currentPassword or newPassword"));
      return;
    }
    if (body.newPassword.length < 5) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Password must be at least 5 characters"));
      return;
    }
    const record = await prisma.user.findUnique({ where: { id: user.sub as string } });
    if (!record) {
      reply.code(404).send(errorResponse("NOT_FOUND", "User not found"));
      return;
    }
    const ok = await argon2.verify(record.passwordHash, body.currentPassword);
    if (!ok) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Current password is incorrect"));
      return;
    }
    const passwordHash = await argon2.hash(body.newPassword);
    await prisma.user.update({
      where: { id: record.id },
      data: { passwordHash }
    });
    reply.send({ ok: true });
  });
}
