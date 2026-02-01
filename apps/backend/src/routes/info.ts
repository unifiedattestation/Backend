import fs from "fs";
import { FastifyInstance } from "fastify";
import { getPrisma } from "../lib/prisma";

export default async function infoRoutes(app: FastifyInstance) {
  app.get("/", async () => {
    const publicKeys = app.config.signingKeys.keys.map((key) => ({
      kid: key.kid,
      alg: key.alg,
      publicKey: key.publicKey
    }));
    return {
      backendId: app.config.backendId,
      publicKeys
    };
  });

  app.get("/root", async () => {
    const roots: string[] = [];
    const rsaPath = app.config.ua_root_rsa_cert_path;
    const ecdsaPath = app.config.ua_root_ecdsa_cert_path;
    if (rsaPath && fs.existsSync(rsaPath)) {
      roots.push(fs.readFileSync(rsaPath, "utf8").trim());
    }
    if (ecdsaPath && fs.existsSync(ecdsaPath)) {
      roots.push(fs.readFileSync(ecdsaPath, "utf8").trim());
    }
    return { roots };
  });

  app.get("/status", async () => {
    const prisma = getPrisma();
    const revoked = await prisma.deviceEntry.findMany({
      where: { revokedAt: { not: null }, authority: { isLocal: true } },
      select: {
        rsaSerialHex: true,
        ecdsaSerialHex: true,
        rsaIntermediateSerialHex: true,
        ecdsaIntermediateSerialHex: true
      }
    });
    const revokedAnchorSerials = revoked.flatMap((entry) => [
      entry.rsaSerialHex,
      entry.ecdsaSerialHex,
      entry.rsaIntermediateSerialHex,
      entry.ecdsaIntermediateSerialHex
    ]);
    const revokedOemAnchors = await prisma.oemTrustAnchor.findMany({
      where: { revokedAt: { not: null } },
      select: { rsaSerialHex: true, ecdsaSerialHex: true }
    });
    const revokedSerials = [
      ...revokedAnchorSerials.filter((serial): serial is string => Boolean(serial)),
      ...revokedOemAnchors.flatMap((entry) => [entry.rsaSerialHex, entry.ecdsaSerialHex])
    ];
    return {
      revokedSerials,
      suspendedSerials: []
    };
  });
}
