import { describe, it, expect } from "vitest";
import request from "supertest";
import { buildServer } from "../src/server";
import { getPrisma } from "../src/lib/prisma";
import { generateApiKey } from "../src/services/apiKeys";

const prisma = getPrisma();

describe("POST /v1/challenge", () => {
  it.skipIf(!process.env.DATABASE_URL)("issues challenge token", async () => {
    const server = buildServer();
    const user = await prisma.user.create({
      data: {
        email: `test-${Date.now()}@ua.local`,
        passwordHash: "hash",
        role: "developer"
      }
    });
    const org = await prisma.developerOrg.create({
      data: {
        name: "Test Org",
        ownerUserId: user.id
      }
    });
    const project = await prisma.project.create({
      data: {
        name: "Test Project",
        packageName: "com.example.ua",
        orgId: org.id
      }
    });
    const apiKey = generateApiKey();
    await prisma.projectApiKey.create({
      data: {
        projectId: project.id,
        keyPrefix: apiKey.prefix,
        keyHash: apiKey.hash
      }
    });

    const response = await request(server.server)
      .post("/v1/challenge")
      .set("x-ua-api-key", apiKey.raw)
      .send({ projectId: project.id, developerClientId: org.id });

    expect(response.status).toBe(200);
    expect(response.body.challengeToken).toBeTypeOf("string");
  });
});
