import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import deviceRoutes from "../src/routes/device";

const mockPrisma = {
  buildPolicy: { findMany: vi.fn() },
  app: { findUnique: vi.fn() },
  deviceReport: { upsert: vi.fn() }
};

vi.mock("../src/lib/prisma", () => ({
  getPrisma: () => mockPrisma
}));

const mockAttestation = {
  attestationChallengeHex: "abc",
  attestationSecurityLevel: "TEE",
  keymasterSecurityLevel: "TEE",
  app: { packageName: "com.example.app", signerDigests: ["aa"] },
  deviceIntegrity: {},
  publicKeySpkiDer: Buffer.from("01", "hex")
};

vi.mock("../src/lib/attestation", () => ({
  parseCertificateChain: vi.fn(() => [Buffer.from("01", "hex")]),
  verifyCertificateChain: vi.fn(),
  parseKeyAttestation: vi.fn(() => mockAttestation),
  getCertificateSerial: vi.fn(() => "ABC")
}));

vi.mock("../src/services/attestationAuthorities", () => ({
  getAuthorityForSerial: vi.fn(() => ({
    authorityId: "auth1",
    authorityRootId: "root1",
    authorityRoot: { id: "root1", pem: "pem" },
    rsaSerialHex: "ABC",
    ecdsaSerialHex: "DEF",
    revokedAt: null,
    deviceFamilyId: "family1",
    authority: { baseUrl: "http://example.com", enabled: true, isLocal: false }
  })),
  getAuthorityRoots: vi.fn(() => [{ id: "root1", pem: "pem" }]),
  getAuthorityStatus: vi.fn(() => ({ revokedSerials: [], suspendedSerials: [] }))
}));

function buildApp() {
  const app = Fastify();
  app.decorate("config", {
    backendId: "backend",
    configPath: "config.yaml",
    signingKeys: {
      activeKid: "k1",
      keys: [
        {
          kid: "k1",
          alg: "EdDSA",
          privateKey: "MC4CAQAwBQYDK2VwBCIEIHZpmqe4EtA0jQE3mUYxPRRJRGgBTQhji+GkGU/Mymob",
          publicKey: "MCowBQYDK2VwAyEAwDqa+NOeBFlf79vbtbzh7N+58zMqC/4/TZKtNKZ9y3o="
        }
      ]
    },
    security: {
      apiSecretHeader: "x-ua-api-secret",
      jwt: { accessTtlMinutes: 15, refreshTtlDays: 30 }
    }
  });
  app.register(deviceRoutes, { prefix: "/api/v1/device" });
  return app;
}

describe("/api/v1/device/process", () => {
  it("accepts unknown projectId if it matches attestation packageName", async () => {
    mockPrisma.buildPolicy.findMany.mockResolvedValue([]);
    mockPrisma.app.findUnique.mockResolvedValue(null);
    mockPrisma.deviceReport.upsert.mockResolvedValue({});

    const app = buildApp();
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/device/process",
      payload: {
        projectId: "com.example.app",
        requestHash: "abc",
        attestationChain: ["dummy"]
      }
    });

    expect(response.statusCode).toBe(200);
  });

  it("rejects when projectId does not match attestation packageName", async () => {
    mockPrisma.buildPolicy.findMany.mockResolvedValue([]);
    mockPrisma.app.findUnique.mockResolvedValue(null);
    mockPrisma.deviceReport.upsert.mockResolvedValue({});

    mockAttestation.app.packageName = "com.other.app";

    const app = buildApp();
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/device/process",
      payload: {
        projectId: "com.example.app",
        requestHash: "abc",
        attestationChain: ["dummy"]
      }
    });

    expect(response.statusCode).toBe(400);
    const body = response.json();
    expect(body.code).toBe("APP_ID_MISMATCH");

    mockAttestation.app.packageName = "com.example.app";
  });
});
