import Fastify from "fastify";
import forge from "node-forge";
import { afterEach, describe, expect, it, vi } from "vitest";
import deviceRoutes from "../src/routes/device";

// device.ts's own root-selection code (routes/device.ts) constructs real
// `crypto.X509Certificate` instances directly from the parsed chain and from
// each stored authority root PEM to compare SPKIs -- that part isn't mocked
// away by mocking "ua-attestation-verifier", so the mocked chain/root need to
// be real, parseable X.509 DER/PEM. Using the same self-signed cert for both
// the mocked chain's "root" position and the authority's stored root
// guarantees their SPKIs match trivially.
const rootKeys = forge.pki.rsa.generateKeyPair(1024);
const rootCert = forge.pki.createCertificate();
rootCert.publicKey = rootKeys.publicKey;
rootCert.serialNumber = "01";
rootCert.validity.notBefore = new Date(Date.now() - 60 * 60 * 1000);
rootCert.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
const rootAttrs = [{ name: "commonName", value: "UA Test Root" }];
rootCert.setSubject(rootAttrs);
rootCert.setIssuer(rootAttrs);
rootCert.sign(rootKeys.privateKey, forge.md.sha256.create());
const rootDer = Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(rootCert)).getBytes(), "binary");
const rootPem = forge.pki.certificateToPem(rootCert);

const mockPrisma = {
  deviceFamily: {
    findMany: vi.fn(() =>
      Promise.resolve([
        {
          id: "family1",
          codename: null,
          model: null,
          enabled: true,
          oemOrg: { manufacturer: null, brand: null }
        }
      ])
    )
  },
  deviceEntry: {
    findFirst: vi.fn(() =>
      Promise.resolve({
        id: "entry1",
        authorityId: "auth1",
        deviceFamilyId: "family1",
        revokedAt: null,
        rsaSerialHex: null,
        ecdsaSerialHex: null,
        rsaIntermediateSerialHex: null,
        ecdsaIntermediateSerialHex: null,
        authority: { id: "auth1", enabled: true, isLocal: true, roots: [{ pem: rootPem }] },
        deviceFamily: { enabled: true }
      })
    )
  },
  buildPolicy: { findMany: vi.fn(() => Promise.resolve([])), count: vi.fn(() => Promise.resolve(0)) },
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
  deviceIntegrity: {
    verifiedBootKey: "aa11",
    verifiedBootState: "VERIFIED",
    osPatchLevel: 202410
  },
  publicKeySpkiDer: Buffer.from("01", "hex")
};

vi.mock("ua-attestation-verifier", async () => {
  const actual = await vi.importActual<typeof import("ua-attestation-verifier")>("ua-attestation-verifier");
  return {
    ...actual,
    parseCertificateChain: vi.fn(() => [Buffer.from("01", "hex"), rootDer]),
    verifyCertificateChainStrict: vi.fn(),
    parseKeyAttestation: vi.fn(() => mockAttestation),
    getCertificateSerial: vi.fn(() => "ABC"),
    hasAttestationExtension: vi.fn(() => true)
  };
});

vi.mock("../src/services/attestationAuthorities", () => ({
  getAuthorityStatus: vi.fn(() => Promise.resolve({ revokedSerials: [], suspendedSerials: [] }))
}));

function buildApp(options: { allowMissingRootOfTrust?: boolean } = {}) {
  const app = Fastify();
  app.decorate("config", {
    backendId: "backend",
    configPath: "config.yaml",
    signingKey: {
      kid: "k1",
      alg: "EdDSA",
      privateKey: "MC4CAQAwBQYDK2VwBCIEIHZpmqe4EtA0jQE3mUYxPRRJRGgBTQhji+GkGU/Mymob",
      publicKey: "MCowBQYDK2VwAyEAwDqa+NOeBFlf79vbtbzh7N+58zMqC/4/TZKtNKZ9y3o="
    },
    security: {
      apiSecretHeader: "x-ua-api-secret",
      jwt: { accessTtlMinutes: 15, refreshTtlDays: 30 }
    },
    poc: { allowMissingRootOfTrust: options.allowMissingRootOfTrust ?? false }
  });
  app.register(deviceRoutes, { prefix: "/api/v1/device" });
  return app;
}

describe("/api/v1/device/process", () => {
  it("accepts unknown projectId if it matches attestation packageName", async () => {
    mockPrisma.app.findUnique.mockResolvedValue(null);
    mockPrisma.deviceReport.upsert.mockResolvedValue({});

    const app = buildApp();
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/device/process",
      payload: {
        projectId: "com.example.app",
        requestHash: "abc",
        attestationChain: ["dummy"],
        deviceMeta: {}
      }
    });

    expect(response.statusCode).toBe(200);
  });

  it("rejects when projectId does not match attestation packageName", async () => {
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
        attestationChain: ["dummy"],
        deviceMeta: {}
      }
    });

    expect(response.statusCode).toBe(400);
    const body = response.json();
    expect(body.code).toBe("APP_ID_MISMATCH");

    mockAttestation.app.packageName = "com.example.app";
  });
});

// Huawei EMUI-style attestation: TEE-backed key and app identity, but the
// KeyMint record carries no RootOfTrust (no boot key, lock or boot state).
describe("/api/v1/device/process without RootOfTrust", () => {
  const withRootOfTrust = mockAttestation.deviceIntegrity;

  function processWithoutRootOfTrust(options: { allowMissingRootOfTrust?: boolean }) {
    mockPrisma.app.findUnique.mockResolvedValue(null);
    mockPrisma.deviceReport.upsert.mockResolvedValue({});
    mockAttestation.deviceIntegrity = { osPatchLevel: 202506 } as typeof withRootOfTrust;
    return buildApp(options).inject({
      method: "POST",
      url: "/api/v1/device/process",
      payload: {
        projectId: "com.example.app",
        requestHash: "abc",
        attestationChain: ["dummy"],
        deviceMeta: {}
      }
    });
  }

  afterEach(() => {
    mockAttestation.deviceIntegrity = withRootOfTrust;
  });

  it("rejects by default", async () => {
    const response = await processWithoutRootOfTrust({});

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      code: "INVALID_ATTESTATION",
      message: "Missing root of trust"
    });
  });

  it("issues an untrusted ROOT_OF_TRUST_MISSING verdict in PoC mode", async () => {
    const response = await processWithoutRootOfTrust({ allowMissingRootOfTrust: true });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(typeof body.token).toBe("string");
    expect(body.verdict).toEqual({
      isTrusted: false,
      reasonCodes: ["ROOT_OF_TRUST_MISSING", "BUILD_POLICY_UNVERIFIED"]
    });
  });

  it("leaves attestations that do have a RootOfTrust unchanged in PoC mode", async () => {
    mockPrisma.app.findUnique.mockResolvedValue(null);
    mockPrisma.deviceReport.upsert.mockResolvedValue({});
    const response = await buildApp({ allowMissingRootOfTrust: true }).inject({
      method: "POST",
      url: "/api/v1/device/process",
      payload: {
        projectId: "com.example.app",
        requestHash: "abc",
        attestationChain: ["dummy"],
        deviceMeta: {}
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().verdict.reasonCodes).not.toContain("ROOT_OF_TRUST_MISSING");
  });
});
