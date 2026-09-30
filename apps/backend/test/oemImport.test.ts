import Fastify from "fastify";
import forge from "node-forge";
import { beforeEach, describe, expect, it, vi } from "vitest";
import oemRoutes from "../src/routes/oem";
import { HttpError } from "../src/lib/errors";

// Root matching in processDeviceImport must compare public keys, not subject
// attributes: Google's roots carry a subject serialNumber=, Huawei's don't,
// and a matching name on a different key must never be trusted.
function makeCert(attrs: forge.pki.CertificateField[], issuer?: { cert: forge.pki.Certificate; key: forge.pki.rsa.PrivateKey }) {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  // Even-length hex with a leading 01 byte: always a positive DER INTEGER.
  cert.serialNumber = "01" + forge.util.bytesToHex(forge.random.getBytesSync(8));
  cert.validity.notBefore = new Date(Date.now() - 60 * 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
  cert.setSubject(attrs);
  cert.setIssuer(issuer ? issuer.cert.subject.attributes : attrs);
  cert.sign(issuer ? issuer.key : keys.privateKey, forge.md.sha256.create());
  return { cert, key: keys.privateKey, pem: forge.pki.certificateToPem(cert) };
}

const huaweiRoot = makeCert([
  { name: "countryName", value: "CN" },
  { name: "organizationName", value: "Huawei" },
  { shortName: "OU", value: "Huawei CBG" },
  { name: "commonName", value: "Huawei CBG Root CA" }
]);
const googleStyleRoot = makeCert([{ name: "serialNumber", value: "f92009e853b6b045" }]);
const impostorGoogleRoot = makeCert([{ name: "serialNumber", value: "f92009e853b6b045" }]);

function chainUnder(root: ReturnType<typeof makeCert>) {
  const ca = makeCert([{ name: "commonName", value: "Mobile Equipment CA" }], root);
  const device = makeCert([{ name: "commonName", value: "Device" }], ca);
  const leaf = makeCert([{ name: "commonName", value: "A Keymaster Key" }], device);
  return {
    leafCertificatePem: leaf.pem,
    intermediateCertificatesPem: [device.pem, ca.pem],
    rootCertificatePem: root.pem
  };
}

let registeredRoots: { pem: string; authority: { id: string; name: string; enabled: boolean } }[] = [];

const mockPrisma = {
  oemOrg: { findFirst: vi.fn(() => Promise.resolve({ id: "org1", name: "OEM", manufacturer: "huawei" })) },
  attestationRoot: { findMany: vi.fn(() => Promise.resolve(registeredRoots)) },
  deviceFamily: { findFirst: vi.fn(() => Promise.resolve({ id: "family1", codename: "test", model: null })) },
  buildPolicy: { findFirst: vi.fn(() => Promise.resolve({ id: "policy1", buildFingerprint: "fp" })) },
  deviceEntry: {
    count: vi.fn(() => Promise.resolve(0)),
    create: vi.fn(({ data }: any) => Promise.resolve({ id: "entry1", ...data }))
  }
};

vi.mock("../src/lib/prisma", () => ({ getPrisma: () => mockPrisma }));
vi.mock("../src/lib/auth", () => ({ requireUser: () => ({ sub: "user1", role: "oem" }) }));

function buildApp() {
  const app = Fastify();
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof HttpError) {
      reply.code(error.status).send(error.payload);
      return;
    }
    reply.code(500).send({ code: "INTERNAL_ERROR", message: String(error) });
  });
  app.register(oemRoutes, { prefix: "/api/v1/oem" });
  return app;
}

function importDevice(chain: ReturnType<typeof chainUnder>) {
  return buildApp().inject({
    method: "POST",
    url: "/api/v1/oem/import-device",
    payload: {
      device: { codename: "test", buildFingerprint: "fp" },
      buildPolicy: { verifiedBootKey: "aa11" },
      trustAnchor: { ec: chain, rsa: chain }
    }
  });
}

describe("/api/v1/oem/import-device root matching", () => {
  beforeEach(() => {
    mockPrisma.deviceEntry.create.mockClear();
  });

  it("accepts a root without a subject serialNumber when its key is registered", async () => {
    registeredRoots = [{ pem: huaweiRoot.pem, authority: { id: "huawei", name: "Huawei CBG", enabled: true } }];
    const response = await importDevice(chainUnder(huaweiRoot));

    expect(response.statusCode).toBe(200);
    expect(response.json().matchedAuthorityName).toBe("Huawei CBG");
    expect(mockPrisma.deviceEntry.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ authorityId: "huawei" }) })
    );
  });

  it("still accepts a Google-style root with a subject serialNumber", async () => {
    registeredRoots = [{ pem: googleStyleRoot.pem, authority: { id: "google", name: "Google", enabled: true } }];
    const response = await importDevice(chainUnder(googleStyleRoot));

    expect(response.statusCode).toBe(200);
    expect(response.json().matchedAuthorityName).toBe("Google");
  });

  it("rejects a root whose subject serialNumber matches but whose key differs", async () => {
    registeredRoots = [{ pem: googleStyleRoot.pem, authority: { id: "google", name: "Google", enabled: true } }];
    const response = await importDevice(chainUnder(impostorGoogleRoot));

    expect(response.statusCode).toBe(400);
    expect(response.json().code).toBe("UNKNOWN_ROOT");
    expect(mockPrisma.deviceEntry.create).not.toHaveBeenCalled();
  });

  it("ignores roots of disabled authorities", async () => {
    registeredRoots = [{ pem: huaweiRoot.pem, authority: { id: "huawei", name: "Huawei CBG", enabled: false } }];
    const response = await importDevice(chainUnder(huaweiRoot));

    expect(response.statusCode).toBe(400);
    expect(response.json().code).toBe("UNKNOWN_ROOT");
  });
});
