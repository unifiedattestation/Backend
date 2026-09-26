import Fastify from "fastify";
import { beforeEach, describe, expect, it, vi } from "vitest";
import oemRoutes from "../src/routes/oem";
import { HttpError } from "../src/lib/errors";

// /device/process resolves the active anchor per device family, so creating
// an anchor must only be blocked by an active anchor on the *same* family,
// never by another family's anchor in the same OEM org.
type Entry = { oemOrgId: string; deviceFamilyId: string; revokedAt: Date | null };
let entries: Entry[] = [];

const matches = (entry: Entry, where: Partial<Entry>) =>
  Object.entries(where).every(([key, value]) => (entry as any)[key] === value);

const mockPrisma = {
  oemOrg: { findFirst: vi.fn(() => Promise.resolve({ id: "org1", name: "OEM" })) },
  deviceFamily: {
    findFirst: vi.fn(({ where }: any) =>
      Promise.resolve({ id: where.id, codename: where.id, oemOrgId: "org1" })
    )
  },
  attestationAuthority: {
    findUnique: vi.fn(() =>
      Promise.resolve({ id: "google", enabled: true, roots: [{ id: "r1", pem: "pem", oemOrgId: null }] })
    )
  },
  deviceEntry: {
    count: vi.fn(({ where }: any) => Promise.resolve(entries.filter((e) => matches(e, where)).length)),
    create: vi.fn(({ data }: any) => {
      entries.push({ oemOrgId: data.oemOrgId, deviceFamilyId: data.deviceFamilyId, revokedAt: null });
      return Promise.resolve({ id: `entry${entries.length}`, ...data });
    })
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

function createAnchor(deviceFamilyId: string, serialSuffix: string) {
  return buildApp().inject({
    method: "POST",
    url: "/api/v1/oem/anchors",
    payload: {
      deviceFamilyId,
      authorityId: "google",
      rsaSerialHex: `A${serialSuffix}`,
      ecdsaSerialHex: `B${serialSuffix}`,
      rsaIntermediateSerialHex: `C${serialSuffix}`,
      ecdsaIntermediateSerialHex: `D${serialSuffix}`
    }
  });
}

describe("POST /api/v1/oem/anchors", () => {
  beforeEach(() => {
    entries = [];
  });

  it("allows an active anchor on each device family of the same OEM", async () => {
    expect((await createAnchor("phoneA", "1")).statusCode).toBe(200);
    expect((await createAnchor("phoneB", "2")).statusCode).toBe(200);
    expect(entries).toHaveLength(2);
  });

  it("rejects a second active anchor on the same device family", async () => {
    expect((await createAnchor("phoneA", "1")).statusCode).toBe(200);
    const response = await createAnchor("phoneA", "2");

    expect(response.statusCode).toBe(400);
    expect(response.json().message).toMatch(/Revoke this device's existing anchor/);
    expect(entries).toHaveLength(1);
  });

  it("allows a new anchor once the family's previous one is revoked", async () => {
    entries.push({ oemOrgId: "org1", deviceFamilyId: "phoneA", revokedAt: new Date() });
    expect((await createAnchor("phoneA", "1")).statusCode).toBe(200);
  });
});
