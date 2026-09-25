import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getCertificateSerial } from "../src/chain";
import { createAttestationCache } from "../src/cache";
import { derToBase64, makeLeafWithAttestationExtension, makeRoot, toPem } from "./helpers";
import type { BuildPolicyInput, DeviceRegistryEntry, ParsedAttestation } from "../src/types";

// verify.ts's chain/name/signature/validity checks are already exercised
// against real signed certificates in chain.test.ts. Here, `parseKeyAttestation`
// is mocked to return controlled content -- see the comment on
// makeLeafWithAttestationExtension() in ./helpers for why (a confirmed
// node-forge limitation with high-tag-number KeyMint extension tags makes
// signing a *realistic* KeyMint-shaped extension unverifiable independently of
// this codebase). This still exercises the real chain signature/trust-anchor
// verification (via a real, correctly minimal, signed cert) alongside the
// real registry/cache/revocation/policy-matching orchestration in verify.ts.
let mockAttestation: ParsedAttestation;
vi.mock("../src/parsing", async () => {
  const actual = await vi.importActual<typeof import("../src/parsing")>("../src/parsing");
  return {
    ...actual,
    parseKeyAttestation: vi.fn(() => mockAttestation)
  };
});

// Must import verifyDeviceAttestation AFTER vi.mock (hoisted by Vitest anyway,
// but keep the intent explicit).
import { verifyDeviceAttestation } from "../src/verify";

const BASE_URL = "https://ua.example.test";
const SLUG = "acme-widget";
const CHALLENGE_HEX = "aabbccdd";
const VERIFIED_BOOT_KEY_HEX = "aa11bb22";
const VERIFIED_BOOT_HASH_HEX = "cc33dd44";
const PACKAGE_NAME = "com.example.app";
const SIGNER_DIGEST_HEX = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff";

function baseAttestation(overrides: Partial<ParsedAttestation> = {}): ParsedAttestation {
  return {
    attestationChallengeHex: CHALLENGE_HEX,
    attestationSecurityLevel: "TEE",
    keymasterSecurityLevel: "TEE",
    app: { packageName: PACKAGE_NAME, signerDigests: [SIGNER_DIGEST_HEX] },
    deviceIntegrity: {
      verifiedBootState: "VERIFIED",
      deviceLocked: true,
      verifiedBootKey: VERIFIED_BOOT_KEY_HEX,
      verifiedBootHash: VERIFIED_BOOT_HASH_HEX,
      osVersion: 140000,
      osPatchLevel: 202410
    },
    publicKeySpkiDer: Buffer.alloc(0),
    ...overrides
  };
}

function buildDeviceEntry(overrides: Partial<DeviceRegistryEntry> = {}): DeviceRegistryEntry {
  return {
    slug: SLUG,
    manufacturer: "Acme",
    brand: "acme",
    model: "Widget",
    codename: "widget",
    name: "widget",
    enabled: true,
    createdAt: new Date().toISOString(),
    oemOrgName: "Acme OEM",
    certificate: null,
    // Deliberately omits `enabled` -- the real /api/v1/devices/:slug endpoint
    // never sends it (it only ever lists already-enabled builds), and a past
    // bug here assumed it would be present.
    builds: [
      {
        buildFingerprint: "acme/widget/widget:14/AAA/1:user/release-keys",
        verifiedBootKeyHex: VERIFIED_BOOT_KEY_HEX,
        verifiedBootHashHex: VERIFIED_BOOT_HASH_HEX,
        osVersionRaw: 140000,
        minOsPatchLevelRaw: 202401
      } as unknown as BuildPolicyInput
    ],
    ...overrides
  };
}

function setupChain() {
  const root = makeRoot();
  const leaf = makeLeafWithAttestationExtension(root);
  const attestationChain = [derToBase64(leaf), derToBase64(root.cert)];
  const leafSerialHex = getCertificateSerial(Buffer.from(attestationChain[0], "base64"));
  return { root, leaf, attestationChain, leafSerialHex };
}

function mockFetch(handlers: {
  devices?: DeviceRegistryEntry;
  roots?: string[];
  status?: Record<string, { status: "REVOKED"; reason: string }>;
}) {
  const fn = vi.fn(async (input: string | URL) => {
    const url = String(input);
    if (url === `${BASE_URL}/api/v1/devices/${SLUG}`) {
      return new Response(JSON.stringify(handlers.devices), { status: 200 });
    }
    if (url === `${BASE_URL}/api/v1/info/root`) {
      return new Response(JSON.stringify(handlers.roots ?? []), { status: 200 });
    }
    if (url === `${BASE_URL}/api/v1/info/status`) {
      return new Response(JSON.stringify({ entries: handlers.status ?? {} }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  });
  vi.stubGlobal("fetch", fn);
  return { fn };
}

describe("verifyDeviceAttestation", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
    mockAttestation = baseAttestation();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("verifies a valid chain end to end (happy path)", async () => {
    const { root, attestationChain } = setupChain();
    mockFetch({ devices: buildDeviceEntry(), roots: [toPem(root.cert)] });

    const result = await verifyDeviceAttestation({
      attestationChain,
      requestHash: CHALLENGE_HEX,
      registryBaseUrl: BASE_URL,
      deviceSlug: SLUG,
      deviceMeta: { buildFingerprint: "acme/widget/widget:14/AAA/1:user/release-keys" }
    });

    expect(result.verdict.isTrusted).toBe(true);
    expect(result.verdict.reasonCodes).toEqual([]);
    expect(result.claims.app.packageName).toBe(PACKAGE_NAME);
  });

  it("rejects a revoked leaf certificate", async () => {
    const { root, attestationChain, leafSerialHex } = setupChain();
    const normalizedSerial = leafSerialHex.replace(/^0+/, "").toLowerCase();
    mockFetch({
      devices: buildDeviceEntry(),
      roots: [toPem(root.cert)],
      status: { [normalizedSerial]: { status: "REVOKED", reason: "UNSPECIFIED" } }
    });

    await expect(
      verifyDeviceAttestation({
        attestationChain,
        requestHash: CHALLENGE_HEX,
        registryBaseUrl: BASE_URL,
        deviceSlug: SLUG
      })
    ).rejects.toMatchObject({ code: "REVOKED_CERT" });
  });

  it("rejects on requestHash / attestation challenge mismatch", async () => {
    const { root, attestationChain } = setupChain();
    mockFetch({ devices: buildDeviceEntry(), roots: [toPem(root.cert)] });

    await expect(
      verifyDeviceAttestation({
        attestationChain,
        requestHash: "not-the-right-hash",
        registryBaseUrl: BASE_URL,
        deviceSlug: SLUG
      })
    ).rejects.toMatchObject({ code: "CHALLENGE_MISMATCH" });
  });

  it("rejects an untrusted root", async () => {
    const { attestationChain } = setupChain();
    const otherRoot = makeRoot("Someone Else's Root");
    mockFetch({ devices: buildDeviceEntry(), roots: [toPem(otherRoot.cert)] });

    await expect(
      verifyDeviceAttestation({
        attestationChain,
        requestHash: CHALLENGE_HEX,
        registryBaseUrl: BASE_URL,
        deviceSlug: SLUG
      })
    ).rejects.toMatchObject({ code: "UNTRUSTED_ROOT" });
  });

  it("flags BUILD_POLICY_MISMATCH when no registered build matches", async () => {
    const { root, attestationChain } = setupChain();
    mockFetch({
      devices: buildDeviceEntry({
        builds: [
          {
            buildFingerprint: "acme/widget/widget:14/AAA/1:user/release-keys",
            verifiedBootKeyHex: "ffffffff",
            verifiedBootHashHex: null,
            osVersionRaw: null,
            minOsPatchLevelRaw: null
          } as unknown as BuildPolicyInput
        ]
      }),
      roots: [toPem(root.cert)]
    });

    const result = await verifyDeviceAttestation({
      attestationChain,
      requestHash: CHALLENGE_HEX,
      registryBaseUrl: BASE_URL,
      deviceSlug: SLUG
    });
    expect(result.verdict.isTrusted).toBe(false);
    expect(result.verdict.reasonCodes).toContain("BUILD_POLICY_MISMATCH");
  });

  it("fails closed with BUILD_POLICY_MISMATCH when the device has no registered builds", async () => {
    const { root, attestationChain } = setupChain();
    mockFetch({ devices: buildDeviceEntry({ builds: [] }), roots: [toPem(root.cert)] });

    const result = await verifyDeviceAttestation({
      attestationChain,
      requestHash: CHALLENGE_HEX,
      registryBaseUrl: BASE_URL,
      deviceSlug: SLUG
    });
    expect(result.verdict.isTrusted).toBe(false);
    expect(result.verdict.reasonCodes).toContain("BUILD_POLICY_MISMATCH");
  });

  it("throws ANCHOR_MISSING when no root certificates are available", async () => {
    const { attestationChain } = setupChain();
    mockFetch({ devices: buildDeviceEntry(), roots: [] });

    await expect(
      verifyDeviceAttestation({
        attestationChain,
        requestHash: CHALLENGE_HEX,
        registryBaseUrl: BASE_URL,
        deviceSlug: SLUG
      })
    ).rejects.toMatchObject({ code: "ANCHOR_MISSING" });
  });

  it("reuses a shared cache instead of refetching on a second call", async () => {
    const { root, attestationChain } = setupChain();
    const { fn } = mockFetch({ devices: buildDeviceEntry(), roots: [toPem(root.cert)] });
    const cache = createAttestationCache();

    await verifyDeviceAttestation({
      attestationChain,
      requestHash: CHALLENGE_HEX,
      registryBaseUrl: BASE_URL,
      deviceSlug: SLUG,
      cache
    });
    const callCountAfterFirst = fn.mock.calls.length;

    await verifyDeviceAttestation({
      attestationChain,
      requestHash: CHALLENGE_HEX,
      registryBaseUrl: BASE_URL,
      deviceSlug: SLUG,
      cache
    });

    expect(fn.mock.calls).toHaveLength(callCountAfterFirst);
  });
});
