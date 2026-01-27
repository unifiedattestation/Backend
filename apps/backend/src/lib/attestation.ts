import crypto from "crypto";
import forge from "node-forge";

const ANDROID_KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

type ParsedAuthorizationList = {
  attestationApplicationId?: {
    packageName?: string;
    signerDigests: string[];
  };
  verifiedBootState?: string;
  deviceLocked?: boolean;
  verifiedBootKey?: string;
  verifiedBootHash?: string;
  osVersionRaw?: number;
  osPatchLevelRaw?: number;
  vendorPatchLevelRaw?: number;
  bootPatchLevelRaw?: number;
  osPatchLevel?: number;
  vendorPatchLevel?: number;
  bootPatchLevel?: number;
  teePatchLevel?: number;
};

export type ParsedAttestation = {
  attestationChallengeHex: string;
  attestationSecurityLevel: string;
  keymasterSecurityLevel: string;
  app: {
    packageName?: string;
    signerDigests: string[];
  };
  deviceIntegrity: ParsedAuthorizationList;
  publicKeySpkiDer: Buffer;
};

function extractExtensionValue(der: Buffer, oid: string): Buffer {
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(der.toString("binary"), "binary"));
  const certSeq = asn1.value as forge.asn1.Asn1[];
  const tbs = certSeq[0];
  const tbsSeq = tbs.value as forge.asn1.Asn1[];
  const extensionsWrapper = tbsSeq.find(
    (node) => node.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && node.type === 3
  );
  if (!extensionsWrapper) {
    throw new Error("Missing certificate extensions");
  }
  const extensionsSeq = (extensionsWrapper.value as forge.asn1.Asn1[])[0];
  const extensions = (extensionsSeq.value as forge.asn1.Asn1[]) || [];
  for (const extension of extensions) {
    const nodes = extension.value as forge.asn1.Asn1[];
    const oidNode = nodes[0];
    const oidValue = forge.asn1.derToOid(oidNode.value as string);
    if (oidValue === oid) {
      const valueNode = nodes[nodes.length - 1];
      return Buffer.from(valueNode.value as string, "binary");
    }
  }
  throw new Error("Missing attestation extension");
}

export function getCertificateSerial(der: Buffer): string {
  const cert = new crypto.X509Certificate(der);
  return cert.serialNumber.toUpperCase();
}

function bytesToHex(value: string): string {
  return Buffer.from(value, "binary").toString("hex");
}

function asn1Integer(node: forge.asn1.Asn1): number {
  const hex = bytesToHex(node.value as string);
  return parseInt(hex || "0", 16);
}

function asn1Enumerated(node: forge.asn1.Asn1): number {
  return asn1Integer(node);
}

function asn1OctetString(node: forge.asn1.Asn1): Buffer {
  return Buffer.from(node.value as string, "binary");
}

function asn1Boolean(node: forge.asn1.Asn1): boolean {
  const bytes = Buffer.from(node.value as string, "binary");
  return bytes.length > 0 && bytes[0] !== 0x00;
}

function parseAttestationApplicationId(value: Buffer): ParsedAuthorizationList["attestationApplicationId"] {
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(value.toString("binary"), "binary"));
  const sequence = asn1.value as forge.asn1.Asn1[];
  const packageInfos = sequence[0]?.value as forge.asn1.Asn1[] | undefined;
  const signatureDigests = sequence[1]?.value as forge.asn1.Asn1[] | undefined;
  let packageName: string | undefined;
  if (packageInfos && packageInfos.length > 0) {
    const packageInfo = packageInfos[0]?.value as forge.asn1.Asn1[] | undefined;
    if (packageInfo && packageInfo.length > 0) {
      const pkg = packageInfo[0];
      if (pkg?.value) {
        packageName = forge.util.decodeUtf8(pkg.value as string);
      }
    }
  }
  const signerDigests =
    signatureDigests?.map((digest) => bytesToHex(digest.value as string)) || [];
  return { packageName, signerDigests };
}

function parseAuthorizationList(listNode: forge.asn1.Asn1): ParsedAuthorizationList {
  const result: ParsedAuthorizationList = {};
  const entries = (listNode.value as forge.asn1.Asn1[]) || [];
  for (const entry of entries) {
    if (entry.tagClass !== forge.asn1.Class.CONTEXT_SPECIFIC) {
      continue;
    }
    const tag = entry.type;
    const valueNode = (entry.value as forge.asn1.Asn1[])[0] || entry;
    switch (tag) {
      case 702:
        result.deviceLocked = asn1Boolean(valueNode);
        break;
      case 704:
        result.verifiedBootKey = asn1OctetString(valueNode).toString("hex");
        break;
      case 705:
        result.verifiedBootState = asn1Enumerated(valueNode) === 0 ? "VERIFIED" : "UNVERIFIED";
        break;
      case 706:
        result.verifiedBootHash = asn1OctetString(valueNode).toString("hex");
        break;
      case 7060:
        result.osPatchLevelRaw = asn1Integer(valueNode);
        result.osPatchLevel = result.osPatchLevelRaw;
        break;
      case 7061:
        result.vendorPatchLevelRaw = asn1Integer(valueNode);
        result.vendorPatchLevel = result.vendorPatchLevelRaw;
        break;
      case 7062:
        result.bootPatchLevelRaw = asn1Integer(valueNode);
        result.bootPatchLevel = result.bootPatchLevelRaw;
        break;
      case 7063:
        result.teePatchLevel = asn1Integer(valueNode);
        break;
      case 7050:
        result.osVersionRaw = asn1Integer(valueNode);
        break;
      case 709:
        result.attestationApplicationId = parseAttestationApplicationId(asn1OctetString(valueNode));
        break;
      default:
        break;
    }
  }
  return result;
}

function parseSecurityLevel(node: forge.asn1.Asn1): string {
  const value = asn1Enumerated(node);
  switch (value) {
    case 0:
      return "SOFTWARE";
    case 1:
      return "TEE";
    case 2:
      return "STRONGBOX";
    default:
      return "UNKNOWN";
  }
}

export function parseKeyAttestation(certificateDer: Buffer): ParsedAttestation {
  const extBytes = extractExtensionValue(certificateDer, ANDROID_KEY_ATTESTATION_OID);
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(extBytes.toString("binary"), "binary"));
  const seq = asn1.value as forge.asn1.Asn1[];
  if (!seq || seq.length < 8) {
    throw new Error("Invalid attestation extension format");
  }
  const attestationSecurityLevel = parseSecurityLevel(seq[1]);
  const keymasterSecurityLevel = parseSecurityLevel(seq[3]);
  const challenge = asn1OctetString(seq[4]).toString("hex");
  const softwareEnforced = parseAuthorizationList(seq[6]);
  const teeEnforced = parseAuthorizationList(seq[7]);
  const app =
    teeEnforced.attestationApplicationId ||
    softwareEnforced.attestationApplicationId || { signerDigests: [] };
  const cert = new crypto.X509Certificate(certificateDer);
  const publicKeyDer = cert.publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return {
    attestationChallengeHex: challenge,
    attestationSecurityLevel,
    keymasterSecurityLevel,
    app: {
      packageName: app.packageName,
      signerDigests: app.signerDigests || []
    },
    deviceIntegrity: {
      ...softwareEnforced,
      ...teeEnforced
    },
    publicKeySpkiDer: Buffer.from(publicKeyDer)
  };
}

export function parseCertificateChain(chain: string[]): Buffer[] {
  return chain.map((der) => {
    return Buffer.from(der, "base64");
  });
}

export function verifyCertificateChain(
  chain: Buffer[],
  trustAnchors: string[]
): void {
  const certs = chain.map((der) => new crypto.X509Certificate(der));
  if (certs.length === 0) {
    throw new Error("Empty certificate chain");
  }
  for (let i = 0; i < certs.length - 1; i += 1) {
    const issuer = certs[i + 1];
    if (!certs[i].verify(issuer.publicKey)) {
      throw new Error("Invalid certificate chain");
    }
  }
  const trustCerts = trustAnchors.map((pem) => new crypto.X509Certificate(pem));
  const root = certs[certs.length - 1];
  const trusted = trustCerts.some(
    (anchor) => root.verify(anchor.publicKey) || root.raw.equals(anchor.raw)
  );
  if (!trusted) {
    throw new Error("Untrusted certificate chain");
  }
}
