import crypto from "crypto";
import forge from "node-forge";

const ANDROID_KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

type ParsedAuthorizationList = {
  attestationApplicationId?: {
    packageName?: string;
    signerDigests: string[];
  };
  origin?: string;
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

type DerTlv = {
  tagClass: number;
  constructed: boolean;
  tagNumber: number;
  value: Buffer;
  totalLength: number;
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

export function hasAttestationExtension(der: Buffer): boolean {
  try {
    extractExtensionValue(der, ANDROID_KEY_ATTESTATION_OID);
    return true;
  } catch {
    return false;
  }
}

function readDerTlv(buffer: Buffer, offset: number): { tlv: DerTlv; nextOffset: number } {
  if (offset >= buffer.length) {
    throw new Error("DER parse out of bounds");
  }
  const first = buffer[offset];
  const tagClass = (first & 0xc0) >> 6;
  const constructed = (first & 0x20) === 0x20;
  let tagNumber = first & 0x1f;
  let cursor = offset + 1;
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    let more = true;
    while (more) {
      if (cursor >= buffer.length) {
        throw new Error("DER tag overflow");
      }
      const b = buffer[cursor];
      tagNumber = (tagNumber << 7) | (b & 0x7f);
      more = (b & 0x80) === 0x80;
      cursor += 1;
    }
  }
  if (cursor >= buffer.length) {
    throw new Error("DER length overflow");
  }
  const lenByte = buffer[cursor];
  cursor += 1;
  let length = 0;
  if (lenByte < 0x80) {
    length = lenByte;
  } else {
    const numBytes = lenByte & 0x7f;
    if (numBytes === 0) {
      throw new Error("Indefinite length not supported");
    }
    if (cursor + numBytes > buffer.length) {
      throw new Error("DER length overflow");
    }
    for (let i = 0; i < numBytes; i += 1) {
      length = (length << 8) | buffer[cursor + i];
    }
    cursor += numBytes;
  }
  const end = cursor + length;
  if (end > buffer.length) {
    throw new Error("DER value overflow");
  }
  const value = buffer.slice(cursor, end);
  return {
    tlv: {
      tagClass,
      constructed,
      tagNumber,
      value,
      totalLength: end - offset
    },
    nextOffset: end
  };
}

function parseDerCollection(buffer: Buffer, tagNumber: number): DerTlv[] {
  const { tlv } = readDerTlv(buffer, 0);
  if (tlv.tagClass !== 0 || tlv.tagNumber !== tagNumber) {
    throw new Error("Expected DER collection");
  }
  return parseDerChildren(tlv.value);
}

function parseDerChildren(buffer: Buffer): DerTlv[] {
  const result: DerTlv[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    const { tlv: child, nextOffset } = readDerTlv(buffer, offset);
    result.push(child);
    offset = nextOffset;
  }
  return result;
}

function parseDerInteger(value: Buffer): number {
  let num = 0;
  for (const b of value) {
    num = (num << 8) | b;
  }
  return num;
}

function parseDerBoolean(value: Buffer): boolean {
  return value.length > 0 && value[0] !== 0x00;
}

function parseBoolOrInt(value: Buffer): boolean {
  if (value.length === 1) {
    return value[0] !== 0x00;
  }
  return parseDerInteger(value) === 1;
}

function parseVerifiedBootState(value: Buffer): string {
  const level = parseDerInteger(value);
  return level === 0 ? "VERIFIED" : "UNVERIFIED";
}

function parseOrigin(value: Buffer): string {
  const origin = parseDerInteger(value);
  switch (origin) {
    case 0:
      return "GENERATED";
    case 1:
      return "DERIVED";
    case 2:
      return "IMPORTED";
    case 3:
      return "UNKNOWN";
    default:
      return "UNKNOWN";
  }
}

function extractOctetStringValue(value: Buffer): Buffer {
  try {
    const { tlv } = readDerTlv(value, 0);
    if (tlv.tagClass === 0 && tlv.tagNumber === 4 && tlv.totalLength === value.length) {
      return tlv.value;
    }
  } catch {
    return value;
  }
  return value;
}

function parseDerCollectionFromValue(value: Buffer): DerTlv[] {
  try {
    const { tlv } = readDerTlv(value, 0);
    if (tlv.tagClass === 0 && (tlv.tagNumber === 16 || tlv.tagNumber === 17)) {
      return parseDerChildren(tlv.value);
    }
    if (tlv.tagClass === 0 && tlv.tagNumber === 4) {
      const inner = readDerTlv(tlv.value, 0).tlv;
      if (inner.tagClass === 0 && (inner.tagNumber === 16 || inner.tagNumber === 17)) {
        return parseDerChildren(inner.value);
      }
    }
  } catch {
    return [];
  }
  try {
    return parseDerChildren(value);
  } catch {
    return [];
  }
}

function parseAttestationApplicationId(value: Buffer): ParsedAuthorizationList["attestationApplicationId"] {
  let seq: DerTlv[] = [];
  try {
    seq = parseDerCollectionFromValue(value);
  } catch {
    return { signerDigests: [] };
  }
  const packageInfos = seq[0]?.value ? parseDerChildren(seq[0].value) : [];
  const signatureDigests = seq[1]?.value ? parseDerChildren(seq[1].value) : [];
  let packageName: string | undefined;
  if (packageInfos.length > 0) {
    const first = packageInfos[0];
    if (first.tagClass === 0 && first.tagNumber === 4) {
      packageName = first.value.toString("utf8");
    } else if (first.tagClass === 0 && first.tagNumber === 16) {
      const pkgInfo = parseDerChildren(first.value);
      const nameTlv = pkgInfo[0];
      if (nameTlv && nameTlv.tagClass === 0 && nameTlv.tagNumber === 4) {
        packageName = nameTlv.value.toString("utf8");
      }
    }
  }
  const signerDigests = signatureDigests
    .filter((tlv) => tlv.tagClass === 0 && tlv.tagNumber === 4)
    .map((tlv) => tlv.value.toString("hex"));
  return { packageName, signerDigests };
}

function parseAuthorizationList(buffer: Buffer): ParsedAuthorizationList {
  const result: ParsedAuthorizationList = {};
  let entries: DerTlv[] = [];
  try {
    entries = parseDerCollection(buffer, 16);
  } catch {
    try {
      entries = parseDerCollection(buffer, 17);
    } catch {
      try {
        let offset = 0;
        while (offset < buffer.length) {
          const { tlv, nextOffset } = readDerTlv(buffer, offset);
          entries.push(tlv);
          offset = nextOffset;
        }
      } catch {
        return result;
      }
    }
  }
  for (const entry of entries) {
    if (entry.tagClass !== 2) {
      continue;
    }
    let value = entry.value;
    if (entry.constructed && value.length > 0) {
      try {
        const { tlv: inner } = readDerTlv(value, 0);
        if (inner.tagClass === 0 && (inner.tagNumber === 1 || inner.tagNumber === 2 || inner.tagNumber === 4 || inner.tagNumber === 10)) {
          value = inner.value;
        } else {
          value = entry.value;
        }
      } catch {
        // leave value as-is
      }
    }
    switch (entry.tagNumber) {
      case 702:
        result.origin = parseOrigin(value);
        break;
      case 704:
        try {
          const { tlv } = readDerTlv(value, 0);
          if (tlv.tagClass === 0 && tlv.tagNumber === 16) {
            const parts = parseDerChildren(tlv.value);
            const key = parts.find((part) => part.tagClass === 0 && part.tagNumber === 4);
            const locked = parts.find((part) => part.tagClass === 0 && part.tagNumber === 1);
            const state = parts.find((part) => part.tagClass === 0 && part.tagNumber === 10);
            const octets = parts.filter((part) => part.tagClass === 0 && part.tagNumber === 4);
            const hash = octets.length > 1 ? octets[1] : undefined;
            if (key) {
              result.verifiedBootKey = key.value.toString("hex");
            }
            if (locked) {
              result.deviceLocked = parseBoolOrInt(locked.value);
            }
            if (state) {
              result.verifiedBootState = parseVerifiedBootState(state.value);
            }
            if (hash) {
              result.verifiedBootHash = hash.value.toString("hex");
            }
            break;
          }
        } catch {
          // fall through to octet extraction
        }
        if (!result.verifiedBootKey) {
          result.verifiedBootKey = extractOctetStringValue(value).toString("hex");
        }
        break;
      case 705:
        if (value.length <= 2) {
          if (!result.verifiedBootState) {
            result.verifiedBootState = parseVerifiedBootState(value);
          }
        } else {
          result.osVersionRaw = parseDerInteger(value);
        }
        break;
      case 706:
        if (value.length <= 4) {
          result.osPatchLevelRaw = parseDerInteger(value);
          result.osPatchLevel = result.osPatchLevelRaw;
        } else if (!result.verifiedBootHash) {
          result.verifiedBootHash = extractOctetStringValue(value).toString("hex");
        }
        break;
      case 718:
        result.vendorPatchLevelRaw = parseDerInteger(value);
        result.vendorPatchLevel = result.vendorPatchLevelRaw;
        break;
      case 719:
        result.bootPatchLevelRaw = parseDerInteger(value);
        result.bootPatchLevel = result.bootPatchLevelRaw;
        break;
      case 7060:
        result.osPatchLevelRaw = parseDerInteger(value);
        result.osPatchLevel = result.osPatchLevelRaw;
        break;
      case 7061:
        result.vendorPatchLevelRaw = parseDerInteger(value);
        result.vendorPatchLevel = result.vendorPatchLevelRaw;
        break;
      case 7062:
        result.bootPatchLevelRaw = parseDerInteger(value);
        result.bootPatchLevel = result.bootPatchLevelRaw;
        break;
      case 7063:
        result.teePatchLevel = parseDerInteger(value);
        break;
      case 7050:
        result.osVersionRaw = parseDerInteger(value);
        break;
      case 709:
        result.attestationApplicationId = parseAttestationApplicationId(value);
        break;
      default:
        break;
    }
  }
  return result;
}

function parseSecurityLevel(value: Buffer): string {
  const level = parseDerInteger(value);
  switch (level) {
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
  const seq = parseDerCollection(extBytes, 16);
  if (seq.length < 8) {
    throw new Error("Invalid attestation extension format");
  }
  const attestationSecurityLevel = parseSecurityLevel(seq[1].value);
  const keymasterSecurityLevel = parseSecurityLevel(seq[3].value);
  const challenge = seq[4].value.toString("hex");
  const softwareEnforced = parseAuthorizationList(seq[6].value);
  const teeEnforced = parseAuthorizationList(seq[7].value);
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

export function verifyCertificateChainStrict(
  chain: Buffer[],
  trustAnchors: string[],
  validationDate: Date = new Date()
): void {
  const certs = chain.map((der) => new crypto.X509Certificate(der));
  if (certs.length === 0) {
    throw new Error("Empty certificate chain");
  }
  if (!hasAttestationExtension(chain[0])) {
    throw new Error("Missing attestation extension on leaf");
  }
  for (let i = 1; i < chain.length; i += 1) {
    if (hasAttestationExtension(chain[i])) {
      throw new Error("Attestation extension present in non-leaf certificate");
    }
  }
  for (let i = 0; i < certs.length - 1; i += 1) {
    const subject = certs[i];
    const issuer = certs[i + 1];
    if (subject.issuer !== issuer.subject) {
      throw new Error("Certificate name chaining failed");
    }
    if (!subject.verify(issuer.publicKey)) {
      throw new Error("Invalid certificate chain");
    }
  }
  for (let i = 1; i < certs.length; i += 1) {
    const cert = certs[i];
    if (validationDate < cert.validFrom || validationDate > cert.validTo) {
      throw new Error("Certificate validity failed");
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
