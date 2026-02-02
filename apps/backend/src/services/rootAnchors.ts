import crypto from "crypto";
import type * as x509Types from "@peculiar/x509";

let x509Module: typeof x509Types | null = null;
let x509CryptoReady = false;

async function loadX509() {
  if (!x509Module) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    x509Module = require("@peculiar/x509") as typeof x509Types;
  }
  if (!x509CryptoReady) {
    if (!crypto.webcrypto) {
      throw new Error("WebCrypto is not available for X.509 generation");
    }
    x509Module.cryptoProvider.set(crypto.webcrypto as any);
    x509CryptoReady = true;
  }
  return x509Module;
}

function toPem(label: string, der: ArrayBuffer) {
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

export async function generateSelfSignedRoot(commonName: string, algorithm: "rsa" | "ecdsa") {
  const {
    X509CertificateGenerator,
    Name,
    BasicConstraintsExtension,
    KeyUsagesExtension,
    KeyUsageFlags,
    PemConverter
  } = await loadX509();
  const subtle = crypto.webcrypto.subtle;
  const algorithmParams =
    algorithm === "rsa"
      ? {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: "SHA-256"
        }
      : {
          name: "ECDSA",
          namedCurve: "P-256"
        };
  const keys = await subtle.generateKey(algorithmParams, true, ["sign", "verify"]);
  const serialNumber = crypto.randomBytes(16).toString("hex").toUpperCase();
  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber,
    name: new Name(`CN=${commonName}`),
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000),
    keys,
    extensions: [
      new BasicConstraintsExtension(true, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.digitalSignature, true)
    ]
  });
  const privateKeyDer = await subtle.exportKey("pkcs8", keys.privateKey);
  const certPem =
    PemConverter?.encode?.(cert.rawData, "CERTIFICATE")?.trim() ??
    toPem("CERTIFICATE", cert.rawData);
  const keyPem =
    PemConverter?.encode?.(privateKeyDer, "PRIVATE KEY")?.trim() ??
    toPem("PRIVATE KEY", privateKeyDer);
  return { certPem, keyPem, serialHex: serialNumber };
}

export async function generateIntermediateSignedByRoot(
  commonName: string,
  algorithm: "rsa" | "ecdsa",
  issuerCertPem: string,
  issuerPrivateKeyPem: string
) {
  const {
    X509CertificateGenerator,
    X509Certificate,
    Name,
    BasicConstraintsExtension,
    KeyUsagesExtension,
    KeyUsageFlags,
    PemConverter
  } = await loadX509();
  const subtle = crypto.webcrypto.subtle;
  const algorithmParams =
    algorithm === "rsa"
      ? {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: "SHA-256"
        }
      : {
          name: "ECDSA",
          namedCurve: "P-256"
        };
  const keys = await subtle.generateKey(algorithmParams, true, ["sign", "verify"]);
  const issuerCert = new X509Certificate(issuerCertPem);
  const signingKey = await subtle.importKey(
    "pkcs8",
    Buffer.from(
      issuerPrivateKeyPem
        .replace(/-----(BEGIN|END) [\s\S]+?-----/g, "")
        .replace(/\s+/g, ""),
      "base64"
    ),
    algorithmParams,
    false,
    ["sign"]
  );
  const serialNumber = crypto.randomBytes(16).toString("hex").toUpperCase();
  const cert = await X509CertificateGenerator.create({
    serialNumber,
    subject: new Name(`C=DE, O=Unified Attestation, CN=${commonName}`),
    issuer: new Name(issuerCert.subject),
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000),
    publicKey: keys.publicKey,
    signingKey,
    signingAlgorithm: algorithmParams,
    extensions: [
      new BasicConstraintsExtension(true, 0, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.digitalSignature, true)
    ]
  });
  const privateKeyDer = await subtle.exportKey("pkcs8", keys.privateKey);
  const certPem =
    PemConverter?.encode?.(cert.rawData, "CERTIFICATE")?.trim() ??
    toPem("CERTIFICATE", cert.rawData);
  const keyPem =
    PemConverter?.encode?.(privateKeyDer, "PRIVATE KEY")?.trim() ??
    toPem("PRIVATE KEY", privateKeyDer);
  return { certPem, keyPem, serialHex: serialNumber };
}
