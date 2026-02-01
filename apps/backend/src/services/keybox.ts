import crypto from "crypto";
import fs from "fs";
import type * as x509Types from "@peculiar/x509";
import { Config } from "../lib/config";

type UaProvisioningMaterial = {
  issuerCertPem: string;
  issuerPrivateKeyPem: string;
  rootCertPem: string;
};

type GeneratedKey = {
  algorithm: "ecdsa" | "rsa";
  privateKeyPem: string;
  certificateChainPem: string[];
};

function readPemFile(pathname?: string): string | undefined {
  if (!pathname) return undefined;
  const content = fs.readFileSync(pathname, "utf8");
  return content.trim();
}

function randomSerialHex(): string {
  const bytes = crypto.randomBytes(16);
  return bytes.toString("hex").toUpperCase();
}

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
    x509Module.X509CertificateGenerator.crypto = crypto.webcrypto;
    x509CryptoReady = true;
  }
  return x509Module;
}

function toPem(label: string, der: ArrayBuffer) {
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

async function importSigningKey(issuerPrivateKeyPem: string, algorithm: "rsa" | "ecdsa") {
  const subtle = crypto.webcrypto.subtle;
  const keyObject = crypto.createPrivateKey(issuerPrivateKeyPem);
  const pkcs8Der = keyObject.export({ type: "pkcs8", format: "der" });
  if (algorithm === "rsa") {
    return subtle.importKey(
      "pkcs8",
      pkcs8Der,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );
  }
  return subtle.importKey("pkcs8", pkcs8Der, { name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign"
  ]);
}

function keyUsageForAlgorithm(algorithm: "rsa" | "ecdsa") {
  return algorithm === "rsa"
    ? x509Module!.KeyUsageFlags.digitalSignature | x509Module!.KeyUsageFlags.keyEncipherment
    : x509Module!.KeyUsageFlags.digitalSignature;
}

async function createLeafCertificate(
  leafPublicKeyPem: string,
  issuerCertPem: string,
  issuerPrivateKeyPem: string,
  subjectCommonName: string,
  serialHex: string,
  algorithm: "rsa" | "ecdsa"
): Promise<string> {
  const { X509CertificateGenerator, Name, BasicConstraintsExtension, KeyUsagesExtension, PemConverter } =
    await loadX509();
  const issuer = new crypto.X509Certificate(issuerCertPem);
  const leafPublicKey = crypto.createPublicKey(leafPublicKeyPem);
  const signingKey = await importSigningKey(issuerPrivateKeyPem, algorithm);
  const cert = await X509CertificateGenerator.create({
    serialNumber: serialHex,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000),
    publicKey: leafPublicKey.export({ type: "spki", format: "der" }),
    subject: new Name(`CN=${subjectCommonName}`),
    issuer: new Name(issuer.subject),
    signingKey,
    extensions: [
      new BasicConstraintsExtension(false, undefined, true),
      new KeyUsagesExtension(keyUsageForAlgorithm(algorithm), true)
    ]
  });
  return (
    PemConverter?.encode?.(cert.rawData, "CERTIFICATE")?.trim() ??
    toPem("CERTIFICATE", cert.rawData)
  );
}

function generateKeyPair(algorithm: "ecdsa" | "rsa") {
  if (algorithm === "ecdsa") {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });
    return {
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString().trim(),
      privateKeyPem: privateKey.export({ type: "sec1", format: "pem" }).toString().trim()
    };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001
  });
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString().trim(),
    privateKeyPem: privateKey.export({ type: "pkcs1", format: "pem" }).toString().trim()
  };
}

async function buildCertificateChain(
  leafPublicKeyPem: string,
  material: UaProvisioningMaterial,
  label: string,
  serialHex: string,
  algorithm: "rsa" | "ecdsa"
): Promise<string[]> {
  const leafCert = await createLeafCertificate(
    leafPublicKeyPem,
    material.issuerCertPem,
    material.issuerPrivateKeyPem,
    label,
    serialHex,
    algorithm
  );
  return [leafCert, material.issuerCertPem.trim(), material.rootCertPem.trim()];
}

function wrapPemBlock(pem: string): string {
  return `\n${pem.trim()}\n`;
}

function buildKeyXml(entry: GeneratedKey): string {
  const certsXml = entry.certificateChainPem
    .map((cert) => `<Certificate format="pem">${wrapPemBlock(cert)}</Certificate>`)
    .join("");
  return `<Key algorithm="${entry.algorithm}"><PrivateKey format="pem">${wrapPemBlock(
    entry.privateKeyPem
  )}</PrivateKey><CertificateChain><NumberOfCertificates>${entry.certificateChainPem.length}</NumberOfCertificates>${certsXml}</CertificateChain></Key>`;
}

export async function generateKeyboxXml(
  config: Config,
  deviceId: string,
  includeRsa: boolean,
  includeEcdsa: boolean,
  rsaSerialHex?: string,
  ecdsaSerialHex?: string
): Promise<string> {
  if (!includeRsa || !includeEcdsa) {
    throw new Error("Keybox must include both RSA and ECDSA keys");
  }
  const rsaCert = readPemFile(config.ua_root_rsa_cert_path);
  const rsaKey = readPemFile(config.ua_root_rsa_private_key_path);
  const ecdsaCert = readPemFile(config.ua_root_ecdsa_cert_path);
  const ecdsaKey = readPemFile(config.ua_root_ecdsa_private_key_path);
  if (!rsaCert || !rsaKey || !ecdsaCert || !ecdsaKey) {
    throw new Error("UA root cert/private key paths are not configured");
  }
  return generateKeyboxXmlWithDualRoots(
    { issuerCertPem: rsaCert, issuerPrivateKeyPem: rsaKey, rootCertPem: rsaCert },
    { issuerCertPem: ecdsaCert, issuerPrivateKeyPem: ecdsaKey, rootCertPem: ecdsaCert },
    deviceId,
    rsaSerialHex || randomSerialHex(),
    ecdsaSerialHex || randomSerialHex()
  );
}

export async function generateKeyboxXmlWithDualRoots(
  rsaRoots: { issuerCertPem: string; issuerPrivateKeyPem: string; rootCertPem: string },
  ecdsaRoots: { issuerCertPem: string; issuerPrivateKeyPem: string; rootCertPem: string },
  deviceId: string,
  rsaSerialHex: string,
  ecdsaSerialHex: string
): Promise<string> {
  const rsaMaterial: UaProvisioningMaterial = {
    issuerCertPem: rsaRoots.issuerCertPem,
    issuerPrivateKeyPem: rsaRoots.issuerPrivateKeyPem,
    rootCertPem: rsaRoots.rootCertPem
  };
  const ecdsaMaterial: UaProvisioningMaterial = {
    issuerCertPem: ecdsaRoots.issuerCertPem,
    issuerPrivateKeyPem: ecdsaRoots.issuerPrivateKeyPem,
    rootCertPem: ecdsaRoots.rootCertPem
  };
  const ecdsaKeys = generateKeyPair("ecdsa");
  const rsaKeys = generateKeyPair("rsa");
  const ecdsaEntry: GeneratedKey = {
    algorithm: "ecdsa",
    privateKeyPem: ecdsaKeys.privateKeyPem,
    certificateChainPem: await buildCertificateChain(
      ecdsaKeys.publicKeyPem,
      ecdsaMaterial,
      "UA ECDSA Key",
      ecdsaSerialHex,
      "ecdsa"
    )
  };
  const rsaEntry: GeneratedKey = {
    algorithm: "rsa",
    privateKeyPem: rsaKeys.privateKeyPem,
    certificateChainPem: await buildCertificateChain(
      rsaKeys.publicKeyPem,
      rsaMaterial,
      "UA RSA Key",
      rsaSerialHex,
      "rsa"
    )
  };
  return (
    `<?xml version="1.0"?>\n` +
    `<AndroidAttestation>\n` +
    `<NumberOfKeyboxes>1</NumberOfKeyboxes>\n` +
    `<Keybox DeviceID="${deviceId}">` +
    `${buildKeyXml(ecdsaEntry)}${buildKeyXml(rsaEntry)}` +
    `</Keybox>\n` +
    `</AndroidAttestation>`
  );
}
