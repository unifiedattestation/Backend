import crypto from "crypto";
import fs from "fs";
import forge from "node-forge";
import { Config } from "../lib/config";

type UaProvisioningMaterial = {
  rootCertPem: string;
  rootPrivateKeyPem: string;
  intermediateCertPem?: string;
  intermediatePrivateKeyPem?: string;
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

function loadProvisioningMaterial(config: Config): UaProvisioningMaterial {
  const rootCertPem = readPemFile(config.ua_root_cert_path);
  const rootPrivateKeyPem = readPemFile(config.ua_root_private_key_path);
  if (!rootCertPem || !rootPrivateKeyPem) {
    throw new Error("UA root cert/private key paths are not configured");
  }
  const intermediateCertPem = readPemFile(config.ua_intermediate_cert_path);
  const intermediatePrivateKeyPem = readPemFile(config.ua_intermediate_private_key_path);
  if ((intermediateCertPem && !intermediatePrivateKeyPem) || (!intermediateCertPem && intermediatePrivateKeyPem)) {
    throw new Error("UA intermediate cert/private key must be provided together");
  }
  return {
    rootCertPem,
    rootPrivateKeyPem,
    intermediateCertPem,
    intermediatePrivateKeyPem
  };
}

function randomSerialHex(): string {
  const bytes = crypto.randomBytes(16);
  return bytes.toString("hex").toUpperCase();
}

function createLeafCertificate(
  leafPublicKeyPem: string,
  issuerCertPem: string,
  issuerPrivateKeyPem: string,
  subjectCommonName: string,
  serialHex: string
): string {
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(leafPublicKeyPem);
  cert.serialNumber = serialHex;
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000);
  const issuerCert = forge.pki.certificateFromPem(issuerCertPem);
  cert.setIssuer(issuerCert.subject.attributes);
  cert.setSubject([{ name: "commonName", value: subjectCommonName }]);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    {
      name: "keyUsage",
      digitalSignature: true,
      keyEncipherment: true
    }
  ]);
  const issuerKey = forge.pki.privateKeyFromPem(issuerPrivateKeyPem);
  cert.sign(issuerKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert).trim();
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

function buildCertificateChain(
  leafPublicKeyPem: string,
  material: UaProvisioningMaterial,
  label: string,
  serialHex: string
): string[] {
  if (material.intermediateCertPem && material.intermediatePrivateKeyPem) {
    const leafCert = createLeafCertificate(
      leafPublicKeyPem,
      material.intermediateCertPem,
      material.intermediatePrivateKeyPem,
      label,
      serialHex
    );
    return [leafCert, material.intermediateCertPem.trim(), material.rootCertPem.trim()];
  }
  const leafCert = createLeafCertificate(
    leafPublicKeyPem,
    material.rootCertPem,
    material.rootPrivateKeyPem,
    label,
    serialHex
  );
  return [leafCert, material.rootCertPem.trim()];
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

export function generateKeyboxXml(
  config: Config,
  deviceId: string,
  includeRsa: boolean,
  includeEcdsa: boolean,
  rsaSerialHex?: string,
  ecdsaSerialHex?: string
): string {
  if (!includeRsa || !includeEcdsa) {
    throw new Error("Keybox must include both RSA and ECDSA keys");
  }
  const material = loadProvisioningMaterial(config);
  const rsaSerial = (rsaSerialHex || randomSerialHex()).replace(/^0+/, "").toUpperCase();
  const ecdsaSerial = (ecdsaSerialHex || randomSerialHex()).replace(/^0+/, "").toUpperCase();
  const ecdsaKeys = generateKeyPair("ecdsa");
  const rsaKeys = generateKeyPair("rsa");
  const ecdsaEntry: GeneratedKey = {
    algorithm: "ecdsa",
    privateKeyPem: ecdsaKeys.privateKeyPem,
    certificateChainPem: buildCertificateChain(
      ecdsaKeys.publicKeyPem,
      material,
      "UA ECDSA Key",
      ecdsaSerial
    )
  };
  const rsaEntry: GeneratedKey = {
    algorithm: "rsa",
    privateKeyPem: rsaKeys.privateKeyPem,
    certificateChainPem: buildCertificateChain(
      rsaKeys.publicKeyPem,
      material,
      "UA RSA Key",
      rsaSerial
    )
  };
  const xmlBody =
    `<?xml version="1.0"?>\n` +
    `<AndroidAttestation>\n` +
    `<NumberOfKeyboxes>1</NumberOfKeyboxes>\n` +
    `<Keybox DeviceID="${deviceId}">` +
    `${buildKeyXml(ecdsaEntry)}${buildKeyXml(rsaEntry)}` +
    `</Keybox>\n` +
    `</AndroidAttestation>`;
  return xmlBody;
}
