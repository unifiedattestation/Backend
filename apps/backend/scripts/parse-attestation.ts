import crypto from "crypto";
import forge from "node-forge";
import { hasAttestationExtension, parseKeyAttestation } from "../src/lib/attestation";

import fs from "fs";
import path from "path";

const DEFAULT_CERT_PATH = path.resolve(__dirname, "fixtures", "attestation-leaf.b64");

function loadCertBase64(): string {
  const arg = process.argv.find((value) => value.startsWith("--cert="));
  if (arg) {
    return arg.slice("--cert=".length).trim();
  }
  const fileArg = process.argv.find((value) => value.startsWith("--cert-file="));
  if (fileArg) {
    return fs.readFileSync(fileArg.slice("--cert-file=".length).trim(), "utf8").trim();
  }
  if (process.env.UA_ATTESTATION_CERT_BASE64) {
    return process.env.UA_ATTESTATION_CERT_BASE64.trim();
  }
  if (process.env.UA_ATTESTATION_CERT_FILE) {
    return fs.readFileSync(process.env.UA_ATTESTATION_CERT_FILE, "utf8").trim();
  }
  return fs.readFileSync(DEFAULT_CERT_PATH, "utf8").trim();
}

function main() {
  const certBase64 = loadCertBase64();
  const der = Buffer.from(certBase64, "base64");
  const cert = new crypto.X509Certificate(der);
  console.log("Subject:", cert.subject);
  console.log("Issuer:", cert.issuer);
  console.log("Serial:", cert.serialNumber);
  console.log("Has attestation extension:", hasAttestationExtension(der));
  try {
    const certAsn1 = forge.asn1.fromDer(
      forge.util.createBuffer(der.toString("binary"), "binary")
    );
    const tbs = (certAsn1.value || [])[0];
    const tbsSeq = (tbs?.value as forge.asn1.Asn1[]) || [];
    const extWrap = tbsSeq.find(
      (node) => node.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && node.type === 3
    );
    const extSeq = ((extWrap?.value as forge.asn1.Asn1[]) || [])[0];
    const extensions = (extSeq?.value as forge.asn1.Asn1[]) || [];
    for (const ext of extensions) {
      const nodes = (ext.value as forge.asn1.Asn1[]) || [];
      const oidNode = nodes[0];
      const oid = forge.asn1.derToOid(oidNode.value as string);
      if (oid !== "1.3.6.1.4.1.11129.2.1.17") {
        continue;
      }
      const valueNode = nodes[nodes.length - 1];
      const raw = Buffer.from(valueNode.value as string, "binary");
      console.log("Attestation ext len:", raw.length);
      const readDerTlv = (buffer: Buffer, offset: number) => {
        const first = buffer[offset];
        const tagClass = (first & 0xc0) >> 6;
        const constructed = (first & 0x20) === 0x20;
        let tagNumber = first & 0x1f;
        let cursor = offset + 1;
        if (tagNumber === 0x1f) {
          tagNumber = 0;
          let more = true;
          while (more) {
            const b = buffer[cursor];
            tagNumber = (tagNumber << 7) | (b & 0x7f);
            more = (b & 0x80) === 0x80;
            cursor += 1;
          }
        }
        const lenByte = buffer[cursor];
        cursor += 1;
        let length = 0;
        if (lenByte < 0x80) {
          length = lenByte;
        } else {
          const numBytes = lenByte & 0x7f;
          for (let i = 0; i < numBytes; i += 1) {
            length = (length << 8) | buffer[cursor + i];
          }
          cursor += numBytes;
        }
        const end = cursor + length;
        return {
          tagClass,
          tagNumber,
          constructed,
          len: length,
          value: buffer.slice(cursor, end),
          totalLength: end - offset
        };
      };
      type Tlv = {
        tagClass: number;
        tagNumber: number;
        constructed: boolean;
        len: number;
        value: Buffer;
        totalLength: number;
      };
      const parseDerChildren = (buffer: Buffer): Tlv[] => {
        const result: Array<{
          tagClass: number;
          tagNumber: number;
          constructed: boolean;
          len: number;
          value: Buffer;
          totalLength: number;
        }> = [];
        let offset = 0;
        while (offset < buffer.length) {
          const tlv = readDerTlv(buffer, offset);
          result.push({
            tagClass: tlv.tagClass,
            tagNumber: tlv.tagNumber,
            constructed: tlv.constructed,
            len: tlv.len,
            value: tlv.value,
            totalLength: tlv.totalLength
          });
          offset += tlv.totalLength;
        }
        return result;
      };
      const top = parseDerChildren(raw);
      console.log("Attestation top children:", top);
      const topTlv = readDerTlv(raw, 0);
      if (topTlv.tagClass === 0 && topTlv.tagNumber === 16) {
        const inner = parseDerChildren(topTlv.value);
        console.log("Attestation sequence children:", inner);
        const offsetOfChild = (index: number) => {
          let offset = 0;
          for (let i = 0; i <= index; i += 1) {
            const tlv = readDerTlv(topTlv.value, offset);
            if (i === index) {
              return tlv;
            }
            offset += tlv.totalLength;
          }
          return null;
        };
        const sw = offsetOfChild(6);
        const tee = offsetOfChild(7);
        if (sw) {
          const swChildren = parseDerChildren(sw.value);
          console.log("Software enforced tags:", swChildren.map((t) => t.tagNumber));
          const tag709 = swChildren.find((t) => t.tagNumber === 709);
          if (tag709) {
            console.log("Tag 709 raw len:", tag709.len);
            console.log("Tag 709 raw hex:", tag709.value.toString("hex").slice(0, 200));
          }
        }
        if (tee) {
          const teeChildren = parseDerChildren(tee.value);
          console.log("TEE enforced tags:", teeChildren.map((t) => t.tagNumber));
          const tag704 = teeChildren.find((t) => t.tagNumber === 704);
          const tag706 = teeChildren.find((t) => t.tagNumber === 706);
          if (tag704) {
            console.log("Tag 704 raw len:", tag704.len);
            console.log("Tag 704 raw hex:", tag704.value.toString("hex").slice(0, 200));
          }
          if (tag706) {
            console.log("Tag 706 raw len:", tag706.len);
            console.log("Tag 706 raw hex:", tag706.value.toString("hex").slice(0, 200));
          }
          console.log("TEE enforced raw hex:", tee.value.toString("hex").slice(0, 500));
        }
      }
      break;
    }
  } catch (error) {
    console.error("Extension debug failed:", (error as Error).message);
  }
  try {
    const parsed = parseKeyAttestation(der);
    console.log("Attestation challenge:", parsed.attestationChallengeHex);
    console.log("App package:", parsed.app.packageName);
    console.log("Signer digests:", parsed.app.signerDigests);
    console.log("Attestation security:", parsed.attestationSecurityLevel);
    console.log("Keymaster security:", parsed.keymasterSecurityLevel);
    console.log("Key origin:", parsed.deviceIntegrity.origin);
    console.log("OS version (raw):", parsed.deviceIntegrity.osVersionRaw);
    console.log("OS patch level (raw):", parsed.deviceIntegrity.osPatchLevelRaw);
    console.log("Vendor patch level (raw):", parsed.deviceIntegrity.vendorPatchLevelRaw);
    console.log("Boot patch level (raw):", parsed.deviceIntegrity.bootPatchLevelRaw);
    console.log("TEE patch level (raw):", parsed.deviceIntegrity.teePatchLevel);
    console.log("Device integrity:", parsed.deviceIntegrity);
  } catch (error) {
    console.error("Parse failed:", (error as Error).message);
  }
}

main();
