// A signing-certificate SHA-256 digest as UA reads it from attestationApplicationId:
// normally 32 raw bytes (64 hex chars). Some OEM KeyMint implementations (Huawei
// EMUI) store the digest as ASCII hex text instead, which UA reads as 64 bytes
// (128 hex chars) -- accepted so such apps can be registered too.
export function isValidSignerDigest(value: string): boolean {
  return /^(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{128})$/.test(value.trim());
}
