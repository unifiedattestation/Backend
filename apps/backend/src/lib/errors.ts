export type ErrorCode =
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "PROJECT_NOT_FOUND"
  | "PROJECT_MISMATCH"
  | "APP_NOT_FOUND"
  | "INVALID_CHAIN"
  | "UNTRUSTED_ROOT"
  | "REVOKED_CERT"
  | "NO_TRUST_ANCHORS"
  | "CHALLENGE_MISMATCH"
  | "PACKAGE_MISMATCH"
  | "SIGNER_MISMATCH"
  | "INVALID_ATTESTATION"
  | "APP_ID_MISMATCH"
  | "POLICY_FAIL"
  | "TOKEN_EXPIRED"
  | "REQUEST_HASH_MISMATCH"
  | "INVALID_TOKEN"
  | "INVALID_REQUEST"
  | "NOT_FOUND"
  | "INTERNAL_ERROR";

export function errorResponse(code: ErrorCode, message: string, details?: Record<string, unknown>) {
  return { code, message, details };
}

export class HttpError extends Error {
  public status: number;
  public payload: ReturnType<typeof errorResponse>;

  constructor(status: number, code: ErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.payload = errorResponse(code, message, details);
  }
}
