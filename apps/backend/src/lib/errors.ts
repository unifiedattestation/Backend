export type ErrorCode =
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "PROJECT_NOT_FOUND"
  | "PROJECT_MISMATCH"
  | "INVALID_CHALLENGE"
  | "CHALLENGE_EXPIRED"
  | "REPLAY_DETECTED"
  | "INVALID_ARTIFACT"
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
