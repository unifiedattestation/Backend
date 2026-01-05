import jwt from "jsonwebtoken";
import { Config, SigningKey } from "./config";

function pemFromBase64(base64: string, label: "PRIVATE KEY" | "PUBLIC KEY"): string {
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

export function signChallengeToken(
  payload: Record<string, unknown>,
  key: SigningKey,
  config: Config
): string {
  const privateKey = pemFromBase64(key.privateKey || "", "PRIVATE KEY");
  return jwt.sign(payload, privateKey, {
    algorithm: key.alg,
    header: {
      typ: "ua.challenge+jws",
      kid: key.kid
    }
  });
}

export function verifyChallengeToken(
  token: string,
  publicKeys: Array<{ kid: string; alg: string; publicKey: string }>
): { payload: jwt.JwtPayload; header: jwt.JwtHeader } {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded === "string") {
    throw new Error("Invalid token");
  }
  const header = decoded.header as jwt.JwtHeader;
  const kid = header.kid as string | undefined;
  if (!kid) {
    throw new Error("Missing kid");
  }
  const key = publicKeys.find((k) => k.kid === kid);
  if (!key) {
    throw new Error("Unknown kid");
  }
  const publicKey = pemFromBase64(key.publicKey, "PUBLIC KEY");
  const payload = jwt.verify(token, publicKey, {
    algorithms: [key.alg as jwt.Algorithm]
  }) as jwt.JwtPayload;
  return { payload, header };
}
