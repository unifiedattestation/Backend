import crypto from "crypto";
import { Config, getActiveSigningKey } from "../lib/config";
import { signChallengeToken, verifyChallengeToken } from "../lib/crypto";

export type ChallengeClaims = {
  iss: string;
  aud: string;
  pid: string;
  did: string;
  iat: number;
  exp: number;
  jti: string;
  nonce: string;
};

export class ChallengeService {
  constructor(private config: Config) {}

  issueChallenge(developerClientId: string, projectId: string) {
    const now = Math.floor(Date.now() / 1000);
    const ttl = this.config.challenge.ttlSeconds;
    const jti = crypto.randomUUID();
    const nonce = crypto.randomBytes(32).toString("hex");
    const payload: ChallengeClaims = {
      iss: this.config.backendId,
      aud: `${developerClientId}:${projectId}`,
      pid: projectId,
      did: developerClientId,
      iat: now,
      exp: now + ttl,
      jti,
      nonce
    };
    const key = getActiveSigningKey(this.config);
    const token = signChallengeToken(payload, key, this.config);
    return { token, exp: payload.exp };
  }

  verifyChallengeToken(token: string) {
    const keys = this.config.signingKeys.keys.map((key) => ({
      kid: key.kid,
      alg: key.alg,
      publicKey: key.publicKey
    }));
    const { payload } = verifyChallengeToken(token, keys);
    return payload as ChallengeClaims;
  }
}
