import { z } from "zod";

export const ChallengeRequestSchema = z.object({
  projectId: z.string(),
  developerClientId: z.string()
});

export const ChallengeResponseSchema = z.object({
  challengeToken: z.string(),
  expiresAt: z.string()
});

export const ArtifactSchema = z.object({
  type: z.enum(["mock", "keymint", "jwt"]),
  payload: z.string()
});

export const VerifyRequestSchema = z.object({
  projectId: z.string(),
  developerClientId: z.string(),
  challengeToken: z.string(),
  artifact: ArtifactSchema
});

export const VerifyResponseSchema = z.object({
  outcome: z.boolean(),
  verdict: z.object({
    checkedAt: z.string(),
    issuerBackendId: z.string(),
    projectId: z.string(),
    developerClientId: z.string(),
    verifiedChallenge: z.boolean(),
    replayDetected: z.boolean(),
    signals: z.record(z.any())
  })
});

export type ChallengeRequest = z.infer<typeof ChallengeRequestSchema>;
export type ChallengeResponse = z.infer<typeof ChallengeResponseSchema>;
export type VerifyRequest = z.infer<typeof VerifyRequestSchema>;
export type VerifyResponse = z.infer<typeof VerifyResponseSchema>;
