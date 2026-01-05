import { z } from "zod";

export const ProjectSchema = z.object({
  id: z.string(),
  orgId: z.string(),
  name: z.string(),
  packageName: z.string(),
  createdAt: z.string()
});

export const CreateProjectRequestSchema = z.object({
  name: z.string().min(1),
  packageName: z.string().min(1)
});

export const ApiKeySchema = z.object({
  id: z.string(),
  projectId: z.string(),
  keyPrefix: z.string(),
  createdAt: z.string(),
  revokedAt: z.string().nullable().optional()
});

export const CreateApiKeyResponseSchema = z.object({
  apiKey: z.string(),
  keyPrefix: z.string(),
  id: z.string()
});

export type Project = z.infer<typeof ProjectSchema>;
export type CreateProjectRequest = z.infer<typeof CreateProjectRequestSchema>;
export type ApiKey = z.infer<typeof ApiKeySchema>;
export type CreateApiKeyResponse = z.infer<typeof CreateApiKeyResponseSchema>;
