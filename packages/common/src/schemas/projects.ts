import { z } from "zod";

export const AppSchema = z.object({
  id: z.string(),
  projectId: z.string(),
  name: z.string(),
  signerDigestSha256: z.string(),
  createdAt: z.string()
});

export const CreateAppRequestSchema = z.object({
  name: z.string().min(1),
  projectId: z.string().min(1).optional(),
  packageName: z.string().min(1).optional(),
  signerDigestSha256: z.string().min(1)
}).refine((data) => data.projectId || data.packageName, {
  message: "projectId is required",
  path: ["projectId"]
});

export const CreateAppSecretResponseSchema = z.object({
  apiSecret: z.string(),
  prefix: z.string(),
  id: z.string()
});

export type App = z.infer<typeof AppSchema>;
export type CreateAppRequest = z.infer<typeof CreateAppRequestSchema>;
export type CreateAppSecretResponse = z.infer<typeof CreateAppSecretResponseSchema>;
