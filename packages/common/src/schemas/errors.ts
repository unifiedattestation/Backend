import { z } from "zod";

export const ErrorResponseSchema = z.object({
  code: z.string(),
  message: z.string(),
  details: z.record(z.any()).optional()
});

export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
