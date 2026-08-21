import { z } from "zod";

export const DeviceListQuerySchema = z.object({
  search: z.string().trim().max(200).optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20)
});

export const PublicDeviceFamilySchema = z.object({
  slug: z.string(),
  manufacturer: z.string().nullable(),
  brand: z.string().nullable(),
  model: z.string().nullable(),
  codename: z.string().nullable(),
  name: z.string(),
  enabled: z.boolean(),
  createdAt: z.string(),
  oemOrgName: z.string()
});

export const DeviceListResponseSchema = z.object({
  items: z.array(PublicDeviceFamilySchema),
  page: z.number(),
  pageSize: z.number(),
  total: z.number(),
  totalPages: z.number()
});

export const PublicBuildPolicySchema = z.object({
  buildFingerprint: z.string(),
  verifiedBootKeyHex: z.string(),
  verifiedBootHashHex: z.string().nullable(),
  osVersionRaw: z.number().nullable(),
  minOsPatchLevelRaw: z.number().nullable(),
  createdAt: z.string()
});

export const PublicDeviceCertificateSchema = z.object({
  rsaLeafSerialHex: z.string(),
  rsaIntermediateSerialHex: z.string().nullable(),
  ecdsaLeafSerialHex: z.string(),
  ecdsaIntermediateSerialHex: z.string().nullable(),
  authority: z.object({
    name: z.string(),
    rootCertificatesUrl: z.string()
  })
});

export const DeviceDetailResponseSchema = PublicDeviceFamilySchema.extend({
  certificate: PublicDeviceCertificateSchema.nullable(),
  builds: z.array(PublicBuildPolicySchema)
});

export type DeviceListQuery = z.infer<typeof DeviceListQuerySchema>;
export type PublicDeviceFamily = z.infer<typeof PublicDeviceFamilySchema>;
export type DeviceListResponse = z.infer<typeof DeviceListResponseSchema>;
export type PublicBuildPolicy = z.infer<typeof PublicBuildPolicySchema>;
export type PublicDeviceCertificate = z.infer<typeof PublicDeviceCertificateSchema>;
export type DeviceDetailResponse = z.infer<typeof DeviceDetailResponseSchema>;
