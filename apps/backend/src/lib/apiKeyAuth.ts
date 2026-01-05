import { FastifyRequest } from "fastify";
import { HttpError } from "./errors";

export function getApiKey(request: FastifyRequest, headerName: string) {
  const value = request.headers[headerName.toLowerCase()];
  if (!value || Array.isArray(value)) {
    return null;
  }
  return value;
}

export function requireApiKey(request: FastifyRequest, headerName: string) {
  const apiKey = getApiKey(request, headerName);
  if (!apiKey) {
    throw new HttpError(401, "UNAUTHORIZED", "Missing API key");
  }
  return apiKey;
}
