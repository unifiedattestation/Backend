import { FastifyRequest } from "fastify";
import { verifyAccessToken } from "../services/auth";
import { HttpError } from "./errors";

export function getBearerToken(request: FastifyRequest) {
  const header = request.headers.authorization;
  if (!header) return null;
  const [type, token] = header.split(" ");
  if (type !== "Bearer" || !token) return null;
  return token;
}

export function requireUser(request: FastifyRequest) {
  const token = getBearerToken(request);
  if (!token) {
    throw new HttpError(401, "UNAUTHORIZED", "Missing bearer token");
  }
  try {
    return verifyAccessToken(token);
  } catch {
    throw new HttpError(401, "UNAUTHORIZED", "Invalid token");
  }
}
