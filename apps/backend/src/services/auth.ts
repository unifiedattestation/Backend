import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { getPrisma } from "../lib/prisma";

const JWT_SECRET = process.env.UA_JWT_SECRET || "dev-secret-change-me";

export type AuthTokens = { accessToken: string; refreshToken: string };

export async function registerUser(email: string, password: string, role: "developer" | "oem" | "admin") {
  const prisma = getPrisma();
  const passwordHash = await argon2.hash(password);
  const user = await prisma.user.create({
    data: {
      email,
      passwordHash,
      role
    }
  });

  if (role === "developer") {
    const org = await prisma.developerOrg.create({
      data: {
        name: `${email.split("@")[0]} Org`,
        ownerUserId: user.id,
        memberships: {
          create: [{ userId: user.id, role: "owner" }]
        }
      }
    });
    await prisma.user.update({ where: { id: user.id }, data: { developerOrgId: org.id } });
  }

  if (role === "oem") {
    const org = await prisma.oemOrg.create({
      data: {
        name: `${email.split("@")[0]} OEM`,
        ownerUserId: user.id
      }
    });
    await prisma.user.update({ where: { id: user.id }, data: { oemOrgId: org.id } });
  }

  return user;
}

export async function verifyUser(email: string, password: string) {
  const prisma = getPrisma();
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return null;
  }
  const ok = await argon2.verify(user.passwordHash, password);
  if (!ok) {
    return null;
  }
  return user;
}

export function issueTokens(
  userId: string,
  role: string,
  accessTtlMinutes: number,
  refreshTtlDays: number
): AuthTokens {
  const accessToken = jwt.sign({ sub: userId, role, type: "access" }, JWT_SECRET, {
    expiresIn: `${accessTtlMinutes}m`
  });
  const refreshToken = jwt.sign({ sub: userId, role, type: "refresh" }, JWT_SECRET, {
    expiresIn: `${refreshTtlDays}d`
  });
  return { accessToken, refreshToken };
}

export function verifyRefreshToken(token: string) {
  const payload = jwt.verify(token, JWT_SECRET) as jwt.JwtPayload;
  if (payload.type !== "refresh") {
    throw new Error("Invalid refresh token");
  }
  return payload;
}

export function verifyAccessToken(token: string) {
  const payload = jwt.verify(token, JWT_SECRET) as jwt.JwtPayload;
  if (payload.type !== "access") {
    throw new Error("Invalid access token");
  }
  return payload;
}
