import fs from "fs";
import path from "path";
import crypto from "crypto";
import yaml from "js-yaml";

export type SigningKey = {
  kid: string;
  alg: "EdDSA" | "ES256";
  privateKey?: string;
  publicKey: string;
};

export type Config = {
  configPath: string;
  jwtSecret?: string;
  backendId?: string;
  signingKey?: SigningKey;
  security: {
    apiSecretHeader?: string;
    jwt: {
      accessTtlMinutes: number;
      refreshTtlDays: number;
    };
  };
};

const DEFAULT_CONFIG_PATHS = [
  path.resolve(process.cwd(), "config.yaml"),
  path.resolve(process.cwd(), "apps", "backend", "config.yaml")
];

function generateUuidV7(): string {
  const bytes = crypto.randomBytes(16);
  const now = Date.now();
  bytes[0] = (now >> 40) & 0xff;
  bytes[1] = (now >> 32) & 0xff;
  bytes[2] = (now >> 24) & 0xff;
  bytes[3] = (now >> 16) & 0xff;
  bytes[4] = (now >> 8) & 0xff;
  bytes[5] = now & 0xff;
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
    16,
    20
  )}-${hex.slice(20)}`;
}

function persistConfig(pathname: string, config: Config) {
  const { configPath: _ignore, ...persisted } = config;
  const yamlText = yaml.dump(persisted, { lineWidth: 120 });
  fs.writeFileSync(pathname, yamlText, "utf8");
}

export function loadConfig(): Config {
  const explicitPath = process.env.UA_CONFIG_PATH;
  const configPath =
    explicitPath ||
    DEFAULT_CONFIG_PATHS.find((candidate) => fs.existsSync(candidate));
  if (!configPath) {
    throw new Error("config.yaml not found. Set UA_CONFIG_PATH.");
  }
  const file = fs.readFileSync(configPath, "utf8");
  const loaded = yaml.load(file) as Config;
  const config: Config = {
    ...loaded,
    jwtSecret: process.env.UA_JWT_SECRET || loaded.jwtSecret,
    configPath,
    security: {
      apiSecretHeader: "x-ua-api-secret",
      jwt: {
        accessTtlMinutes: Number(
          process.env.UA_JWT_ACCESS_TTL || loaded.security.jwt.accessTtlMinutes
        ),
        refreshTtlDays: Number(
          process.env.UA_JWT_REFRESH_TTL || loaded.security.jwt.refreshTtlDays
        )
      }
    }
  };

  return config;
}

export function getActiveSigningKey(config: Config): SigningKey {
  const key = config.signingKey;
  if (!key || !key.privateKey) {
    throw new Error("Active signing key missing or lacks privateKey");
  }
  return key;
}
