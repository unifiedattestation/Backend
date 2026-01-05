import fs from "fs";
import path from "path";
import yaml from "js-yaml";

export type SigningKey = {
  kid: string;
  alg: "EdDSA" | "ES256";
  privateKey?: string;
  publicKey: string;
};

export type Config = {
  backendId: string;
  region: string;
  challenge: {
    ttlSeconds: number;
  };
  signingKeys: {
    activeKid: string;
    keys: SigningKey[];
  };
  federation: {
    backends: Array<{
      backendId: string;
      name: string;
      region: string;
      trustLevel: number;
      status: "active" | "dev";
      publicKeys: Array<{ kid: string; alg: string; publicKey: string }>;
    }>;
  };
  security: {
    apiKeyHeader: string;
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
    backendId: process.env.UA_BACKEND_ID || loaded.backendId,
    region: process.env.UA_REGION || loaded.region,
    challenge: {
      ttlSeconds: Number(process.env.UA_CHALLENGE_TTL || loaded.challenge.ttlSeconds)
    },
    signingKeys: {
      ...loaded.signingKeys,
      activeKid: process.env.UA_ACTIVE_KID || loaded.signingKeys.activeKid
    },
    security: {
      apiKeyHeader: process.env.UA_API_KEY_HEADER || loaded.security.apiKeyHeader,
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
  const key = config.signingKeys.keys.find((k) => k.kid === config.signingKeys.activeKid);
  if (!key || !key.privateKey) {
    throw new Error("Active signing key missing or lacks privateKey");
  }
  return key;
}
