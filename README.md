# Unified Attestation

Unified Attestation (UA) is an open-source, federated alternative to Google Play Integrity. Each app registers with a single **home backend X**, while device/OEM trust roots can be registered with different federation backends **Y**. The app server always calls backend **X** for challenges and verification.

## Architecture (V1)
- **Backend API** (`/apps/backend`): Fastify + Prisma + PostgreSQL
- **Portal** (`/apps/portal`): Next.js + Tailwind
- **Shared types** (`/packages/common`): Zod schemas and shared types
- **Federation list**: configured in `config.yaml`

## Quickstart

### 1) Install deps
```bash
npm install
```

### 2) Configure env
```bash
cp .env.example .env
```

### 3) Start Postgres + services
```bash
docker-compose up --build
```

Backend runs on `http://localhost:3001` and portal on `http://localhost:3000`.

### 4) Prisma (local dev)
```bash
npx prisma generate
```

## Core Flows

### Register a developer
```bash
curl -X POST http://localhost:3001/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"dev@ua.local","password":"password123","role":"developer"}'
```

### Create a project
```bash
curl -X POST http://localhost:3001/v1/projects \
  -H "Authorization: Bearer <accessToken>" \
  -H "Content-Type: application/json" \
  -d '{"name":"My App","packageName":"com.example.app"}'
```

### Create an API key (displayed once)
```bash
curl -X POST http://localhost:3001/v1/projects/<projectId>/api-keys \
  -H "Authorization: Bearer <accessToken>"
```

### Issue a challenge (from app server)
```bash
curl -X POST http://localhost:3001/v1/challenge \
  -H "x-ua-api-key: <apiKey>" \
  -H "Content-Type: application/json" \
  -d '{"projectId":"<projectId>","developerClientId":"<developerClientId>"}'
```

### Verify a challenge (mock artifact)
```bash
curl -X POST http://localhost:3001/v1/verify \
  -H "x-ua-api-key: <apiKey>" \
  -H "Content-Type: application/json" \
  -d '{
    "projectId":"<projectId>",
    "developerClientId":"<developerClientId>",
    "challengeToken":"<challengeToken>",
    "artifact": { "type":"mock", "payload":"{\"deviceIntegrity\":\"basic\"}" }
  }'
```

## OpenAPI
- Docs: `http://localhost:3001/docs`
- JSON: `http://localhost:3001/openapi.json`

## Config
See `config.yaml` for backend ID, signing keys, federation list, and challenge TTL. Keys are Ed25519 (base64 DER). Override with env vars:

- `UA_BACKEND_ID`
- `UA_REGION`
- `UA_CHALLENGE_TTL`
- `UA_API_KEY_HEADER`
- `UA_ACTIVE_KID`

## Tests
```bash
npm run -w @ua/backend test
```

## Notes
- Challenges are stateless and signed (JWS). Best-effort single-use is enforced via in-memory TTL cache.
- `/v1/challenge` and `/v1/verify` require project API key auth.
- Federation list is read-only in V1 and comes from `config.yaml`.
