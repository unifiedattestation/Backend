# Unified Attestation Backend (Combined X + Y)

Unified Attestation (UA) is an open-source, federated alternative to Play Integrity. This backend acts as both **home backend X** (app-facing) and **device backend Y** (attestation verifier). Federation is handled offline via stored trust anchors and verification keys.

## Architecture
- **Backend API** (`/apps/backend`): Fastify + Prisma + PostgreSQL
- **Portal** (`/apps/portal`): Next.js + Tailwind
- **Shared types** (`/packages/common`)
- **Federation trust store**: stored in Postgres, managed by admin UI/API

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

## Core API

### Backend info (public)
```bash
curl http://localhost:3001/api/v1/info
```

### Device process (device-facing)
```bash
curl -X POST http://localhost:3001/api/v1/device/process \
  -H "Content-Type: application/json" \
  -d '{
    "projectId":"com.example.app",
    "requestHash":"<sha256 hex>",
    "attestationChain":["<base64 DER cert0>", "<base64 DER cert1>"]
  }'
```

### Decode token (app-server-facing, requires api secret)
```bash
curl -X POST http://localhost:3001/api/v1/app/decodeToken \
  -H "x-ua-api-secret: <apiSecret>" \
  -H "Content-Type: application/json" \
  -d '{
    "projectId":"com.example.app",
    "token":"<token>",
    "expectedRequestHash":"<sha256 hex>"
  }'
```

## Portal login
- Default admin: `admin / admin`
- Admin creates app dev + OEM users
- App dev registers apps and retrieves API secret
- OEM registers device families + trust anchors

## Config
See `config.yaml` for JWT and security settings. Backend ID + signing key are stored in the database.

Env overrides:

## Tests
```bash
npm run -w @ua/backend test
```

## Breaking Changes (from V1)
- `/v1/challenge` and `/v1/verify` are removed. Use `/api/v1/device/process` and `/api/v1/app/decodeToken`.
- App-facing auth uses API secrets per app (projectId == packageName).
- Federation list is now stored in DB and managed in the Admin UI/API.
