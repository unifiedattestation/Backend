FROM node:20-alpine AS base
WORKDIR /app
COPY package.json package-lock.json* ./
COPY packages/common/package.json packages/common/package.json
COPY apps/backend/package.json apps/backend/package.json
RUN npm install
COPY packages/common packages/common
COPY apps/backend apps/backend
COPY prisma prisma
COPY config.yaml config.yaml
RUN npm run -w @ua/common build && npm run -w @ua/backend build

FROM node:20-alpine
WORKDIR /app
COPY --from=base /app/node_modules /app/node_modules
COPY --from=base /app/apps/backend/dist /app/apps/backend/dist
COPY --from=base /app/prisma /app/prisma
COPY --from=base /app/config.yaml /app/config.yaml
ENV NODE_ENV=production
CMD ["node", "apps/backend/dist/server.js"]
