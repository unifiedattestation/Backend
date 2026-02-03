FROM node:24-trixie AS base
WORKDIR /app
COPY package.json package-lock.json* ./
COPY packages/common/package.json packages/common/package.json
COPY apps/backend/package.json apps/backend/package.json
RUN npm ci
COPY packages/common packages/common
COPY apps/backend apps/backend
COPY prisma prisma
COPY config.yaml config.yaml
ENV NODE_OPTIONS=--max-old-space-size=8192
RUN npm run -w @ua/common build && npm run -w @ua/backend build
RUN mkdir -p apps/backend/static && \
  mkdir -p apps/backend/dist/static && \
  cp -R node_modules/@fastify/swagger-ui/static/. apps/backend/static/ && \
  cp -R node_modules/@fastify/swagger-ui/static/. apps/backend/dist/static/

FROM node:24-trixie
WORKDIR /app
COPY --from=base /app/node_modules /app/node_modules
COPY --from=base /app/apps/backend/dist /app/apps/backend/dist
COPY --from=base /app/apps/backend/static /app/apps/backend/static
COPY --from=base /app/prisma /app/prisma
COPY --from=base /app/config.yaml /app/config.yaml
ENV NODE_ENV=production
CMD ["sh", "-c", "until npx prisma db push; do echo 'Waiting for database...'; sleep 2; done; node apps/backend/dist/server.js"]
