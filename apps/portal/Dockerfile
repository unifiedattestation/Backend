FROM node:24-alpine AS base
WORKDIR /app
COPY package.json package-lock.json* ./
COPY apps/portal/package.json apps/portal/package.json
RUN npm ci
COPY apps/portal apps/portal
ENV NODE_OPTIONS=--max-old-space-size=8192
RUN npm run -w @ua/portal build

FROM node:24-alpine
WORKDIR /app
COPY --from=base /app/node_modules /app/node_modules
COPY --from=base /app/apps/portal/.next /app/apps/portal/.next
COPY --from=base /app/apps/portal/public /app/apps/portal/public
COPY --from=base /app/apps/portal/package.json /app/apps/portal/package.json
WORKDIR /app/apps/portal
ENV NODE_ENV=production
CMD ["npm", "run", "start"]
