FROM node:20-alpine AS base
WORKDIR /app
COPY package.json package-lock.json* ./
COPY apps/portal/package.json apps/portal/package.json
RUN npm install
COPY apps/portal apps/portal
RUN npm run -w @ua/portal build

FROM node:20-alpine
WORKDIR /app
COPY --from=base /app/node_modules /app/node_modules
COPY --from=base /app/apps/portal/.next /app/apps/portal/.next
COPY --from=base /app/apps/portal/public /app/apps/portal/public
COPY --from=base /app/apps/portal/package.json /app/apps/portal/package.json
ENV NODE_ENV=production
CMD ["npm", "run", "-w", "@ua/portal", "start"]
