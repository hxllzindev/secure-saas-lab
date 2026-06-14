FROM node:24-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:24-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

RUN addgroup -S aegis && adduser -S -G aegis aegis
COPY --from=dependencies /app/node_modules ./node_modules
COPY --chown=aegis:aegis package.json ./
COPY --chown=aegis:aegis src ./src

USER aegis
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1

CMD ["node", "src/server.js"]
