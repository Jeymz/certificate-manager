# syntax=docker/dockerfile:1

FROM node:22-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-update-notifier \
  && npm cache clean --force

FROM node:22-alpine AS runner
WORKDIR /app
RUN apk add --no-cache dumb-init \
  && addgroup -S appuser \
  && adduser -S -G appuser appuser
ENV NODE_ENV=production
COPY --from=deps --chown=appuser:appuser /app/node_modules ./node_modules
# Only bring the runtime surface into the image to avoid bundling tests/coverage/etc.
COPY --chown=appuser:appuser package*.json ./
COPY --chown=appuser:appuser server.js ./
COPY --chown=appuser:appuser src ./src
COPY --chown=appuser:appuser config ./config
RUN mkdir -p files \
  && chown -R appuser:appuser files
USER appuser
EXPOSE 8080
VOLUME ["/app/files"]
ENTRYPOINT ["/usr/bin/dumb-init","--"]
CMD ["node","server.js"]
