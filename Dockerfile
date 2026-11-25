# Zero npm dependencies: no install step, no build step, tiny attack surface.
# For reproducibility, pin the base image by digest in your fork:
#   FROM node:22-alpine@sha256:<digest>
FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package.json ./
COPY server ./server
COPY public ./public

# Data directory for the SQLite file (mounted as a volume in compose).
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME /data

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "--disable-warning=ExperimentalWarning", "server/index.js"]
