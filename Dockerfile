FROM node:22-alpine AS build
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
# Explicit runtime inputs: never ship history, env, keys or state.
COPY src/ ./src/
COPY public/ ./public/
# Browser SDK dependencies (esbuild, React, Privy react-auth) are build-only.
# One layer: dev tree never committed (legacy builder inode limit).
RUN npm ci --include=dev && npm run build:privy && npm prune --omit=dev && npm cache clean --force

FROM node:22-alpine
WORKDIR /app
ARG GIT_SHA=dev
ARG BUILT_AT=unknown
ARG BUILT_BY=Hermes
ENV GIT_SHA=$GIT_SHA
ENV BUILT_AT=$BUILT_AT
ENV BUILT_BY=$BUILT_BY
ENV NODE_ENV=production
# Loopback only; nginx is the public door (src/service-mode.mjs:12 default port 8798).
ENV HOST=127.0.0.1
ENV SERVICE_MODE=wallet
COPY --from=build --chown=node:node /app /app
# The retired v1 banking host must not appear in shipped content. The split spelling keeps
# this guard from matching its own image-history metadata.
RUN if grep -r -i -a -l -F "banking"".nuri.com" /app; then exit 1; else test "$?" = 1; fi
USER node
EXPOSE 8798
# Persistent PRIVATE state (SHORT_LINKS_DB and its .chain-<id> sidecars, AGENT_STORE_PATH) is bind-mounted.
CMD ["node", "src/wallet-server.mjs"]
