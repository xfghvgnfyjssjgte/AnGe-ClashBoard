FROM --platform=linux/amd64 docker.io/guergeiro/pnpm:lts-latest AS builder

WORKDIR /build

COPY . .

RUN pnpm install
RUN pnpm build

FROM docker.io/node:22-alpine

WORKDIR /app

RUN apk add --no-cache curl gzip

COPY package.json pnpm-lock.yaml ./
RUN corepack enable && corepack pnpm install --prod --frozen-lockfile --ignore-scripts

RUN mkdir -p .tools/mihomo-bin \
  && ARCH="$(uname -m)" \
  && case "$ARCH" in \
    x86_64) MIHOMO_ASSET="mihomo-linux-amd64-v1.gz" ;; \
    aarch64) MIHOMO_ASSET="mihomo-linux-arm64.gz" ;; \
    *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
  esac \
  && curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/latest/download/${MIHOMO_ASSET}" \
    | gzip -d > .tools/mihomo-bin/mihomo \
  && chmod +x .tools/mihomo-bin/mihomo

COPY --from=builder /build/dist ./dist
COPY config ./config
COPY server ./server

ENV PORT=2048

EXPOSE 2048

CMD ["node", "server/index.mjs"]
