FROM node:20-alpine

# 安装 cloudflared（容器内隧道）
RUN apk add --no-cache curl && \
    curl -fsSL -o /usr/local/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 && \
    chmod +x /usr/local/bin/cloudflared

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server.js ./
COPY public ./public
COPY start-cf.sh ./
RUN chmod +x start-cf.sh

ENV NODE_ENV=production
ENV PORT=8890

EXPOSE 8890

CMD ["./start-cf.sh"]
