#!/bin/sh
# 启动 Privoice + 容器内 Cloudflare Tunnel
# 环境变量：
#   TUNNEL_TOKEN  - Cloudflare Named Tunnel token（可选，无则用 Quick Tunnel）

set -e

echo "[start] launching Privoice on port ${PORT:-8890}..."
node server.js &
NODE_PID=$!
sleep 3

if [ -n "$TUNNEL_TOKEN" ]; then
  echo "[start] mode=NAMED TUNNEL (permanent domain)"
  cloudflared tunnel --no-autoupdate run --token "$TUNNEL_TOKEN" &
  CF_PID=$!
else
  echo "[start] mode=QUICK TUNNEL (temporary, changes on restart)"
  cloudflared tunnel --no-autoupdate --url http://localhost:${PORT:-8890} &
  CF_PID=$!
fi

echo "[start] node pid=$NODE_PID cloudflared pid=$CF_PID"

# 任一进程退出则整体退出，让平台重启
wait -n $NODE_PID $CF_PID 2>/dev/null || wait $NODE_PID $CF_PID
