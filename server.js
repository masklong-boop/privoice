/*
 * Server v2 - 隐私优先的语音/视频/文件聊天室
 *
 * 设计原则：
 *  - 零知识：不接收、不存储密码；不接收、不存储明文
 *  - 零日志：不写任何日志文件；不记录 IP、房间、消息
 *  - 零持久化：纯内存；房间空即销毁；进程重启全消失
 *  - 仅做「信令转发」，媒体与文件全部 P2P
 */

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8890;
const PUBLIC = path.join(__dirname, 'public');

const LIMITS = {
  MAX_ROOMS: 1000,          // 最大同时房间数
  MAX_PEERS_PER_ROOM: 50,   // 单房间最大人数
  MAX_HISTORY: 200,         // 每房间内存缓存消息数（房间销毁即清）
  MAX_NAME: 24,
  MAX_MSG: 4000,
  RATE_MSGS_PER_10S: 60,    // 每人每10秒消息上限
  MAX_PAYLOAD: 1024 * 512   // 单帧 512KB（文件走 P2P，不经服务器）
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json'
};

/* ---------------- 静态服务（无访问日志） ---------------- */


// 允许的 Host（防 Back4app 默认域名旁路；可用环境变量 ALLOWED_HOSTS 覆盖，逗号分隔，留空则不校验）
// 同时放行 localhost/127.0.0.1（容器内 cloudflared 转发时 Host 可能是这些）
const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || 'privoice.dpdns.org,pv2.privoice.dpdns.org,localhost,127.0.0.1')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

const server = http.createServer((req, res) => {
  // 隐私加固 0：Host 头校验（阻断 *.b4a.run 等旁路域名）
  if (ALLOWED_HOSTS.length) {
    const host = String(req.headers.host || '').toLowerCase().split(':')[0];
    if (!ALLOWED_HOSTS.includes(host)) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end('Not Found');
      return;
    }
  }

  // 隐私加固：仅允许 GET/HEAD/OPTIONS，其他方法直接 405（减少攻击面）
  const method = (req.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    if (method !== 'POST') {  // POST 仅用于 /rtcreport（已限制本机）
      res.writeHead(405, { 'Content-Type': 'text/plain', 'Allow': 'GET, HEAD, OPTIONS' });
      res.end('Method Not Allowed');
      return;
    }
  }
  let urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
  if (urlPath === '/') urlPath = '/index.html';

  // [已移除] /integrity.json 端点（曾含内网 IP 判断逻辑）

  // [已移除] /addr 与 /rtcreport 端点（曾硬编码内网 IP 与本地路径，属隐私泄露）

  const filePath = path.normalize(path.join(PUBLIC, urlPath));
  if (!filePath.startsWith(PUBLIC)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not Found'); return; }
    const headers = {
      'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      // 允许 WebRTC / 麦克风 / 摄像头（同源）
      'Permissions-Policy': 'microphone=(self), camera=(self), display-capture=(self), geolocation=(), interest-cohort=()',
      // ---- 隐私加固：防泄露 / 防嗅探 ----
      // 禁止被嵌入 iframe（防点击劫持 + 防第三方读取）
      'X-Frame-Options': 'DENY',
      // 禁止跨域资源共享（默认不开放任何跨域）
      'Cross-Origin-Resource-Policy': 'same-origin',
      // 断开跨源窗口引用
      'Cross-Origin-Opener-Policy': 'same-origin',
      // 禁止搜索引擎收录（双保险，CF 也有 X-Robots-Tag）
      'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet, noimageindex',
      // 不暴露技术栈
      'X-Powered-By': '',
      // 严格传输安全（HTTPS 时生效）
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      // CSP：仅允许同源脚本/样式，禁止内联（防 XSS 注入读取）
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' blob: data:",
        "media-src 'self' blob:",
        "connect-src 'self' wss: ws: stun: turn:",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'"
      ].join('; ')
    };
    res.writeHead(200, headers);
    res.end(data);
  });
});

const wss = new WebSocketServer({ server, maxPayload: LIMITS.MAX_PAYLOAD, perMessageDeflate: false });

/* ---------------- 房间状态（纯内存） ---------------- */

// rooms: Map<roomId, { peers: Map<peerId, ws>, history: [], createdAt, owner: peerId }>
const rooms = new Map();
let roomSeq = 0;

function getRoom(roomId) {
  return rooms.get(roomId);
}

function createRoom(roomId, ownerId) {
  const r = { peers: new Map(), history: [], createdAt: Date.now(), owner: ownerId, seq: ++roomSeq };
  rooms.set(roomId, r);
  return r;
}

function destroyRoom(roomId) {
  const r = rooms.get(roomId);
  if (!r) return;
  r.history.length = 0; // 显式清空缓存
  r.peers.clear();
  rooms.delete(roomId);
}

function safeSend(ws, obj) {
  if (ws && ws.readyState === 1) {
    try { ws.send(JSON.stringify(obj)); } catch (e) {}
  }
}

function broadcast(room, obj, exceptPeerId) {
  for (const [pid, pws] of room.peers) {
    if (pid === exceptPeerId) continue;
    safeSend(pws, obj);
  }
}

function leaveRoom(ws) {
  const { roomId, peerId } = ws;
  if (!roomId || !peerId) return;
  const r = getRoom(roomId);
  if (r) {
    r.peers.delete(peerId);
    broadcast(r, { type: 'peer-left', peerId });
    // 房主离开 -> 转移房主（若还有人）
    if (r.owner === peerId) {
      const next = r.peers.keys().next();
      if (!next.done) {
        r.owner = next.value;
        broadcast(r, { type: 'owner-changed', peerId: r.owner });
      }
    }
    if (r.peers.size === 0) destroyRoom(roomId);
  }
  ws.roomId = null; ws.peerId = null;
}

/* ---------------- 消息处理 ---------------- */

wss.on('connection', (ws) => {
  ws.roomId = null;
  ws.peerId = null;
  ws.isAlive = true;
  ws.msgWindow = { start: Date.now(), count: 0 };

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }
    if (!msg || typeof msg.type !== 'string') return;

    // ---- 限流（内存计数，不落盘） ----
    if (msg.type === 'msg' || msg.type === 'signal' || msg.type === 'file-signal') {
      const now = Date.now();
      if (now - ws.msgWindow.start > 10000) { ws.msgWindow.start = now; ws.msgWindow.count = 0; }
      if (++ws.msgWindow.count > LIMITS.RATE_MSGS_PER_10S) {
        safeSend(ws, { type: 'rate-limited' });
        return;
      }
    }

    switch (msg.type) {
      /* ---------- 加入房间 ---------- */
      case 'join': {
        if (typeof msg.roomId !== 'string' || typeof msg.peerId !== 'string') return;
        if (msg.roomId.length < 32 || msg.roomId.length > 128) return;

        let r = getRoom(msg.roomId);
        if (!r) {
          if (rooms.size >= LIMITS.MAX_ROOMS) { safeSend(ws, { type: 'error', code: 'server-full' }); return; }
          r = createRoom(msg.roomId, msg.peerId);
        }
        if (r.peers.size >= LIMITS.MAX_PEERS_PER_ROOM) {
          safeSend(ws, { type: 'error', code: 'room-full', max: LIMITS.MAX_PEERS_PER_ROOM });
          return;
        }

        ws.roomId = msg.roomId;
        ws.peerId = msg.peerId;
        const existing = [...r.peers.keys()];
        r.peers.set(msg.peerId, ws);

        // 返回：已有成员 + 加密历史（服务器只转发密文，解不开）
        safeSend(ws, {
          type: 'joined',
          peers: existing,
          history: r.history.slice(-LIMITS.MAX_HISTORY),
          owner: r.owner,
          isOwner: r.owner === msg.peerId
        });
        broadcast(r, { type: 'peer-joined', peerId: msg.peerId }, msg.peerId);
        break;
      }

      /* ---------- WebRTC 信令（点对点） ---------- */
      case 'signal': {
        if (!ws.roomId) return;
        const r = getRoom(ws.roomId);
        if (!r) return;
        const target = r.peers.get(msg.to);
        if (target) safeSend(target, { type: 'signal', from: ws.peerId, payload: msg.payload });
        break;
      }

      /* ---------- 加密聊天（服务器只见密文） ---------- */
      case 'msg': {
        if (!ws.roomId) return;
        const r = getRoom(ws.roomId);
        if (!r) return;
        const item = { from: ws.peerId, blob: msg.blob, ts: Date.now() };
        r.history.push(item);
        if (r.history.length > LIMITS.MAX_HISTORY) r.history.shift();
        broadcast(r, { type: 'msg', from: ws.peerId, blob: msg.blob, ts: item.ts }, ws.peerId);
        break;
      }

      /* ---------- 文件传输信令（文件本体走 P2P DataChannel） ---------- */
      case 'file-signal': {
        if (!ws.roomId) return;
        const r = getRoom(ws.roomId);
        if (!r) return;
        const target = r.peers.get(msg.to);
        if (target) safeSend(target, { type: 'file-signal', from: ws.peerId, payload: msg.payload });
        break;
      }

      /* ---------- 昵称 ---------- */
      case 'name': {
        if (!ws.roomId) return;
        const r = getRoom(ws.roomId);
        if (!r) return;
        const nm = String(msg.name || '').slice(0, LIMITS.MAX_NAME);
        ws.displayName = nm;
        broadcast(r, { type: 'peer-name', peerId: ws.peerId, name: nm }, ws.peerId);
        break;
      }

      /* ---------- 状态（麦克风/摄像头/正在输入） ---------- */
      case 'state': {
        if (!ws.roomId) return;
        const r = getRoom(ws.roomId);
        if (!r) return;
        broadcast(r, { type: 'peer-state', peerId: ws.peerId, state: msg.state }, ws.peerId);
        break;
      }

      /* ---------- 心跳 ---------- */
      case 'ping': {
        safeSend(ws, { type: 'pong', t: msg.t });
        break;
      }

      case 'bye': leaveRoom(ws); break;
      default: break;
    }
  });

  ws.on('close', () => leaveRoom(ws));
  ws.on('error', () => {});
});

/* ---------------- 心跳（清理死连接） ---------------- */
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { try { ws.terminate(); } catch (e) {} continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch (e) {}
  }
}, 30000);

/* ---------------- 优雅退出 ---------------- */
function shutdown() {
  for (const id of [...rooms.keys()]) destroyRoom(id);
  try { wss.close(); } catch (e) {}
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1500);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

server.listen(PORT, '0.0.0.0', () => {
  process.stdout.write('Privoice v2 on http://0.0.0.0:' + PORT + '\n');
});
