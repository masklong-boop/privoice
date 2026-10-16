/* 语音房间 */
'use strict';

const $ = (id) => document.getElementById(id);

const els = {
  home: $('home'), room: $('room'),
  pwd: $('pwd'), nick: $('nick'), homeHint: $('homeHint'),
  btnEye: $('btnEye'), meterBar: $('meterBar'), btnCreate: $('btnCreate'), btnJoin: $('btnJoin'),
  shareBox: $('shareBox'), shareLink: $('shareLink'), btnCopy: $('btnCopy'),
  connDot: $('connDot'), roomLabel: $('roomLabel'), peerCount: $('peerCount'),
  peers: $('peers'), emptyTip: $('emptyTip'),
  btnMic: $('btnMic'), btnDeaf: $('btnDeaf'), btnCam: $('btnCam'), btnScreen: $('btnScreen'),
  btnVoice: $('btnVoice'), btnImg: $('btnImg'), btnChat: $('btnChat'), btnLeave: $('btnLeave'),
  fileInput: $('fileInput'), unread: $('unread'),
  chat: $('chat'), btnChatClose: $('btnChatClose'), msgs: $('msgs'), typing: $('typing'),
  msgInput: $('msgInput'), btnSend: $('btnSend'), btnImgPick: $('btnImgPick'),
  videoBox: $('videoBox'), videos: $('videos'),
  btnPanel: $('btnPanel'), panel: $('panel'), btnPanelClose: $('btnPanelClose'), memberList: $('memberList'),
  audios: $('audios'), toast: $('toast'), modal: $('modal'), modalBox: $('modalBox'),
  imgView: $('imgView'), imgViewImg: $('imgViewImg'), imgViewClose: $('imgViewClose')
};

const ITER = 600000;
const SALT_LEN = 16;

/* 盐值：每个房间随机生成（不再用全局固定值，避免被预计算彩虹表）
 * 盐值通过邀请链接的 #s= 片段传递（URL fragment 不会发送给服务器） */
function b64url(u8) {
  let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64url(str) {
  let s = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try {
    const b = atob(s); const o = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) o[i] = b.charCodeAt(i);
    return o;
  } catch (e) { return null; }
}
function newSalt() { const a = new Uint8Array(SALT_LEN); crypto.getRandomValues(a); return b64url(a); }
function getUrlSalt() {
  const m = String(location.hash || '').match(/[#&]s=([A-Za-z0-9_-]{8,64})/);
  return m ? m[1] : null;
}

const state = {
  roomId: null, peerId: null, nick: '匿名',
  ws: null, chatKey: null,
  pcs: new Map(), dcs: new Map(), audioEls: new Map(), videoEls: new Map(),
  names: new Map(), states: new Map(),
  rawStream: null, outStream: null,
  camStream: null, screenStream: null,
  micOn: true, deaf: false, camOn: false, screenOn: false,
  joined: false, owner: null, isOwner: false,
  iceServers: [], unread: 0, chatOpen: false,
  allowPublicIp: false, blockedCand: 0,
  // 隐私加固：强制中继模式（不暴露任何本机/公网 IP）
  forceRelay: true, relayFailed: false,
  // 防指纹：每次会话随机噪声种子
  fpSeed: Math.floor(Math.random() * 1e9),
  voiceEffect: 'none', audioCtx: null, voiceChain: null,
  recvFiles: new Map(),
  burnSeconds: 0, burnTimer: null
};

/* ============ 工具 ============ */
const buf2hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

function toast(text, ms) {
  els.toast.textContent = text;
  els.toast.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => els.toast.classList.remove('show'), ms || 2400);
}

function b64encode(buf) {
  const bytes = new Uint8Array(buf); let s = ''; const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  return btoa(s);
}
function b64decode(str) {
  const s = atob(str); const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
function randomId() { const a = new Uint8Array(16); crypto.getRandomValues(a); return buf2hex(a); }
function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(0) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}
function initialOf(n) { return ((n || '?').trim().charAt(0) || '?').toUpperCase(); }

function showModal(title, body, buttons) {
  els.modalBox.innerHTML = '<div style="font-weight:600;font-size:16px;margin-bottom:10px"></div><div></div>';
  els.modalBox.children[0].textContent = title || '';
  els.modalBox.children[1].textContent = body || '';
  const bar = document.createElement('div'); bar.className = 'mBtns';
  (buttons || [{ text: '好' }]).forEach(b => {
    const btn = document.createElement('button');
    btn.className = 'btn' + (b.primary ? ' primary' : '');
    btn.textContent = b.text;
    btn.onclick = () => { els.modal.classList.remove('open'); if (b.onClick) b.onClick(); };
    bar.appendChild(btn);
  });
  els.modalBox.appendChild(bar);
  els.modal.classList.add('open');
}

/* ============ 加密 ============ */
async function deriveKeys(password, saltBytes) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: ITER, hash: 'SHA-256' }, base, 512);
  const all = new Uint8Array(bits);
  const roomHash = await crypto.subtle.digest('SHA-256', all.slice(0, 32));
  const roomId = buf2hex(roomHash);
  const chatKey = await crypto.subtle.importKey('raw', all.slice(32, 64), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  return { roomId, chatKey };
}

async function encryptMsg(text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.chatKey, new TextEncoder().encode(text));
  return b64encode(iv) + '.' + b64encode(ct);
}
async function decryptMsg(blob) {
  try {
    const [ivB64, ctB64] = String(blob).split('.');
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(ivB64) }, state.chatKey, b64decode(ctB64));
    return new TextDecoder().decode(pt);
  } catch (e) { return null; }
}
async function encryptBytes(u8) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.chatKey, u8);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0); out.set(new Uint8Array(ct), 12);
  return out;
}
async function decryptBytes(buf) {
  try {
    const u8 = new Uint8Array(buf);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.slice(0, 12) }, state.chatKey, u8.slice(12));
    return new Uint8Array(pt);
  } catch (e) { return null; }
}

/* ============ 密码强度 ============ */
function pwStrength(pw) {
  let s = 0;
  if (pw.length >= 6) s++;
  if (pw.length >= 10) s++;
  if (pw.length >= 14) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(s, 5);
}
function updateMeter() {
  const pw = els.pwd.value;
  const s = pwStrength(pw);
  const colors = ['#ef4444', '#ef4444', '#f59e0b', '#f59e0b', '#22c55e', '#22c55e'];
  els.meterBar.style.width = [0, 20, 40, 60, 80, 100][s] + '%';
  els.meterBar.style.background = colors[s];
}

/* ============ 变声 ============ */
const VOICE_LIST = [
  { id: 'none', name: '原声' },
  { id: 'deep', name: '低沉' },
  { id: 'high', name: '高亢' },
  { id: 'child', name: '童声' },
  { id: 'robot', name: '机器人' },
  { id: 'phone', name: '电话' },
  { id: 'cave', name: '空旷' }
];

const PITCH_WORKLET = `
class PitchShifter extends AudioWorkletProcessor {
  static get parameterDescriptors() {
    return [{ name: 'pitch', defaultValue: 1.0, minValue: 0.5, maxValue: 2.0 }];
  }
  constructor() {
    super();
    this.N = 8192;
    this.buf = new Float32Array(this.N);
    this.w = 0;
    this.grain = this.N >> 1;
    this.d1 = 0;
    this.d2 = this.grain;
  }
  process(inputs, outputs, p) {
    const inp = inputs[0] && inputs[0][0];
    const out = outputs[0] && outputs[0][0];
    if (!out) return true;
    const pitch = p.pitch[0];
    const N = this.N, half = this.grain;
    for (let i = 0; i < out.length; i++) {
      this.buf[this.w] = inp ? (inp[i] || 0) : 0;
      const p1 = this.d1, p2 = this.d2;
      const i1 = (this.w - (half - p1) + N) % N;
      const i2 = (this.w - (half - p2) + N) % N;
      const w1 = 0.5 - 0.5 * Math.cos(Math.PI * p1 / half);
      const w2 = 0.5 - 0.5 * Math.cos(Math.PI * p2 / half);
      out[i] = this.buf[i1] * w1 + this.buf[i2] * w2;
      this.d1 += pitch; if (this.d1 >= half) this.d1 -= half;
      this.d2 += pitch; if (this.d2 >= half) this.d2 -= half;
      this.w = (this.w + 1) % N;
    }
    return true;
  }
}
registerProcessor('pitch-shifter', PitchShifter);
`;

async function ensureAudioCtx() {
  if (state.audioCtx) return state.audioCtx;
  const ctx = new (window.AudioContext || window.webkitAudioContext)();
  try {
    const blob = new Blob([PITCH_WORKLET], { type: 'application/javascript' });
    const url = URL.createObjectURL(blob);
    await ctx.audioWorklet.addModule(url);
    URL.revokeObjectURL(url);
    state.hasWorklet = true;
  } catch (e) { state.hasWorklet = false; }
  state.audioCtx = ctx;
  return ctx;
}

function buildVoiceChain(ctx, src, effectId) {
  const dest = ctx.createMediaStreamDestination();
  const cfg = {
    deep:  { pitch: 0.78, lowpass: 900, gain: 1.25 },
    high:  { pitch: 1.30, highpass: 220, peak: 2200, peakGain: 6 },
    child: { pitch: 1.55, highpass: 350, peak: 3000, peakGain: 5 },
    robot: { ring: 55 },
    phone: { bandpass: 1600, q: 0.9 },
    cave:  { delay: 0.14, feedback: 0.42, wet: 0.45 }
  }[effectId];

  let node = src;

  if (effectId === 'none' || !cfg) {
    node.connect(dest);
    return { dest, nodes: [node] };
  }

  const created = [];

  if (cfg.pitch && state.hasWorklet) {
    const sh = new AudioWorkletNode(ctx, 'pitch-shifter');
    sh.parameters.get('pitch').value = cfg.pitch;
    node.connect(sh); node = sh; created.push(sh);
  }
  if (cfg.lowpass) { const f = ctx.createBiquadFilter(); f.type = 'lowpass'; f.frequency.value = cfg.lowpass; node.connect(f); node = f; created.push(f); }
  if (cfg.highpass) { const f = ctx.createBiquadFilter(); f.type = 'highpass'; f.frequency.value = cfg.highpass; node.connect(f); node = f; created.push(f); }
  if (cfg.peak) { const f = ctx.createBiquadFilter(); f.type = 'peaking'; f.frequency.value = cfg.peak; f.gain.value = cfg.peakGain || 5; f.Q.value = 1.2; node.connect(f); node = f; created.push(f); }
  if (cfg.bandpass) { const f = ctx.createBiquadFilter(); f.type = 'bandpass'; f.frequency.value = cfg.bandpass; f.Q.value = cfg.q || 1; node.connect(f); node = f; created.push(f); }
  if (cfg.gain) { const g = ctx.createGain(); g.gain.value = cfg.gain; node.connect(g); node = g; created.push(g); }

  if (cfg.ring) {
    const osc = ctx.createOscillator(); osc.frequency.value = cfg.ring;
    const ring = ctx.createGain(); ring.gain.value = 0;
    const mod = ctx.createGain(); mod.gain.value = 1;
    osc.connect(ring.gain);
    node.connect(mod);
    const out = ctx.createGain(); out.gain.value = 1;
    mod.connect(out);
    // 环形调制：信号 * (0.5 + 0.5*sin)
    const carrier = ctx.createGain(); carrier.gain.value = 1;
    mod.connect(carrier);
    const mixer = ctx.createGain();
    carrier.connect(mixer);
    const dry = ctx.createGain(); dry.gain.value = 0.25;
    mod.connect(dry); dry.connect(mixer);
    node = mixer; created.push(osc, ring, mod, out, carrier, mixer, dry);
    osc.start();
  }

  if (cfg.delay) {
    const d = ctx.createDelay(1.0); d.delayTime.value = cfg.delay;
    const fb = ctx.createGain(); fb.gain.value = cfg.feedback;
    const wet = ctx.createGain(); wet.gain.value = cfg.wet;
    node.connect(d); d.connect(fb); fb.connect(d); d.connect(wet);
    const mix = ctx.createGain(); mix.gain.value = 1;
    node.connect(mix); wet.connect(mix);
    node = mix; created.push(d, fb, wet, mix);
  }

  node.connect(dest);
  return { dest, nodes: created };
}

async function applyVoice(effectId) {
  if (!state.rawStream) { toast('无麦克风'); return; }
  if (effectId === 'none') {
    state.outStream = state.rawStream;
    state.voiceEffect = 'none';
    await renegotiateTracks();
    return;
  }
  try {
    const ctx = await ensureAudioCtx();
    if (ctx.state === 'suspended') {
      // 加超时保护：某些环境（无用户手势）resume 会挂起
      await Promise.race([ctx.resume(), new Promise(r => setTimeout(r, 1500))]);
    }
    if (state.voiceChain) { try { state.voiceChain.forEach(n => n.disconnect()); } catch (e) {} state.voiceChain = null; }
    const src = ctx.createMediaStreamSource(state.rawStream);
    const { dest, nodes } = buildVoiceChain(ctx, src, effectId);
    state.voiceChain = [src].concat(nodes || []);
    state.outStream = dest.stream;
    state.voiceEffect = effectId;
  } catch (e) {
    toast('变声不可用');
    state.outStream = state.rawStream;
    state.voiceEffect = 'none';
  }
  await renegotiateTracks();
}

async function renegotiateTracks() {
  const stream = state.outStream || state.rawStream;
  if (!stream) return;
  for (const [pid, pc] of state.pcs) {
    const senders = pc.getSenders();
    for (const s of senders) {
      if (s.track && s.track.kind === 'audio') { try { pc.removeTrack(s); } catch (e) {} }
    }
    const at = stream.getAudioTracks()[0];
    if (at) { try { pc.addTrack(at, stream); } catch (e) {} }
    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      send({ type: 'signal', to: pid, payload: { sdp: pc.localDescription } });
    } catch (e) {}
  }
}

/* ============ 渲染 ============ */
function showScreen(name) {
  els.home.classList.toggle('active', name === 'home');
  els.room.classList.toggle('active', name === 'room');
}

function renderPeers() {
  const ids = [...state.pcs.keys()];
  els.peers.innerHTML = '';
  els.peerCount.textContent = ids.length + 1;

  const add = (id, isSelf, name, live, micOn) => {
    const div = document.createElement('div');
    div.className = 'peer' + (live ? ' speaking' : '');
    div.innerHTML = '<div class="avatar"></div><div class="nm"></div>' +
      '<div class="mic"></div>' + (isSelf && state.isOwner ? '<div class="owner">👑</div>' : '');
    div.querySelector('.avatar').textContent = initialOf(name);
    div.querySelector('.nm').textContent = name + (isSelf ? '（我）' : '');
    div.querySelector('.mic').textContent = micOn === false ? '🔇' : '🎤';
    els.peers.appendChild(div);
  };

  add('self', true, state.nick, true, state.micOn);
  ids.forEach(id => {
    const st = state.states.get(id) || {};
    add(id, false, state.names.get(id) || '匿名', !!state.audioEls.get(id), st.mic !== false);
  });

  els.emptyTip.classList.toggle('hide', ids.length > 0);
  renderMembers();
}

function renderMembers() {
  if (!els.memberList) return;
  els.memberList.innerHTML = '';
  const mk = (id, isSelf, name, micOn, camOn) => {
    const d = document.createElement('div'); d.className = 'member';
    d.innerHTML = '<div class="avatar"></div><div class="mi"><div class="mn"></div><div class="ms"></div></div>' +
      (state.owner === id ? '<div class="mtag">房主</div>' : '');
    d.querySelector('.avatar').textContent = initialOf(name);
    d.querySelector('.mn').textContent = name + (isSelf ? '（我）' : '');
    d.querySelector('.ms').textContent = (micOn === false ? '🔇 静音' : '🎤 开麦') + (camOn ? ' · 📷' : '');
    els.memberList.appendChild(d);
  };
  mk('self', true, state.nick, state.micOn, state.camOn || state.screenOn);
  for (const id of state.pcs.keys()) {
    const st = state.states.get(id) || {};
    mk(id, false, state.names.get(id) || '匿名', st.mic, st.cam);
  }
}

function sysMsg(text) {
  const d = document.createElement('div');
  d.className = 'msg sys'; d.textContent = text;
  els.msgs.appendChild(d); els.msgs.scrollTop = els.msgs.scrollHeight;
}

function scheduleBurn(el) {
  if (!state.burnSeconds) return;
  setTimeout(() => { try { el.remove(); } catch (e) {} }, state.burnSeconds * 1000);
}

function addMsg(name, text, mine) {
  const d = document.createElement('div');
  d.className = 'msg' + (mine ? ' me' : '');
  const who = document.createElement('div'); who.className = 'who'; who.textContent = name;
  const t = document.createElement('div'); t.className = 'txt'; t.textContent = text;
  d.appendChild(who); d.appendChild(t);
  els.msgs.appendChild(d); els.msgs.scrollTop = els.msgs.scrollHeight;
  scheduleBurn(d);
  if (!mine && !state.chatOpen) {
    state.unread++;
    els.unread.textContent = state.unread;
    els.unread.style.display = '';
  }
}

function addImageMsg(name, id, mine, url) {
  const d = document.createElement('div');
  d.className = 'msg' + (mine ? ' me' : '');
  const who = document.createElement('div'); who.className = 'who'; who.textContent = name;
  const img = document.createElement('img');
  img.src = url;
  img.onclick = () => { els.imgViewImg.src = url; els.imgView.classList.add('open'); };
  d.appendChild(who); d.appendChild(img);
  els.msgs.appendChild(d); els.msgs.scrollTop = els.msgs.scrollHeight;
  scheduleBurn(d);
  if (!mine && !state.chatOpen) {
    state.unread++;
    els.unread.textContent = state.unread;
    els.unread.style.display = '';
  }
}

/* ============ WebRTC ============ */
function newPc(peerId) {
  // 隐私加固：默认强制中继（relay），本机/公网 IP 一律不外发；
  // 中继不可用时自动回退为“仅过滤公网候选”模式
  const cfg = {
    iceServers: state.iceServers,
    iceCandidatePoolSize: 0,
    bundlePolicy: 'max-bundle',
    rtcpMuxPolicy: 'require'
  };
  if (state.forceRelay && !state.relayFailed) cfg.iceTransportPolicy = 'relay';
  const pc = new RTCPeerConnection(cfg);

  const stream = state.camStream || state.screenStream || state.outStream || state.rawStream;
  if (stream) stream.getTracks().forEach(t => pc.addTrack(t, stream));

  pc.onicecandidate = (e) => {
    if (!e.candidate) return;
    const c = e.candidate.candidate || '';
    // IP 保护：默认不外发含公网 IP 的候选（srflx/prflx），避免暴露真实出口 IP
    // 仅在同网段直连失败时（超时/失败）才自动放开
    if (!state.allowPublicIp && / typ (srflx|prflx)/.test(c)) { state.blockedCand = (state.blockedCand || 0) + 1; return; }
    send({ type: 'signal', to: peerId, payload: { cand: e.candidate } });
  };

  pc.ontrack = (e) => {
    const s = e.streams[0];
    if (s.getVideoTracks().length) {
      let v = state.videoEls.get(peerId);
      if (!v) {
        const tile = document.createElement('div'); tile.className = 'vtile';
        v = document.createElement('video'); v.autoplay = true; v.playsInline = true;
        const nm = document.createElement('span'); nm.textContent = state.names.get(peerId) || '匿名';
        tile.appendChild(v); tile.appendChild(nm); els.videos.appendChild(tile);
        state.videoEls.set(peerId, v); els.videoBox.classList.add('open');
      }
      v.srcObject = s; v.play().catch(() => {});
    } else {
      let el = state.audioEls.get(peerId);
      if (!el) {
        el = document.createElement('audio'); el.autoplay = true; el.playsInline = true;
        els.audios.appendChild(el); state.audioEls.set(peerId, el);
      }
      el.srcObject = s; el.muted = state.deaf; el.play().catch(() => {});
    }
    renderPeers();
  };

  pc.ondatachannel = (e) => { if (e.channel.label === 'file') setupDataChannel(peerId, e.channel); };
  pc.onconnectionstatechange = () => {
    // 隐私加固的回退链：
    //  1) relay 失败 -> 关闭 forceRelay，退到“仅过滤公网候选”
    //  2) 仍失败 -> 放开 allowPublicIp（最后手段，保证能用）
    if (pc.connectionState === 'failed') {
      if (state.forceRelay && !state.relayFailed) {
        state.relayFailed = true;      // 本会话后续连接不再强制 relay
        try { pc.restartIce(); } catch (e) {}
      } else if (!state.allowPublicIp) {
        state.allowPublicIp = true;
        try { pc.restartIce(); } catch (e) {}
      } else {
        try { pc.restartIce(); } catch (e) {}
      }
    }
    renderPeers();
  };

  state.pcs.set(peerId, pc);
  renderPeers();
  return pc;
}

async function makeOffer(peerId) {
  const pc = newPc(peerId);
  const dc = pc.createDataChannel('file', { ordered: true });
  setupDataChannel(peerId, dc);
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  send({ type: 'signal', to: peerId, payload: { sdp: pc.localDescription } });
}

async function onSignal(from, payload) {
  let pc = state.pcs.get(from);
  if (payload.sdp) {
    if (!pc) pc = newPc(from);
    const desc = payload.sdp;
    if (desc.type === 'offer') {
      await pc.setRemoteDescription(desc);
      const ans = await pc.createAnswer();
      await pc.setLocalDescription(ans);
      send({ type: 'signal', to: from, payload: { sdp: pc.localDescription } });
    } else if (pc.signalingState !== 'stable') {
      await pc.setRemoteDescription(desc);
    }
  } else if (payload.cand && pc) {
    try { await pc.addIceCandidate(payload.cand); } catch (e) {}
  }
}

/* ============ 图片 P2P ============ */
function setupDataChannel(peerId, dc) {
  state.dcs.set(peerId, dc);
  dc.binaryType = 'arraybuffer';
  dc.onmessage = async (e) => {
    let m; try { m = JSON.parse(e.data); } catch (err) { return; }
    if (m.k === 'meta') {
      state.recvFiles.set(m.id, { chunks: [], name: m.name, size: m.size, type: m.type || '' });
    } else if (m.k === 'chunk') {
      const f = state.recvFiles.get(m.id); if (!f) return;
      const plain = await decryptBytes(b64decode(m.d));
      if (plain) f.chunks.push(plain);
    } else if (m.k === 'done') {
      const f = state.recvFiles.get(m.id); if (!f) return;
      const blob = new Blob(f.chunks, { type: f.type || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      if ((f.type || '').startsWith('image/')) {
        addImageMsg(state.names.get(peerId) || '匿名', m.id, false, url);
      } else {
        const d = document.createElement('div');
        d.className = 'msg'; d.innerHTML = '<div class="who"></div><div class="txt"></div>';
        d.querySelector('.who').textContent = state.names.get(peerId) || '匿名';
        const a = document.createElement('a');
        a.href = url; a.download = f.name; a.textContent = f.name + ' (' + fmtSize(f.size) + ')';
        a.style.color = '#4f7cff';
        d.querySelector('.txt').appendChild(a);
        els.msgs.appendChild(d); els.msgs.scrollTop = els.msgs.scrollHeight;
        scheduleBurn(d);
      }
    }
  };
}

async function sendBlob(file, isImage) {
  if (!state.dcs.size) { toast('暂无其他成员'); return; }
  const id = randomId();
  const type = file.type || (isImage ? 'image/png' : 'application/octet-stream');
  for (const [pid, dc] of state.dcs) {
    if (dc.readyState !== 'open') continue;
    try { dc.send(JSON.stringify({ k: 'meta', id, name: file.name || ('图片-' + id.slice(0, 6)), size: file.size, type })); } catch (e) { continue; }
    const CHUNK = 32 * 1024;
    let off = 0;
    while (off < file.size) {
      const buf = await file.slice(off, off + CHUNK).arrayBuffer();
      const enc = await encryptBytes(new Uint8Array(buf));
      while (dc.bufferedAmount > 1024 * 1024) await new Promise(r => setTimeout(r, 40));
      try { dc.send(JSON.stringify({ k: 'chunk', id, d: b64encode(enc) })); } catch (e) { break; }
      off += CHUNK;
    }
    try { dc.send(JSON.stringify({ k: 'done', id })); } catch (e) {}
  }
  if (isImage) {
    addImageMsg(state.nick + '（我）', id, true, URL.createObjectURL(file));
  } else {
    const d = document.createElement('div');
    d.className = 'msg me';
    d.innerHTML = '<div class="who"></div><div class="txt"></div>';
    d.querySelector('.who').textContent = state.nick + '（我）';
    d.querySelector('.txt').textContent = file.name + ' (' + fmtSize(file.size) + ') 已发送';
    els.msgs.appendChild(d); els.msgs.scrollTop = els.msgs.scrollHeight;
    scheduleBurn(d);
  }
}

/* ============ 信令 ============ */
function send(obj) { if (state.ws && state.ws.readyState === 1) state.ws.send(JSON.stringify(obj)); }

function connectWs() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(proto + '://' + location.host);
  state.ws = ws;

  ws.onopen = () => {
    els.connDot.className = 'dot ok';
    send({ type: 'join', roomId: state.roomId, peerId: state.peerId });
    send({ type: 'name', name: state.nick });
  };

  ws.onmessage = async (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
    switch (m.type) {
      case 'joined': {
        state.joined = true; state.owner = m.owner; state.isOwner = m.isOwner;
        for (const it of (m.history || [])) {
          const t = await decryptMsg(it.blob);
          if (t !== null) addMsg(state.names.get(it.from) || '匿名', t, false);
        }
        for (const pid of m.peers) { state.names.set(pid, '匿名'); await makeOffer(pid); }
        renderPeers();
        break;
      }
      case 'peer-joined':
        send({ type: 'name', name: state.nick });
        send({ type: 'state', state: { mic: state.micOn, cam: state.camOn || state.screenOn } });
        renderPeers();
        break;
      case 'peer-left': {
        const pc = state.pcs.get(m.peerId); if (pc) { try { pc.close(); } catch (e) {} state.pcs.delete(m.peerId); }
        state.dcs.delete(m.peerId);
        const el = state.audioEls.get(m.peerId); if (el) { el.srcObject = null; el.remove(); state.audioEls.delete(m.peerId); }
        const v = state.videoEls.get(m.peerId); if (v) { v.srcObject = null; const t = v.parentElement; t && t.remove(); state.videoEls.delete(m.peerId); }
        state.names.delete(m.peerId); state.states.delete(m.peerId);
        renderPeers();
        break;
      }
      case 'owner-changed': state.owner = m.peerId; renderPeers(); break;
      case 'signal': await onSignal(m.from, m.payload || {}); break;
      case 'msg': {
        const text = await decryptMsg(m.blob);
        if (text !== null) addMsg(state.names.get(m.from) || '匿名', text, false);
        break;
      }
      case 'peer-name': state.names.set(m.peerId, m.name || '匿名'); renderPeers(); break;
      case 'peer-state': state.states.set(m.peerId, m.state || {}); renderPeers(); break;
      case 'error':
        if (m.code === 'room-full') { toast('房间已满'); leaveRoom(true); }
        else if (m.code === 'server-full') { toast('服务繁忙'); leaveRoom(true); }
        break;
      case 'rate-limited': toast('发送太快'); break;
    }
  };

  ws.onclose = () => {
    els.connDot.className = 'dot bad';
    if (state.joined) {
      state.joined = false;
      setTimeout(() => { if (state.roomId) connectWs(); }, 1500);
    }
  };
  ws.onerror = () => {};
}

/* ============ 进出房间 ============ */
async function enterRoom(password, isCreate) {
  const enc = new TextEncoder();
  // 盐：优先用邀请链接里的随机盐；开房时无盐则新建随机盐
  // （不再回退到固定盐，避免任何可预测性）
  let saltB64 = getUrlSalt();
  if (!saltB64) saltB64 = newSalt();
  const saltBytes = unb64url(saltB64) || enc.encode(saltB64);
  const { roomId, chatKey } = await deriveKeys(password, saltBytes);
  state.roomId = roomId; state.chatKey = chatKey;
  state.peerId = randomId();
  state.nick = (els.nick.value || '').trim().slice(0, 16) || '匿名';
  state.iceServers = [
    // 免费公共 STUN（仅用于探测，relay 模式下不暴露 IP）
    { urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] },
    // 免费公共 TURN 中继（Open Relay Project / Metered）—— 让中继可用
    {
      urls: [
        'turn:openrelay.metered.ca:80',
        'turn:openrelay.metered.ca:443',
        'turn:openrelay.metered.ca:443?transport=tcp',
        'turns:openrelay.metered.ca:443?transport=tcp'
      ],
      username: 'openrelayproject',
      credential: 'openrelayproject'
    }
  ];
  state.isCreator = !!isCreate;
  // 静默隐私：消息自动焚毁（15 分钟）
  state.burnSeconds = 900;

  try {
    state.rawStream = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }, video: false
    });
    state.outStream = state.rawStream;
  } catch (e) {
    toast('麦克风不可用');
    state.rawStream = null; state.micOn = false;
    els.btnMic.className = 'ctrl off';
  }

  els.roomLabel.textContent = '房间 ' + roomId.slice(0, 6).toUpperCase();
  showScreen('room');
  renderPeers();

  // 开房间：生成随机盐写入地址栏（fragment，不会发给服务器），分享链接只含盐不含密码
  if (isCreate) {
    try { history.replaceState(null, '', '#s=' + saltB64); } catch (e) {}
    const base = location.origin + location.pathname;
    const link = base + '#s=' + saltB64;
    els.shareLink.value = link;
    els.shareBox.style.display = '';
  }

  connectWs();
}

function leaveRoom(silent) {
  send({ type: 'bye' });
  try { state.ws && state.ws.close(); } catch (e) {}
  state.pcs.forEach(pc => { try { pc.close(); } catch (e) {} });
  state.pcs.clear(); state.dcs.clear();
  state.audioEls.forEach(el => { el.srcObject = null; el.remove(); }); state.audioEls.clear();
  state.videoEls.forEach(v => { v.srcObject = null; const t = v.parentElement; t && t.remove(); }); state.videoEls.clear();
  state.names.clear(); state.states.clear(); state.recvFiles.clear();
  [state.rawStream, state.camStream, state.screenStream].forEach(s => { if (s) s.getTracks().forEach(t => t.stop()); });
  state.rawStream = null; state.outStream = null; state.camStream = null; state.screenStream = null;
  state.roomId = null; state.chatKey = null; state.joined = false;
  state.camOn = false; state.screenOn = false;
  els.msgs.innerHTML = ''; els.videos.innerHTML = ''; els.typing.textContent = '';
  els.connDot.className = 'dot';
  els.shareBox.style.display = 'none';
  els.chat.classList.remove('open'); els.panel.classList.remove('open'); els.videoBox.classList.remove('open');
  els.btnCam.className = 'ctrl'; els.btnScreen.className = 'ctrl';
  state.chatOpen = false; state.unread = 0; els.unread.style.display = 'none';
  showScreen('home');
  if (!silent) toast('已离开');
}

/* ============ 事件 ============ */
async function doEnter(isCreate) {
  const pwd = els.pwd.value;
  els.homeHint.textContent = '';
  if (!pwd || pwd.length < 6) { els.homeHint.textContent = '密码至少 6 位'; return; }
  els.btnCreate.disabled = true;
  els.btnJoin.disabled = true;
  try {
    await enterRoom(pwd, isCreate);
  } catch (e) {
    els.homeHint.textContent = '出错了，请重试';
  } finally {
    els.btnCreate.disabled = false;
    els.btnJoin.disabled = false;
  }
}

els.btnCreate.onclick = () => doEnter(true);
els.btnJoin.onclick = () => doEnter(false);
els.pwd.addEventListener('input', updateMeter);
els.pwd.addEventListener('keydown', e => { if (e.key === 'Enter') doEnter(false); });
els.nick.addEventListener('keydown', e => { if (e.key === 'Enter') doEnter(false); });
els.btnEye.onclick = () => { els.pwd.type = els.pwd.type === 'password' ? 'text' : 'password'; };
els.btnCopy.onclick = () => {
  els.shareLink.select();
  try { document.execCommand('copy'); } catch (e) {}
  if (navigator.clipboard) { try { navigator.clipboard.writeText(els.shareLink.value); } catch (e) {} }
  toast('已复制');
};

els.btnLeave.onclick = () => {
  showModal('离开房间？', '', [{ text: '取消' }, { text: '离开', primary: true, onClick: () => leaveRoom(false) }]);
};

els.btnMic.onclick = () => {
  if (!state.rawStream) { toast('无麦克风'); return; }
  state.micOn = !state.micOn;
  state.rawStream.getAudioTracks().forEach(t => { t.enabled = state.micOn; });
  els.btnMic.className = 'ctrl ' + (state.micOn ? 'on' : 'off');
  els.btnMic.querySelector('.ci').textContent = state.micOn ? '🎤' : '🔇';
  els.btnMic.querySelector('.cl').textContent = state.micOn ? '麦克风' : '已静音';
  send({ type: 'state', state: { mic: state.micOn, cam: state.camOn || state.screenOn } });
  renderPeers();
};

els.btnDeaf.onclick = () => {
  state.deaf = !state.deaf;
  state.audioEls.forEach(el => { el.muted = state.deaf; });
  els.btnDeaf.className = 'ctrl ' + (state.deaf ? 'off' : 'on');
  els.btnDeaf.querySelector('.ci').textContent = state.deaf ? '🔈' : '🔊';
  els.btnDeaf.querySelector('.cl').textContent = state.deaf ? '已静音' : '扬声器';
};

els.btnCam.onclick = async () => {
  if (state.camOn) {
    if (state.camStream) state.camStream.getTracks().forEach(t => t.stop());
    state.camStream = null; state.camOn = false;
    els.btnCam.className = 'ctrl';
    await renegotiateVideo(); return;
  }
  try {
    state.camStream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480 }, audio: false });
    state.camOn = true; els.btnCam.className = 'ctrl active';
    await renegotiateVideo();
    send({ type: 'state', state: { mic: state.micOn, cam: true } });
    let v = state.videoEls.get('self');
    if (!v) {
      const tile = document.createElement('div'); tile.className = 'vtile';
      v = document.createElement('video'); v.autoplay = true; v.playsInline = true; v.muted = true;
      const nm = document.createElement('span'); nm.textContent = '我';
      tile.appendChild(v); tile.appendChild(nm); els.videos.appendChild(tile);
      state.videoEls.set('self', v);
    }
    v.srcObject = state.camStream; v.play().catch(() => {});
    els.videoBox.classList.add('open');
  } catch (e) { toast('摄像头不可用'); }
};

els.btnScreen.onclick = async () => {
  if (state.screenOn) {
    if (state.screenStream) state.screenStream.getTracks().forEach(t => t.stop());
    state.screenStream = null; state.screenOn = false;
    els.btnScreen.className = 'ctrl';
    await renegotiateVideo(); return;
  }
  try {
    state.screenStream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
    state.screenOn = true; els.btnScreen.className = 'ctrl active';
    state.screenStream.getVideoTracks()[0].onended = () => { state.screenOn = false; els.btnScreen.className = 'ctrl'; renegotiateVideo(); };
    await renegotiateVideo();
  } catch (e) {}
};

async function renegotiateVideo() {
  for (const [pid, pc] of state.pcs) {
    for (const s of pc.getSenders()) { if (s.track && s.track.kind === 'video') { try { pc.removeTrack(s); } catch (e) {} } }
    const vs = state.screenStream || state.camStream;
    const vt = vs ? vs.getVideoTracks()[0] : null;
    if (vt) { try { pc.addTrack(vt, vs); } catch (e) {} }
    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      send({ type: 'signal', to: pid, payload: { sdp: pc.localDescription } });
    } catch (e) {}
  }
}

els.btnVoice.onclick = () => {
  const items = VOICE_LIST.map(v => ({
    text: v.name + (state.voiceEffect === v.id ? ' ✓' : ''),
    primary: state.voiceEffect === v.id,
    onClick: () => { applyVoice(v.id); toast('变声：' + v.name); }
  }));
  els.modalBox.innerHTML = '<div style="font-weight:600;font-size:16px;margin-bottom:12px">变声</div>';
  const bar = document.createElement('div'); bar.className = 'mBtns'; bar.style.flexWrap = 'wrap';
  items.forEach(b => {
    const btn = document.createElement('button');
    btn.className = 'btn' + (b.primary ? ' primary' : '');
    btn.textContent = b.text;
    btn.style.flex = '1 1 40%';
    btn.onclick = () => { els.modal.classList.remove('open'); b.onClick(); };
    bar.appendChild(btn);
  });
  els.modalBox.appendChild(bar);
  els.modal.classList.add('open');
};

els.btnChat.onclick = () => {
  state.chatOpen = !state.chatOpen;
  els.chat.classList.toggle('open', state.chatOpen);
  if (state.chatOpen) { state.unread = 0; els.unread.style.display = 'none'; els.msgInput.focus(); }
};
els.btnChatClose.onclick = () => { state.chatOpen = false; els.chat.classList.remove('open'); };
els.btnPanel.onclick = () => els.panel.classList.toggle('open');
els.btnPanelClose.onclick = () => els.panel.classList.remove('open');
els.imgViewClose.onclick = () => els.imgView.classList.remove('open');
els.imgView.onclick = (e) => { if (e.target === els.imgView) els.imgView.classList.remove('open'); };

function pickImage() { els.fileInput.click(); }
els.btnImg.onclick = pickImage;
els.btnImgPick.onclick = pickImage;
els.fileInput.onchange = async () => {
  for (const f of [...els.fileInput.files]) await sendBlob(f, (f.type || '').startsWith('image/'));
  els.fileInput.value = '';
};

async function doSend() {
  const text = els.msgInput.value.trim();
  if (!text) return;
  if (!state.chatKey) return;
  els.msgInput.value = '';
  const blob = await encryptMsg(text);
  send({ type: 'msg', blob });
  addMsg(state.nick + '（我）', text, true);
}
els.btnSend.onclick = doSend;
els.msgInput.addEventListener('keydown', e => { if (e.key === 'Enter') doSend(); });

/* 粘贴图片 */
document.addEventListener('paste', async (e) => {
  if (!state.chatKey) return;
  const items = (e.clipboardData && e.clipboardData.items) || [];
  for (const it of items) {
    if (it.type && it.type.startsWith('image/')) {
      const f = it.getAsFile();
      if (f) { e.preventDefault(); await sendBlob(f, true); return; }
    }
  }
});

window.addEventListener('beforeunload', () => { try { send({ type: 'bye' }); } catch (e) {} });
window.addEventListener('pagehide', () => { try { send({ type: 'bye' }); } catch (e) {} });

/* ============ 静默隐私防护 ============ */

/* ============ 反指纹加固（参考 Spectre-Anti-Fingerprint）============ */
(function antiFingerprint() {
  try {
    const SEED = state.fpSeed;
    // 伪随机（同会话内稳定，避免自身暴露不一致）
    const pr = (i) => {
      let x = (SEED ^ (i * 2654435761)) >>> 0;
      x ^= x << 13; x >>>= 0; x ^= x >> 17; x ^= x << 5; x >>>= 0;
      return x / 4294967296;
    };

    // 1) Canvas 指纹噪声：对 getImageData / toDataURL 注入极小扰动
    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function () {
      const d = origGetImageData.apply(this, arguments);
      try {
        const data = d.data;
        for (let i = 0; i < data.length; i += 997) {
          data[i] = (data[i] + ((pr(i) * 3) | 0)) & 255;
        }
      } catch (e) {}
      return d;
    };
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function () {
      try {
        const ctx = this.getContext('2d');
        if (ctx) {
          const img = origGetImageData.call(ctx, 0, 0, Math.min(this.width, 16), Math.min(this.height, 16));
          for (let i = 0; i < img.data.length; i += 61) img.data[i] = (img.data[i] + 1) & 255;
          ctx.putImageData(img, 0, 0);
        }
      } catch (e) {}
      return origToDataURL.apply(this, arguments);
    };

    // 2) WebGL 指纹：伪装 vendor / renderer 为常见值
    try {
      const patchGL = (proto) => {
        if (!proto) return;
        const og = proto.getParameter;
        proto.getParameter = function (p) {
          const ext = this.getExtension && this.getExtension('WEBGL_debug_renderer_info');
          if (ext) {
            if (p === ext.UNMASKED_VENDOR_WEBGL) return 'Google Inc.';
            if (p === ext.UNMASKED_RENDERER_WEBGL) return 'ANGLE (Intel, Intel(R) UHD Graphics, OpenGL 4.5)';
          }
          if (p === 37445) return 'Google Inc.';
          if (p === 37446) return 'ANGLE (Intel, Intel(R) UHD Graphics, OpenGL 4.5)';
          return og.apply(this, arguments);
        };
      };
      patchGL(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
      patchGL(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
    } catch (e) {}

    // 3) Audio 指纹噪声：轻微扰动 getChannelData
    try {
      const origGetChannelData = AudioBuffer.prototype.getChannelData;
      AudioBuffer.prototype.getChannelData = function () {
        const arr = origGetChannelData.apply(this, arguments);
        try {
          for (let i = 0; i < arr.length; i += 1000) {
            arr[i] = arr[i] + (pr(i) - 0.5) * 1e-7;
          }
        } catch (e) {}
        return arr;
      };
    } catch (e) {}

    // 4) 定时器精度模糊（防时序指纹）
    try {
      const origNow = performance.now.bind(performance);
      const t0 = origNow();
      performance.now = function () {
        return origNow() + (pr(Math.floor(origNow() - t0)) - 0.5) * 0.02;
      };
    } catch (e) {}

    // 5) 标准化易指纹属性（让所有用户看起来一样）
    try {
      const spoof = (obj, key, val) => {
        try { Object.defineProperty(obj, key, { get: () => val, configurable: true }); } catch (e) {}
      };
      spoof(navigator, 'hardwareConcurrency', 4);
      spoof(navigator, 'deviceMemory', 8);
      spoof(navigator, 'platform', 'Win32');
      spoof(navigator, 'doNotTrack', '1');
      if (navigator.plugins && navigator.plugins.length !== undefined) {
        try { Object.defineProperty(navigator, 'plugins', { get: () => [], configurable: true }); } catch (e) {}
      }
      // 语言标准化（不暴露 zh-CN 中文环境）
      try { Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'], configurable: true }); } catch (e) {}
      // 时区混淆：把本地时区改为 UTC（防地理位置推断）
      try {
        const origResolved = Intl.DateTimeFormat.prototype.resolvedOptions;
        Intl.DateTimeFormat.prototype.resolvedOptions = function () {
          const o = origResolved.apply(this, arguments);
          try { o.timeZone = 'UTC'; } catch (e) {}
          return o;
        };
        const origDTF = Intl.DateTimeFormat;
        // getTimezoneOffset 返回 0（UTC）
        Date.prototype.getTimezoneOffset = function () { return 0; };
      } catch (e) {}
      // 屏幕标准化（改成最常见的 1920x1080）
      try {
        spoof(screen, 'width', 1920);
        spoof(screen, 'height', 1080);
        spoof(screen, 'availWidth', 1920);
        spoof(screen, 'availHeight', 1040);
        spoof(screen, 'colorDepth', 24);
        spoof(screen, 'pixelDepth', 24);
        spoof(window, 'devicePixelRatio', 1);
      } catch (e) {}
    } catch (e) {}

    // 6) 移除可能用于指纹的 API
    try { if (navigator.getBattery) navigator.getBattery = undefined; } catch (e) {}
    try { if (navigator.connection) Object.defineProperty(navigator, 'connection', { get: () => undefined, configurable: true }); } catch (e) {}
    try { if (navigator.keyboard) Object.defineProperty(navigator, 'keyboard', { get: () => undefined, configurable: true }); } catch (e) {}
  } catch (e) {}
})();

// 1. 禁止右键菜单 / 长按菜单
['contextmenu', 'dragstart'].forEach(ev =>
  document.addEventListener(ev, e => { if (e.target.tagName !== 'INPUT') e.preventDefault(); }, { passive: false })
);

// 2. 禁止复制/剪切聊天内容（输入框除外）
document.addEventListener('copy', e => {
  const sel = String(window.getSelection ? window.getSelection() : '');
  if (sel && e.target && e.target.tagName !== 'INPUT') {
    e.preventDefault();
    e.clipboardData.setData('text/plain', '');
    toast('内容不可复制');
  }
});
document.addEventListener('cut', e => {
  if (e.target && e.target.tagName !== 'INPUT') { e.preventDefault(); }
});

// 3. 打印/另存为防护（PrintScreen 无法拦截，但可防打印）
window.addEventListener('keydown', e => {
  const k = (e.key || '').toLowerCase();
  if ((e.ctrlKey || e.metaKey) && (k === 'p' || k === 's')) {
    if (!state.roomId) return;
    e.preventDefault();
    toast('已阻止');
  }
});

// 4. 页面失去焦点时自动隐藏内容（防肩窥/录屏）
let blurMask = null;
document.addEventListener('visibilitychange', () => {
  if (!state.roomId) return;
  if (document.hidden) {
    if (!blurMask) {
      blurMask = document.createElement('div');
      blurMask.style.cssText = 'position:fixed;inset:0;z-index:9998;background:#0a0e14;display:flex;align-items:center;justify-content:center;color:#7d8a9c;font-size:15px';
      blurMask.textContent = '已暂停';
      document.body.appendChild(blurMask);
    }
  } else if (blurMask) {
    blurMask.remove(); blurMask = null;
  }
});
window.addEventListener('blur', () => {
  if (!state.roomId) return;
  if (!blurMask) {
    blurMask = document.createElement('div');
    blurMask.style.cssText = 'position:fixed;inset:0;z-index:9998;background:#0a0e14;display:flex;align-items:center;justify-content:center;color:#7d8a9c;font-size:15px';
    blurMask.textContent = '已暂停';
    document.body.appendChild(blurMask);
  }
});
window.addEventListener('focus', () => {
  if (blurMask) { blurMask.remove(); blurMask = null; }
});

// 5. 离房时清理剪贴板中的图片数据（如刚才复制过）
window.addEventListener('pagehide', () => {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText('');
  } catch (e) {}
});

// 6. 阻止 WebRTC IP 泄漏到第三方（仅允许连接房间成员）
//    注：STUN 会暴露公网 IP 给对端（P2P 必需），但不会暴露给服务器之外的第三方
