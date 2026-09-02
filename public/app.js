/* text-sync 前端 — 加解密全部在這裡發生，伺服器只收得到密文 */

const $ = (id) => document.getElementById(id);
const ROOM_CODE_RE = /^[a-z0-9][a-z0-9-]{2,31}$/;
const STORE_KEY = 'text-sync.rooms.v1';
const THEME_KEY = 'text-sync.theme';
const MAX_CHARS = 180000;

// ---------------------------------------------------------------- base64url

const b64u = {
  encode(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  decode(str) {
    const s = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

// ---------------------------------------------------------------- crypto

const te = new TextEncoder();
const td = new TextDecoder();

/**
 * 從網址 fragment 的 secret 衍生兩把鑰匙：
 *   encKey    — AES-GCM 金鑰，只留在這個瀏覽器裡
 *   authToken — 送給伺服器證明「我知道金鑰」，伺服器只存它的 SHA-256
 */
async function deriveKeys(secretBytes) {
  const base = await crypto.subtle.importKey('raw', secretBytes, 'HKDF', false, ['deriveKey', 'deriveBits']);
  const hkdf = (info, salt = new Uint8Array(0)) => ({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) });

  const encKey = await crypto.subtle.deriveKey(
    hkdf('text-sync:enc:v1'), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
  const authBits = await crypto.subtle.deriveBits(hkdf('text-sync:auth:v1'), base, 256);

  return { encKey, authToken: 'ts.' + b64u.encode(new Uint8Array(authBits)) };
}

async function encryptText(encKey, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, te.encode(text));
  const joined = new Uint8Array(iv.length + ct.byteLength);
  joined.set(iv, 0);
  joined.set(new Uint8Array(ct), iv.length);
  return b64u.encode(joined);
}

async function decryptText(encKey, payload) {
  try {
    const raw = b64u.decode(payload);
    const iv = raw.slice(0, 12);
    const ct = raw.slice(12);
    return td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, encKey, ct));
  } catch {
    return null; // 金鑰不符或資料損毀
  }
}

// ---------------------------------------------------------------- 配對碼

// 沒有 0/1/I/O，剛好 32 個字元 → 每碼 5 bits，8 碼 = 40 bits
const PAIR_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const PAIR_LEN = 8;
const PAIR_ITERATIONS = 300000;

function randomPairCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(PAIR_LEN));
  return [...bytes].map((b) => PAIR_ALPHABET[b % 32]).join('');
}

function normalizePairCode(input) {
  return input.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function formatPairCode(code) {
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

/**
 * 從配對碼推出「暫存格位置」與「解密金鑰」。
 *
 * 兩者都掛在同一次 PBKDF2（30 萬次）之後，所以就算伺服器看到了 slotId，
 * 想回推配對碼一樣得付出 30 萬次雜湊 × 2^40 種組合的代價。
 */
async function derivePairKeys(code) {
  const material = await crypto.subtle.importKey('raw', te.encode(code), 'PBKDF2', false, ['deriveBits']);
  const masterBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: te.encode('text-sync:pair:v1'), iterations: PAIR_ITERATIONS },
    material, 256,
  );

  const master = await crypto.subtle.importKey('raw', masterBits, 'HKDF', false, ['deriveKey', 'deriveBits']);
  const hkdf = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(info) });

  const slotBits = await crypto.subtle.deriveBits(hkdf('text-sync:pair:slot:v1'), master, 256);
  const encKey = await crypto.subtle.deriveKey(
    hkdf('text-sync:pair:enc:v1'), master, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );

  const slotId = [...new Uint8Array(slotBits)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return { slotId, encKey };
}

/** 把目前房間的完整網址加密後放進暫存格，回傳配對碼 */
async function createPairing(url) {
  const code = randomPairCode();
  const { slotId, encKey } = await derivePairKeys(code);
  const payload = await encryptText(encKey, url);

  const res = await fetch(`/api/pair/${slotId}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ payload }),
  });
  if (!res.ok) throw new Error('配對暫存失敗');

  const { ttlMs } = await res.json();
  return { code, ttlMs };
}

/** 用配對碼把網址取回來（取一次就沒了） */
async function consumePairing(code) {
  const { slotId, encKey } = await derivePairKeys(code);
  const res = await fetch(`/api/pair/${slotId}`);
  if (!res.ok) return null;

  const { payload } = await res.json();
  return decryptText(encKey, payload);
}

// ---------------------------------------------------------------- 本機記住的房間

const store = {
  all() {
    try {
      return JSON.parse(localStorage.getItem(STORE_KEY)) || [];
    } catch {
      return [];
    }
  },
  save(list) {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(list.slice(0, 50)));
    } catch { /* 隱私模式或空間滿了，功能降級但不擋流程 */ }
  },
  get(code) {
    return this.all().find((r) => r.code === code) || null;
  },
  remember(code, secret, extra = {}) {
    const list = this.all().filter((r) => r.code !== code);
    list.unshift({ code, secret, lastSeen: Date.now(), ...extra });
    this.save(list);
  },
  update(code, patch) {
    const list = this.all();
    const hit = list.find((r) => r.code === code);
    if (!hit) return;
    Object.assign(hit, patch);
    this.save(list);
  },
  forget(code) {
    this.save(this.all().filter((r) => r.code !== code));
  },
};

// ---------------------------------------------------------------- 小工具

function toast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 2200);
}

function relTime(ts) {
  const diff = Date.now() - ts;
  if (diff < 45e3) return '剛剛';
  if (diff < 3600e3) return `${Math.round(diff / 60e3)} 分鐘前`;
  if (diff < 86400e3) return `${Math.round(diff / 3600e3)} 小時前`;
  return `${Math.round(diff / 86400e3)} 天前`;
}

function randomCode() {
  const alphabet = 'abcdefghijkmnpqrstuvwxyz23456789'; // 去掉 l/o/0/1
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join('');
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // http 或舊瀏覽器的退路
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}

// ---------------------------------------------------------------- 主題

(function initTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved) document.documentElement.dataset.theme = saved;
  $('theme-toggle').addEventListener('click', () => {
    const dark = matchMedia('(prefers-color-scheme: dark)').matches;
    const current = document.documentElement.dataset.theme || (dark ? 'dark' : 'light');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem(THEME_KEY, next);
  });
})();

// ---------------------------------------------------------------- 路由

function parseLocation() {
  const m = location.pathname.match(/^\/r\/([^/]+)\/?$/);
  if (!m) return { view: 'home' };

  const code = decodeURIComponent(m[1]).toLowerCase();
  const hash = new URLSearchParams(location.hash.replace(/^#/, ''));
  let secret = hash.get('k');

  // 只存了路徑當書籤時，用這台裝置記住的金鑰把 fragment 補回來
  if (!secret) {
    const saved = store.get(code);
    if (saved) {
      secret = saved.secret;
      history.replaceState(null, '', `/r/${code}#k=${secret}`);
    }
  }
  return { view: 'room', code, secret };
}

function show(view) {
  $('view-home').hidden = view !== 'home';
  $('view-room').hidden = view !== 'room';
  $('room-status').hidden = view !== 'room';
}

// ---------------------------------------------------------------- 首頁

function renderHome() {
  show('home');
  document.title = 'text-sync — 跨裝置加密剪貼簿';

  const rooms = store.all();
  $('saved-card').hidden = rooms.length === 0;

  const list = $('saved-list');
  list.replaceChildren();
  for (const r of rooms) {
    const li = document.createElement('li');

    const a = document.createElement('a');
    a.href = `/r/${r.code}#k=${r.secret}`;
    a.textContent = r.code;

    const time = document.createElement('time');
    time.textContent = relTime(r.lastSeen || 0);

    li.append(a);
    if (r.pinned) {
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = '已釘選';
      li.append(badge);
    }
    li.append(time);

    const del = document.createElement('button');
    del.textContent = '忘記';
    del.className = 'ghost';
    del.addEventListener('click', () => {
      store.forget(r.code);
      renderHome();
      toast('已從這台裝置移除');
    });
    li.append(del);

    list.append(li);
  }
}

$('create-btn').addEventListener('click', () => {
  const err = $('create-error');
  err.hidden = true;

  let code = $('new-code').value.trim().toLowerCase();
  if (!code) code = randomCode();

  if (!ROOM_CODE_RE.test(code)) {
    err.textContent = '代碼需為 3–32 個字元，只能用小寫英文、數字、連字號，且開頭不是連字號。';
    err.hidden = false;
    return;
  }

  const secret = b64u.encode(crypto.getRandomValues(new Uint8Array(32)));
  location.href = `/r/${code}#k=${secret}`;
});

$('new-code').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('create-btn').click();
});

$('join-btn').addEventListener('click', () => {
  const err = $('join-error');
  err.hidden = true;

  const raw = $('join-url').value.trim();
  if (!raw) return;

  try {
    const u = new URL(raw, location.origin);
    const m = u.pathname.match(/^\/r\/([^/]+)\/?$/);
    const k = new URLSearchParams(u.hash.replace(/^#/, '')).get('k');
    if (!m || !k) throw new Error('bad');
    location.href = `/r/${decodeURIComponent(m[1]).toLowerCase()}#k=${k}`;
  } catch {
    err.textContent = '這不像一個完整的房間網址。要長得像 https://…/r/代碼#k=金鑰';
    err.hidden = false;
  }
});

$('join-url').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('join-btn').click();
});

$('pair-join-btn').addEventListener('click', async () => {
  const err = $('pair-error');
  const btn = $('pair-join-btn');
  err.hidden = true;

  const code = normalizePairCode($('pair-input').value);
  if (code.length !== PAIR_LEN || [...code].some((c) => !PAIR_ALPHABET.includes(c))) {
    err.textContent = `配對碼是 ${PAIR_LEN} 個字元，只會用到 ${PAIR_ALPHABET} 這些字（沒有 0、1、I、O）。`;
    err.hidden = false;
    return;
  }

  btn.disabled = true;
  btn.textContent = '驗證中…';
  try {
    const url = await consumePairing(code);
    if (!url) {
      err.textContent = '這組配對碼無效、已過期，或已經被用掉了。請在另一台電腦重新產生一組。';
      err.hidden = false;
      return;
    }
    location.href = url;
  } catch {
    err.textContent = '連線失敗，請確認網路後再試。';
    err.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = '加入';
  }
});

$('pair-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('pair-join-btn').click();
});

// ---------------------------------------------------------------- 房間

class Room {
  constructor(code, secret, encKey, authToken) {
    this.code = code;
    this.secret = secret;
    this.encKey = encKey;
    this.authToken = authToken;
    this.ws = null;
    this.retry = 0;
    this.clips = new Map();
    this.settings = { ttlDays: 7, pinned: false };
    this.typingTimer = null;
    this.lastTypingSent = 0;
    this.closedByUs = false;
    this.everOpen = false;
    this.failures = 0;
  }

  giveUp() {
    this.closedByUs = true;
    this.setConn('off', '無法進入');
    const es = $('empty-state');
    es.hidden = false;
    es.textContent =
      '無法進入這個房間：這組代碼已經有人在用，而你的金鑰不符。請改用當初分享出去的完整網址，或回首頁換一組代碼。';
    toast('金鑰不符，無法進入這個房間');
  }

  connect() {
    this.setConn('connecting', '連線中');
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${location.host}/api/room/${encodeURIComponent(this.code)}/ws`;

    let ws;
    try {
      ws = new WebSocket(url, [this.authToken]);
    } catch {
      return this.scheduleReconnect();
    }
    this.ws = ws;

    ws.addEventListener('open', () => {
      this.retry = 0;
      this.everOpen = true;
      this.setConn('on', '已連線');
      // 握手完成後才報到，這時伺服器才數得到這條連線
      ws.send(JSON.stringify({ type: 'hello' }));
    });

    ws.addEventListener('message', (e) => this.onMessage(e));

    ws.addEventListener('close', () => {
      if (this.closedByUs) return;
      // 從沒握手成功過 → 多半是伺服器擋下（金鑰不符），重試也不會變好
      if (!this.everOpen && ++this.failures >= 3) return this.giveUp();
      this.setConn('off', '已斷線');
      this.scheduleReconnect();
    });
  }

  destroy() {
    this.closedByUs = true;
    clearTimeout(this.typingTimer);
    try { this.ws?.close(); } catch { /* 已經關了 */ }
  }

  scheduleReconnect() {
    const delay = Math.min(1000 * 2 ** this.retry, 15000);
    this.retry++;
    setTimeout(() => { if (!this.closedByUs) this.connect(); }, delay);
  }

  send(msg) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
      return true;
    }
    toast('還沒連上，稍等一下再試');
    return false;
  }

  setConn(state, text) {
    const dot = $('conn-dot');
    dot.className = `dot ${state === 'on' ? 'on' : state === 'off' ? 'off' : ''}`;
    $('conn-text').textContent = text;
    if (state !== 'on') {
      $('peers').hidden = true;
    }
  }

  async onMessage(e) {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }

    switch (msg.type) {
      case 'init':
        // 連上了才記住金鑰：否則開到一個壞金鑰的連結會蓋掉本機存好的正確金鑰
        store.remember(this.code, this.secret, { pinned: store.get(this.code)?.pinned || false });
        this.clips.clear();
        for (const c of msg.clips) this.clips.set(c.id, c);
        this.applySettings(msg.settings);
        this.setPeers(msg.peers);
        await this.render();
        break;

      case 'clips':
        this.clips.clear();
        for (const c of msg.clips) this.clips.set(c.id, c);
        await this.render();
        break;

      case 'add':
        this.clips.set(msg.clip.id, msg.clip);
        await this.render();
        break;

      case 'delete':
        this.clips.delete(msg.id);
        await this.render();
        break;

      case 'clear':
        this.clips.clear();
        await this.render();
        break;

      case 'settings':
        this.applySettings(msg.settings);
        break;

      case 'peers':
        this.setPeers(msg.peers);
        break;

      case 'typing':
        this.showTyping();
        break;

      case 'error':
        toast(msg.message || '發生錯誤');
        break;
    }
  }

  applySettings(s) {
    this.settings = s;
    $('ttl-select').value = String(s.ttlDays);
    $('pin-toggle').checked = s.pinned;
    $('pin-badge').hidden = !s.pinned;
    store.update(this.code, { pinned: s.pinned });
  }

  setPeers(n) {
    const el = $('peers');
    el.textContent = `${n} 台裝置`;
    el.hidden = !(n > 0);
  }

  showTyping() {
    const el = $('typing');
    el.hidden = false;
    clearTimeout(this.typingTimer);
    this.typingTimer = setTimeout(() => { el.hidden = true; }, 2500);
  }

  notifyTyping() {
    const now = Date.now();
    if (now - this.lastTypingSent < 1200) return;
    this.lastTypingSent = now;
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: 'typing' }));
    }
  }

  async render() {
    const wrap = $('clips');
    wrap.replaceChildren();

    const sorted = [...this.clips.values()].sort((a, b) => b.created - a.created);
    $('empty-state').hidden = sorted.length > 0;

    for (const clip of sorted) {
      const text = await decryptText(this.encKey, clip.payload);
      wrap.append(this.clipNode(clip, text));
    }
  }

  clipNode(clip, text) {
    const el = document.createElement('article');
    el.className = 'clip';

    const body = document.createElement('pre');
    body.className = 'clip-body';

    if (text === null) {
      el.classList.add('undecryptable');
      body.textContent = '（無法解密：這筆內容是用另一把金鑰寫入的）';
    } else {
      body.textContent = text;
    }
    el.append(body);

    const foot = document.createElement('div');
    foot.className = 'clip-foot';

    const meta = document.createElement('span');
    meta.textContent = text === null
      ? relTime(clip.created)
      : `${relTime(clip.created)} · ${text.length} 字`;
    foot.append(meta);

    const spacer = document.createElement('span');
    spacer.className = 'grow';
    foot.append(spacer);

    if (text !== null) {
      const copyBtn = document.createElement('button');
      copyBtn.textContent = '複製';
      copyBtn.addEventListener('click', async () => {
        toast((await copy(text)) ? '已複製' : '複製失敗，請手動選取');
      });
      foot.append(copyBtn);
    }

    const delBtn = document.createElement('button');
    delBtn.textContent = '刪除';
    delBtn.addEventListener('click', () => this.send({ type: 'delete', id: clip.id }));
    foot.append(delBtn);

    el.append(foot);

    // 長文摺疊：等進 DOM 量到實際高度再決定要不要給展開鈕
    requestAnimationFrame(() => {
      if (body.scrollHeight > body.clientHeight + 4) {
        el.classList.add('clipped');
        const more = document.createElement('button');
        more.textContent = '展開';
        more.addEventListener('click', () => {
          el.classList.toggle('expanded');
          more.textContent = el.classList.contains('expanded') ? '收合' : '展開';
        });
        foot.insertBefore(more, foot.lastElementChild);
      }
    });

    return el;
  }

  async submit() {
    const ta = $('input');
    const text = ta.value;
    if (!text.trim()) return;
    if (text.length > MAX_CHARS) return toast(`內容太長了（上限 ${MAX_CHARS} 字）`);

    const payload = await encryptText(this.encKey, text);
    if (this.send({ type: 'add', payload })) {
      ta.value = '';
      updateCharCount();
      ta.focus();
    }
  }
}

// ---------------------------------------------------------------- 房間 UI 綁定

let room = null;

function updateCharCount() {
  const n = $('input').value.length;
  $('char-count').textContent = n ? `${n} 字` : '';
}

$('input').addEventListener('input', () => {
  updateCharCount();
  if (room) room.notifyTyping();
});

$('input').addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
    e.preventDefault();
    room?.submit();
  }
});

$('send-btn').addEventListener('click', () => room?.submit());

$('settings-btn').addEventListener('click', () => {
  const p = $('settings-panel');
  p.hidden = !p.hidden;
});

$('ttl-select').addEventListener('change', (e) => {
  room?.send({ type: 'settings', ttlDays: Number(e.target.value) });
});

$('pin-toggle').addEventListener('change', (e) => {
  room?.send({ type: 'settings', pinned: e.target.checked });
  toast(e.target.checked ? '已釘選，不會自動回收' : '已取消釘選');
});

$('clear-btn').addEventListener('click', () => {
  if (!room) return;
  const btn = $('clear-btn');
  if (btn.dataset.armed !== '1') {
    btn.dataset.armed = '1';
    btn.textContent = '再按一次確認清空';
    setTimeout(() => {
      btn.dataset.armed = '0';
      btn.textContent = '清空所有內容';
    }, 4000);
    return;
  }
  room.send({ type: 'clear' });
  btn.dataset.armed = '0';
  btn.textContent = '清空所有內容';
});

$('forget-btn').addEventListener('click', () => {
  if (!room) return;
  store.forget(room.code);
  toast('這台裝置已忘記此房間');
});

$('share-btn').addEventListener('click', () => {
  const url = location.href;
  $('share-url').value = url;
  $('share-modal').hidden = false;
  resetPairUI();

  const box = $('qr');
  box.replaceChildren();
  if (typeof QRCode === 'function') {
    new QRCode(box, { text: url, width: 200, height: 200, correctLevel: QRCode.CorrectLevel.M });
  } else {
    const p = document.createElement('p');
    p.className = 'hint';
    p.textContent = 'QR 產生器沒載入，請直接複製上面的網址。';
    box.append(p);
  }
});

let pairTimer = null;

function resetPairUI() {
  clearInterval(pairTimer);
  pairTimer = null;
  $('pair-result').hidden = true;
  $('pair-gen-error').hidden = true;
  $('pair-btn').disabled = false;
  $('pair-btn').textContent = '配對這台電腦';
}

$('pair-btn').addEventListener('click', async () => {
  const btn = $('pair-btn');
  const err = $('pair-gen-error');
  err.hidden = true;
  btn.disabled = true;
  btn.textContent = '產生中…';

  try {
    const { code, ttlMs } = await createPairing(location.href);
    $('pair-code').textContent = formatPairCode(code);
    $('pair-result').hidden = false;
    btn.textContent = '換一組';
    btn.disabled = false;

    clearInterval(pairTimer);
    const deadline = Date.now() + ttlMs;
    const tick = () => {
      const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
      $('pair-countdown').textContent = left > 0
        ? `${left} 秒後失效，用過一次也會失效`
        : '已失效，按「換一組」重新產生';
      if (left === 0) clearInterval(pairTimer);
    };
    tick();
    pairTimer = setInterval(tick, 1000);
  } catch {
    err.textContent = '產生配對碼失敗，請稍後再試。';
    err.hidden = false;
    btn.disabled = false;
    btn.textContent = '配對這台電腦';
  }
});

$('copy-url-btn').addEventListener('click', async () => {
  toast((await copy($('share-url').value)) ? '網址已複製' : '複製失敗，請手動選取');
});

function closeShare() {
  $('share-modal').hidden = true;
  resetPairUI();
}

$('close-share').addEventListener('click', closeShare);

$('share-modal').addEventListener('click', (e) => {
  if (e.target === $('share-modal')) closeShare();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('share-modal').hidden) closeShare();
});

// ---------------------------------------------------------------- 啟動

async function boot() {
  const loc = parseLocation();

  if (loc.view === 'home') return renderHome();

  if (!ROOM_CODE_RE.test(loc.code)) {
    toast('房間代碼格式不對');
    return renderHome();
  }

  if (!loc.secret) {
    show('home');
    renderHome();
    $('join-error').textContent =
      `你開的網址少了金鑰（# 後面那段），所以進不了房間「${loc.code}」。請用當初分享出去的完整網址。`;
    $('join-error').hidden = false;
    return;
  }

  let keys;
  try {
    keys = await deriveKeys(b64u.decode(loc.secret));
  } catch {
    toast('金鑰格式不正確');
    return renderHome();
  }

  show('room');
  document.title = `${loc.code} — text-sync`;
  $('room-code').textContent = loc.code;

  room = new Room(loc.code, loc.secret, keys.encKey, keys.authToken);
  room.connect();
  $('input').focus();
}

boot();

// 換金鑰或換房間時網址只有 # 變動，瀏覽器不會重載，得自己接手
addEventListener('hashchange', () => {
  room?.destroy();
  room = null;
  $('clips').replaceChildren();
  $('input').value = '';
  updateCharCount();
  $('share-modal').hidden = true;
  $('settings-panel').hidden = true;
  boot();
});
