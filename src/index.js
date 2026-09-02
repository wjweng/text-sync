/**
 * text-sync — 跨裝置加密剪貼簿
 *
 * 伺服器端永遠看不到明文：瀏覽器用網址 fragment 裡的 secret 衍生出
 * 加密金鑰（不外流）與 auth token（送來驗證），這裡只存 token 的 SHA-256。
 */

const ROOM_CODE_RE = /^[a-z0-9][a-z0-9-]{2,31}$/;
const MAX_PAYLOAD_BYTES = 256 * 1024; // 密文上限，約對應 180KB 明文
const MAX_CLIPS = 200;
const DAY_MS = 86400 * 1000;
const IDLE_REAP_DAYS = 30; // 空房閒置多久回收（釘選的房間不適用）
const ALARM_INTERVAL_MS = DAY_MS;

// ---------------------------------------------------------------- Worker

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(request, env, url);
      } catch (err) {
        return json({ error: 'internal_error', message: String(err) }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  },
};

async function handleApi(request, env, url) {
  // /api/room/<code>/ws
  const m = url.pathname.match(/^\/api\/room\/([^/]+)\/ws$/);
  if (!m) return json({ error: 'not_found' }, 404);

  const code = decodeURIComponent(m[1]).toLowerCase();
  if (!ROOM_CODE_RE.test(code)) {
    return json({ error: 'bad_room_code', message: '房間代碼需為 3–32 個小寫英數字或連字號' }, 400);
  }

  if (request.headers.get('Upgrade') !== 'websocket') {
    return json({ error: 'expected_websocket' }, 426);
  }

  // auth token 走 subprotocol，不放 query string（query 會進日誌）
  const proto = request.headers.get('Sec-WebSocket-Protocol') || '';
  const token = proto.split(',').map((s) => s.trim()).find((s) => s.startsWith('ts.'));
  if (!token || token.length < 20 || token.length > 200) {
    return json({ error: 'missing_auth' }, 401);
  }

  const id = env.ROOM.idFromName(code);
  const stub = env.ROOM.get(id);
  return stub.fetch(request);
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

// ---------------------------------------------------------------- Room DO

export class RoomDO {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.sql = ctx.storage.sql;

    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        k TEXT PRIMARY KEY,
        v TEXT NOT NULL
      );
    `);
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS clips (
        id      TEXT PRIMARY KEY,
        payload TEXT    NOT NULL,
        created INTEGER NOT NULL,
        expires INTEGER NOT NULL
      );
    `);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_clips_created ON clips(created);`);
  }

  // -------------------------------------------------------------- meta

  getMeta(key, fallback = null) {
    const row = this.sql.exec('SELECT v FROM meta WHERE k = ?', key).toArray()[0];
    return row ? row.v : fallback;
  }

  setMeta(key, value) {
    this.sql.exec(
      'INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v',
      key,
      String(value),
    );
  }

  settings() {
    return {
      ttlDays: Number(this.getMeta('ttl_days', '7')),
      pinned: this.getMeta('pinned', '0') === '1',
    };
  }

  // -------------------------------------------------------------- connect

  async fetch(request) {
    const proto = request.headers.get('Sec-WebSocket-Protocol') || '';
    const token = proto.split(',').map((s) => s.trim()).find((s) => s.startsWith('ts.'));
    const presentedHash = await sha256Hex(token);
    const storedHash = this.getMeta('auth_hash');

    if (storedHash === null) {
      // 第一個帶著金鑰進來的人建立這個房間（先到先得）
      this.setMeta('auth_hash', presentedHash);
    } else if (!timingSafeEqual(storedHash, presentedHash)) {
      return json({ error: 'unauthorized', message: '這組房間代碼已被使用，且金鑰不符' }, 403);
    }

    this.touch();

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);

    this.reapExpired();
    this.send(server, {
      type: 'init',
      clips: this.listClips(),
      settings: this.settings(),
      peers: this.ctx.getWebSockets().length,
      serverTime: Date.now(),
    });
    // 這裡不廣播 peers：新 socket 要等 101 回應送出後才會進 getWebSockets()，
    // 由 client 連上後補送 hello 觸發（見 case 'hello'）
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { 'Sec-WebSocket-Protocol': token },
    });
  }

  // -------------------------------------------------------------- messages

  async webSocketMessage(ws, raw) {
    let msg;
    try {
      msg = JSON.parse(typeof raw === 'string' ? raw : new TextDecoder().decode(raw));
    } catch {
      return this.send(ws, { type: 'error', message: 'bad_json' });
    }

    this.touch();

    switch (msg.type) {
      case 'add': {
        const payload = typeof msg.payload === 'string' ? msg.payload : '';
        if (!payload) return this.send(ws, { type: 'error', message: 'empty_payload' });
        if (payload.length > MAX_PAYLOAD_BYTES) {
          return this.send(ws, { type: 'error', message: '內容太長了（上限約 180KB）' });
        }

        const now = Date.now();
        const { ttlDays } = this.settings();
        const clip = {
          id: crypto.randomUUID(),
          payload,
          created: now,
          expires: now + ttlDays * DAY_MS,
        };

        this.sql.exec(
          'INSERT INTO clips (id, payload, created, expires) VALUES (?, ?, ?, ?)',
          clip.id, clip.payload, clip.created, clip.expires,
        );
        this.trim();
        this.broadcast({ type: 'add', clip });
        break;
      }

      case 'delete': {
        if (typeof msg.id !== 'string') return;
        this.sql.exec('DELETE FROM clips WHERE id = ?', msg.id);
        this.broadcast({ type: 'delete', id: msg.id });
        break;
      }

      case 'clear': {
        this.sql.exec('DELETE FROM clips');
        this.broadcast({ type: 'clear' });
        break;
      }

      case 'settings': {
        if (Number.isFinite(msg.ttlDays) && [1, 7, 30].includes(msg.ttlDays)) {
          this.setMeta('ttl_days', msg.ttlDays);
          // 既有 clip 依新 TTL 重新計算到期時間
          this.sql.exec('UPDATE clips SET expires = created + ?', msg.ttlDays * DAY_MS);
        }
        if (typeof msg.pinned === 'boolean') {
          this.setMeta('pinned', msg.pinned ? '1' : '0');
        }
        this.broadcast({ type: 'settings', settings: this.settings() });
        break;
      }

      case 'typing': {
        this.broadcast({ type: 'typing' }, ws);
        break;
      }

      case 'hello': {
        this.broadcastPeers();
        break;
      }

      case 'ping': {
        this.send(ws, { type: 'pong' });
        break;
      }
    }
  }

  async webSocketClose(ws) {
    this.broadcastPeers(ws);
  }

  async webSocketError(ws) {
    this.broadcastPeers(ws);
  }

  // -------------------------------------------------------------- alarm

  async alarm() {
    this.reapExpired();

    const { pinned } = this.settings();
    const remaining = this.sql.exec('SELECT COUNT(*) AS n FROM clips').one().n;
    const lastSeen = Number(this.getMeta('last_seen', '0'));
    const idleFor = Date.now() - lastSeen;

    // 空房、沒釘選、閒置超過 30 天 → 整個房間歸零，也不再排下一次 alarm
    if (!pinned && remaining === 0 && idleFor > IDLE_REAP_DAYS * DAY_MS) {
      await this.ctx.storage.deleteAll();
      return;
    }

    this.broadcast({ type: 'clips', clips: this.listClips() });
    await this.ctx.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
  }

  // -------------------------------------------------------------- helpers

  touch() {
    this.setMeta('last_seen', Date.now());
    this.ctx.blockConcurrencyWhile(async () => {
      if ((await this.ctx.storage.getAlarm()) === null) {
        await this.ctx.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
      }
    });
  }

  listClips() {
    return this.sql
      .exec('SELECT id, payload, created, expires FROM clips ORDER BY created DESC LIMIT ?', MAX_CLIPS)
      .toArray();
  }

  reapExpired() {
    this.sql.exec('DELETE FROM clips WHERE expires <= ?', Date.now());
  }

  trim() {
    this.sql.exec(
      `DELETE FROM clips WHERE id NOT IN (
         SELECT id FROM clips ORDER BY created DESC LIMIT ?
       )`,
      MAX_CLIPS,
    );
  }

  send(ws, msg) {
    try {
      ws.send(JSON.stringify(msg));
    } catch {
      /* 連線已關閉，忽略 */
    }
  }

  broadcast(msg, except = null) {
    const data = JSON.stringify(msg);
    for (const ws of this.ctx.getWebSockets()) {
      if (ws === except) continue;
      try {
        ws.send(data);
      } catch {
        /* 忽略斷線的 socket */
      }
    }
  }

  broadcastPeers(closing = null) {
    const n = this.ctx.getWebSockets().filter((ws) => ws !== closing).length;
    this.broadcast({ type: 'peers', peers: n }, closing);
  }
}

// ---------------------------------------------------------------- crypto

async function sha256Hex(input) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** 比對兩個等長 hex 字串，時間不隨相同前綴長度變化 */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
