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
const PAIR_TTL_MS = 90 * 1000;      // 配對碼有效時間
const MAX_PAIR_PAYLOAD = 8 * 1024;

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
  // /api/pair/<slotId> — 一次性配對暫存格。
  // slotId 是從配對碼慢雜湊出來的，伺服器拿不回配對碼，也就解不開裡面的密文。
  const pm = url.pathname.match(/^\/api\/pair\/([0-9a-f]{64})$/);
  if (pm) {
    const stub = env.PAIR.get(env.PAIR.idFromName(pm[1]));
    return stub.fetch(request);
  }

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

    this.alarmEnsured = false;
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
    await this.ensureAlarm();

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
    await this.ensureAlarm();

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
    this.alarmEnsured = true;
  }

  // -------------------------------------------------------------- helpers

  touch() {
    this.setMeta('last_seen', Date.now());
  }

  /**
   * 確保清理用的 alarm 有排。只在這個實例第一次需要時查一次——
   * 每則訊息都查會讓每次往返都多付兩次儲存操作。
   */
  async ensureAlarm() {
    if (this.alarmEnsured) return;
    this.alarmEnsured = true;
    try {
      if ((await this.ctx.storage.getAlarm()) === null) {
        await this.ctx.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
      }
    } catch {
      this.alarmEnsured = false; // 下次再試
    }
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

// ---------------------------------------------------------------- Pair DO

/**
 * 配對用的一次性暫存格：電腦1 放進加密後的房間網址，電腦2 取走一次就沒了。
 * 這裡存的是密文，解密金鑰只有知道配對碼的人算得出來。
 */
export class PairDO {
  constructor(ctx) {
    this.ctx = ctx;
  }

  async fetch(request) {
    if (request.method === 'PUT') {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: 'bad_json' }, 400);
      }

      const payload = typeof body.payload === 'string' ? body.payload : '';
      if (!payload || payload.length > MAX_PAIR_PAYLOAD) {
        return json({ error: 'bad_payload' }, 400);
      }

      const expires = Date.now() + PAIR_TTL_MS;
      await this.ctx.storage.put({ payload, expires });
      await this.ctx.storage.setAlarm(expires + 1000);
      return json({ ok: true, expiresAt: expires, ttlMs: PAIR_TTL_MS });
    }

    if (request.method === 'GET') {
      const rec = await this.ctx.storage.get(['payload', 'expires']);
      const payload = rec.get('payload');
      const expires = rec.get('expires');

      // 取走就銷毀（含過期的殘骸），配對碼只能用一次
      await this.ctx.storage.deleteAll();
      await this.ctx.storage.deleteAlarm();

      if (!payload || !expires || Date.now() > expires) {
        return json({ error: 'not_found' }, 404);
      }
      return json({ payload });
    }

    return json({ error: 'method_not_allowed' }, 405);
  }

  async alarm() {
    await this.ctx.storage.deleteAll();
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
