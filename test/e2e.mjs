// 端對端測試：模擬兩台裝置，驗證加密同步 / 認證 / 設定 / 刪除
// 預設打本機 dev server，給第一個參數就打那個網址：
//   node test/e2e.mjs https://text-sync.example.workers.dev
const target = process.argv[2] || 'http://127.0.0.1:8787';
const BASE = target.replace(/^http/, 'ws').replace(/\/$/, '');
const te = new TextEncoder(), td = new TextDecoder();
let pass = 0, fail = 0;

const b64u = {
  enc: (b) => Buffer.from(b).toString('base64url'),
  dec: (s) => new Uint8Array(Buffer.from(s, 'base64url')),
};

async function deriveKeys(secret) {
  const base = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey', 'deriveBits']);
  const h = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(info) });
  const encKey = await crypto.subtle.deriveKey(h('text-sync:enc:v1'), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const authBits = await crypto.subtle.deriveBits(h('text-sync:auth:v1'), base, 256);
  return { encKey, authToken: 'ts.' + b64u.enc(new Uint8Array(authBits)) };
}

async function encrypt(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(text));
  return b64u.enc(Buffer.concat([Buffer.from(iv), Buffer.from(ct)]));
}
async function decrypt(key, payload) {
  const raw = b64u.dec(payload);
  try {
    return td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12)));
  } catch { return null; }
}

function check(name, cond, extra = '') {
  if (cond) { pass++; console.log(`  ✅ ${name}`); }
  else { fail++; console.log(`  ❌ ${name} ${extra}`); }
}

function connect(code, token) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${BASE}/api/room/${code}/ws`, [token]);
    const inbox = [];
    const waiters = [];
    ws.addEventListener('message', (e) => {
      const m = JSON.parse(e.data);
      const w = waiters.findIndex((x) => x.match(m));
      if (w >= 0) waiters.splice(w, 1)[0].resolve(m);
      else inbox.push(m);
    });
    ws.addEventListener('open', () => { ws.send(JSON.stringify({ type: 'hello' })); resolve({
      ws,
      send: (m) => ws.send(JSON.stringify(m)),
      wait: (match, ms = 20000) => new Promise((res, rej) => {
        const hit = inbox.findIndex(match);
        if (hit >= 0) return res(inbox.splice(hit, 1)[0]);
        const t = setTimeout(() => rej(new Error('timeout waiting for message')), ms);
        waiters.push({ match, resolve: (m) => { clearTimeout(t); res(m); } });
      }),
      close: () => ws.close(),
    }); });
    ws.addEventListener('error', () => reject(new Error('ws error')));
    ws.addEventListener('close', (e) => reject(new Error('closed ' + e.code)));
    setTimeout(() => reject(new Error('connect timeout')), 5000);
  });
}

const room = 'e2e-' + Math.random().toString(36).slice(2, 8);
const secret = crypto.getRandomValues(new Uint8Array(32));
const A = await deriveKeys(secret);

console.log(`\n房間：${room}\n`);

console.log('1. 裝置 A 建立房間並連線');
const a = await connect(room, A.authToken);
const initA = await a.wait((m) => m.type === 'init');
check('收到 init', initA.type === 'init');
check('初始沒有內容', initA.clips.length === 0);
check('預設 TTL 7 天', initA.settings.ttlDays === 7, JSON.stringify(initA.settings));
check('預設未釘選', initA.settings.pinned === false);

console.log('\n2. 裝置 B 用同一把金鑰加入');
const b = await connect(room, A.authToken);
const initB = await b.wait((m) => m.type === 'init');
check('B 也收到 init', initB.type === 'init');
const peersA = await a.wait((m) => m.type === 'peers' && m.peers === 2);
check('A 看到裝置數變 2', peersA.peers === 2, JSON.stringify(peersA));

console.log('\n3. A 送出加密文字 → B 能解開');
const secretMsg = '測試同步 🔐 line1\nline2 with "quotes" & <tags>';
const payload = await encrypt(A.encKey, secretMsg);
a.send({ type: 'add', payload });
const addB = await b.wait((m) => m.type === 'add');
check('B 收到 add 廣播', !!addB.clip);
const roundTrip = await decrypt(A.encKey, addB.clip.payload);
check('B 解密後與原文相同', roundTrip === secretMsg, JSON.stringify(roundTrip));
check('伺服器傳的是密文（不含明文）', !addB.clip.payload.includes('測試'));
const clipId = addB.clip.id;

console.log('\n4. 拿錯金鑰的人解不開');
const wrong = await deriveKeys(crypto.getRandomValues(new Uint8Array(32)));
check('錯金鑰解密失敗', (await decrypt(wrong.encKey, addB.clip.payload)) === null);

console.log('\n5. 同一組房間代碼、不同金鑰 → 伺服器直接拒絕握手');
let rejected = false;
try { await connect(room, wrong.authToken); } catch { rejected = true; }
check('握手被拒絕', rejected);

console.log('\n6. 改設定（TTL 30 天 + 釘選）會廣播給所有人');
b.send({ type: 'settings', ttlDays: 30, pinned: true });
const setA = await a.wait((m) => m.type === 'settings');
check('A 收到新設定', setA.settings.ttlDays === 30 && setA.settings.pinned === true, JSON.stringify(setA.settings));

console.log('\n7. 刪除單筆');
b.send({ type: 'delete', id: clipId });
const delA = await a.wait((m) => m.type === 'delete');
check('A 收到刪除通知', delA.id === clipId);

console.log('\n8. 內容過長會被擋下');
a.send({ type: 'add', payload: 'x'.repeat(300 * 1024) });
const errA = await a.wait((m) => m.type === 'error');
check('伺服器回報過長', /太長/.test(errA.message), errA.message);

console.log('\n9. 重連後資料還在（DO 持久化）');
const p2 = await encrypt(A.encKey, '重連前寫入的資料');
a.send({ type: 'add', payload: p2 });
await b.wait((m) => m.type === 'add');
a.close(); b.close();
await new Promise((r) => setTimeout(r, 600));
const c = await connect(room, A.authToken);
const initC = await c.wait((m) => m.type === 'init');
check('重連後讀回 1 筆', initC.clips.length === 1, `got ${initC.clips.length}`);
check('內容仍可解密', (await decrypt(A.encKey, initC.clips[0].payload)) === '重連前寫入的資料');
check('設定也保留（釘選 + 30 天）', initC.settings.pinned === true && initC.settings.ttlDays === 30);

console.log('\n10. 清空');
c.send({ type: 'clear' });
await new Promise((r) => setTimeout(r, 400));
c.close();
const d = await connect(room, A.authToken);
const initD = await d.wait((m) => m.type === 'init');
check('清空後為 0 筆', initD.clips.length === 0);
d.close();

console.log(`\n────────────\n通過 ${pass} 項，失敗 ${fail} 項\n`);
process.exit(fail ? 1 : 0);
