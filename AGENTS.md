# text-sync — 給接手者的說明

跨裝置加密剪貼簿。一台裝置貼上文字，其他開著同一個房間的裝置立刻收到。
跑在 Cloudflare Workers + Durable Objects，免費方案就夠。

- 線上：https://text-sync.j755007.workers.dev
- 程式碼：`~/projects/text-sync`（本機 + git）
- 規格與決策紀錄：`Dropbox/Agent/100_Todo/projects/text_sync/PRD.md`

> 為什麼分兩處：Dropbox 同步 `.git/` 內部檔案可能損壞倉庫，所以程式碼放本機，
> Dropbox 只放文件與截圖。這是全域規則，不要把 repo 搬進 Dropbox。

沒有框架、沒有 build step、沒有 runtime 相依套件。全部約 1,900 行。
註解與 commit message 用繁體中文。

---

## 最重要的事：安全模型

**不變式：伺服器（Cloudflare）永遠不該拿到明文，也不該拿到任何能反推金鑰的東西。**
動到 `crypto` 相關的程式碼前，先確認你的改動沒有破壞下面任何一條。

### 房間金鑰

網址：`https://<網域>/r/<房間代碼>#k=<secret>`

`#` 後面的 fragment **瀏覽器不會送出**，所以 secret 只存在使用者的瀏覽器裡。
從它用 HKDF 衍生兩把（`public/app.js` 的 `deriveKeys`）：

| 衍生物 | info 字串 | 用途 | 伺服器看得到嗎 |
| --- | --- | --- | --- |
| `encKey` | `text-sync:enc:v1` | AES-GCM 加解密剪貼內容 | ❌ |
| `authToken` | `text-sync:auth:v1` | 證明「我知道 secret」 | ✅ 但只存 SHA-256 |

伺服器（`RoomDO.fetch`）拿 `authToken` 的 SHA-256 跟 `meta.auth_hash` 比對。
房間**先到先得**：第一個帶金鑰進來的人寫入 `auth_hash`，之後對不上的直接回 403，
連 WebSocket 握手都完成不了。比對用 `timingSafeEqual`。

`authToken` 走 `Sec-WebSocket-Protocol` 標頭而不是 query string——query 會進存取日誌。
伺服器必須把同一個值回 echo 回去，否則瀏覽器會拒絕這個連線。

### 配對碼

讓第二台電腦不必手打 43 字的金鑰。`public/app.js` 的 `derivePairKeys`：

```
配對碼（8 碼，40 bits）
   └─ PBKDF2-SHA256, salt="text-sync:pair:v1", 300,000 次 ─→ master (256 bits)
        ├─ HKDF info="text-sync:pair:slot:v1" ─→ slotId（給伺服器當暫存格位置）
        └─ HKDF info="text-sync:pair:enc:v1"  ─→ encKey（加密房間網址）
```

**為什麼 slotId 也要掛在 PBKDF2 後面**：如果 slotId 只是 `SHA-256(配對碼)`，
握有資料的一方可以用 2^40 次便宜雜湊反推配對碼，再算出 encKey 解開密文。
兩個輸出都掛在同一次慢雜湊之後，暴力成本變成 2^40 × 300,000 次，不可行。
**改這段時不要為了加速把 slotId 拆出來單獨雜湊。**

字母表 `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` 刻意去掉 `0`、`1`、`I`、`O`，
剛好 32 個字元，每碼 5 bits。`randomPairCode()` 用 `byte % 32`——因為 256 是 32 的
整數倍，這樣才是均勻分布。換字母表長度時要重新檢查這件事。

暫存格是**一次性**的：`PairDO` 在 GET 時無論成功與否都 `deleteAll()`，90 秒後 alarm 也會清。

---

## 架構

```
src/index.js       Worker 路由 + RoomDO（房間）+ PairDO（配對暫存格）
public/index.html  單頁前端（首頁 + 房間 + 兩個彈窗）
public/app.js      加解密、WebSocket client、所有 UI 行為
public/style.css   樣式（深色／淺色由 tokens 切換）
public/vendor/     qrcode.min.js（本機化，執行時不打任何 CDN）
test/e2e.mjs       端對端測試（25 項）
wrangler.jsonc     Worker 設定
```

路由（`run_worker_first: ["/api/*"]`，其餘交給 Static Assets）：

| 路徑 | 說明 |
| --- | --- |
| `GET /api/room/<code>/ws` | WebSocket 升級，轉給 `RoomDO` |
| `PUT /api/pair/<slotId>` | 放進配對密文，90 秒後自動銷毀 |
| `GET /api/pair/<slotId>` | 取走配對密文，取完即銷毀 |
| 其他 | Static Assets，`/r/*` 走 SPA fallback |

`slotId` 必須是 64 個十六進位字元，不符一律 404。
房間代碼必須符合 `^[a-z0-9][a-z0-9-]{2,31}$`。

---

## 資料模型

`RoomDO`（SQLite-backed Durable Object，每個房間一個）：

```sql
meta  (k TEXT PRIMARY KEY, v TEXT)          -- auth_hash / pinned / ttl_days / last_seen
clips (id TEXT PRIMARY KEY, payload TEXT,   -- payload 是密文
       created INTEGER, expires INTEGER)
```

`PairDO` 只用 KV 儲存 API：`payload`（密文）、`expires`。

---

## WebSocket 協定

都是 JSON。

| 方向 | 型別 |
| --- | --- |
| client → server | `hello` `add` `delete` `clear` `settings` `typing` `ping` |
| server → client | `init` `add` `delete` `clear` `clips` `settings` `peers` `typing` `error` `pong` |

**`hello` 不能拿掉。** 新的 socket 在 `RoomDO.fetch()` 執行期間還沒進
`ctx.getWebSockets()`，所以那時廣播裝置數會少算一台。client 在 `open` 之後補送
`hello`，伺服器收到才 `broadcastPeers()`。

用的是 WebSocket Hibernation API（`ctx.acceptWebSocket` + `webSocketMessage` /
`webSocketClose`），沒人連線時不計運算時間。**不要把狀態存在 DO 的實例變數上**——
hibernate 之後就沒了。目前唯一的實例變數是 `alarmEnsured`，它就算歸零也只是多查一次。

---

## 自動清理

| 對象 | 規則 | 在哪 |
| --- | --- | --- |
| 每筆內容 | 超過 `expires` 就刪，TTL 可設 1／7／30 天 | `reapExpired()` |
| 筆數 | 超過 200 筆刪最舊的 | `trim()` |
| 整個房間 | 空 + 未釘選 + 閒置 30 天 → `deleteAll()` 且不再排 alarm | `alarm()` |
| 釘選的房間 | 不受閒置回收影響 | `meta.pinned` |

Durable Object 沒有常駐實體，占空間的只有存進去的資料。寫過東西的空房約 12 KB，
免費方案 5 GB。

改 TTL 時會用 `UPDATE clips SET expires = created + ?` 重算既有內容，不是只影響新的。

---

## 開發與測試

```bash
npm install
npm run dev     # http://127.0.0.1:8787
npm test        # 需要 dev server 開著
node test/e2e.mjs https://text-sync.j755007.workers.dev   # 打線上
```

`test/e2e.mjs` 用兩個 WebSocket 模擬兩台裝置，涵蓋：加密往返、錯金鑰解不開、
握手拒絕、設定廣播、刪除、過長擋下、重連持久化、清空、配對碼完整流程。

**測試裡的加解密是刻意重寫一份的**，不是 import `app.js`。這樣改壞前端的推導邏輯時
測試會抓到不一致；如果共用同一份程式碼就抓不到了。動 `deriveKeys` 或
`derivePairKeys` 時，兩邊都要改。

---

## 部署

```bash
npx wrangler deploy
```

憑證是 OAuth，存在**電腦1（wjweng）**的 `~/.config/.wrangler/config/default.toml`。
換一台電腦要先 `npx wrangler login`。

`~/.config/agent/secrets.env` 裡的 `CLOUDFLARE_API_TOKEN` **不能用來部署**——
那顆是 2026-08-09 為 Workers AI 生圖建的，只有 AI 權限，打 `workers/scripts` 會回
`Authentication error`。要用 token 部署得另外建一顆（Workers Scripts Edit +
Workers KV Storage Edit + Account Settings Read）。

`wrangler.jsonc` 的 `migrations` 是**累加**的，已經上線的 tag 不能刪或改，
只能往後加新的 tag。目前 v1 = RoomDO、v2 = PairDO。

---

## 常數在哪、改了會怎樣

`src/index.js`：

| 常數 | 值 | 注意 |
| --- | --- | --- |
| `MAX_PAYLOAD_BYTES` | 256 KB | 密文上限，約對應 180 KB 明文；跟前端 `MAX_CHARS` 要一致 |
| `MAX_CLIPS` | 200 | 每個房間保留筆數 |
| `IDLE_REAP_DAYS` | 30 | 空房回收門檻 |
| `PAIR_TTL_MS` | 90 秒 | 配對碼壽命；調長會拉長暴力猜測的時間窗 |

`public/app.js`：

| 常數 | 值 | 注意 |
| --- | --- | --- |
| `MAX_CHARS` | 180,000 | 明文上限 |
| `PAIR_LEN` | 8 | 每少一碼就少 5 bits |
| `PAIR_ITERATIONS` | 300,000 | 調低會削弱離線暴力的成本。**實測只花 35ms**（Chrome，2026-09-02），還有很大的加碼空間——調到 200 萬次仍在 250ms 以內，而暴力成本會再乘 6.7 倍。配對碼是 90 秒即拋的，改這個數字不會讓任何既有資料失效，只要前後端同時改 |
| `STORE_KEY` | `text-sync.rooms.v1` | 改格式時記得升版號，舊資料才不會炸 |

---

## 踩過的坑（都修好了，別再踩回去）

**`blockConcurrencyWhile` 不 await 是個雷。** 原本 `touch()` 每收一則訊息就開一個
沒人接的 `blockConcurrencyWhile`，等於每則訊息都卡住整個 DO 等兩次儲存往返，
而且它一旦 reject 會直接把 DO 重置。現在改成 `ensureAlarm()`，每個實例只查一次。

**`[hidden]` 會被自帶 display 的規則蓋過。** `.modal { display: flex }` 的優先度高於
瀏覽器預設的 `[hidden] { display: none }`，結果分享彈窗隱形地罩住整頁、按不到底下的
按鈕。`style.css` 頂端有一條 `[hidden] { display: none !important; }` 壓住這件事，
新增自帶 display 的元件時記得它存在。

**只改網址 `#` 片段時瀏覽器不會重載。** 使用者在房間裡貼上另一組金鑰的網址不會有反應，
所以有 `hashchange` 監聽器負責拆掉舊房間再 `boot()`。

**金鑰要等連上才寫 localStorage。** 一進房就寫的話，開到一個壞金鑰的連結會蓋掉
本機存好的正確金鑰——那台裝置就再也進不去了。現在是收到 `init` 才 `store.remember`。

**握手被拒絕時不要無限重連。** 金鑰不符會一直失敗，`giveUp()` 在連續 3 次從未成功
握手後停手並顯示說明。

**驗過「功能會不會動」不等於驗過版面。** 設定原本是行內展開的卡片，展開後底部剛好貼上
文字傳送區的頂部（差 -1px），兩張白卡片視覺上融成一張。現在設定與分享都是彈窗。
**任何會改變版面的互動，事後要看一次整體畫面**，並量相鄰元素的間距。

**彈窗要留看得見的出口。** 手機 390×844 下分享彈窗高 742px，只剩上下各 51px 背景可點，
而那是網址列與 home indicator 的位置。所以有右上角 44×44 的 ×，標題列 sticky
（矮螢幕捲動時不會跟著捲走）。點背景與 Esc 是快捷方式，不是唯一出路。

**電腦1 這台的網路對外很慢**（google.com 平均 829ms、光 TLS 握手 1.1 秒），
表現出來是 WebSocket 握手大約每 5 次掉 1 次 `ETIMEDOUT`。**這不是 Worker 的 bug。**
懷疑線上有問題時先量對照組（google／example.com），再決定要不要追自己的程式。
`test/e2e.mjs` 的 `connectWithRetry` 就是為此存在，真實 client 也有重連退避。

---

## 改東西之前的檢查清單

1. 動到加解密？兩邊（`app.js` 與 `test/e2e.mjs`）都要改，且確認伺服器仍拿不到明文
2. 動到 WebSocket 協定？前後端與測試三處都要同步
3. 動到版面？把每個展開／彈窗狀態都截圖看一次，量相鄰元素間距
4. 新增 Durable Object class？`wrangler.jsonc` 要加新的 migration tag，不要改舊的
5. `npm test` 過了再部署，部署後再打一次線上

---

## 還沒做、可以做的

- **`PAIR_ITERATIONS` 加碼**：目前 300,000 次只花 35ms，加到 200 萬仍在 250ms 內，
  暴力成本再乘 6.7 倍。前後端（`app.js` 與 `test/e2e.mjs`）同時改即可，沒有相容性包袱
- **密碼房間**：金鑰由使用者自訂密碼推導，任何電腦輸入「代碼＋密碼」就能進，
  什麼都不用傳。當初評估後沒做，因為弱密碼可被離線爆破——猜到房間代碼的人可以把
  密文抓回去慢慢試。要做的話得配 Argon2id 與強度檢查
- **自訂網域**：現在是 workers.dev 子網域
- **DO alarm 的實際觸發還沒驗過**（要等真的過一天）
