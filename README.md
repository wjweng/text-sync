# text-sync

跨裝置加密剪貼簿。在一台裝置貼上文字，其他開著同一個房間的裝置立刻收到。
部署在 Cloudflare Workers + Durable Objects，免費方案就跑得動。

## 它怎麼保護內容

網址長這樣：

```
https://<你的網域>/r/<房間代碼>#k=<金鑰>
```

- `#` 後面的**金鑰不會送到伺服器**（瀏覽器的規格如此），只留在瀏覽器裡
- 瀏覽器用 HKDF 從金鑰衍生兩把：
  - **加密金鑰** — AES-GCM 加解密，不外流
  - **auth token** — 送給伺服器證明「我知道金鑰」，伺服器只存它的 SHA-256
- 伺服器存的、廣播的都是密文。Cloudflare 那端看不到明文

代價：**弄丟完整網址就永久解不開**，沒有「忘記密碼」。重要的房間請把網址存起來。

## 帶到另一台電腦

手機掃 QR 就好。電腦沒相機，所以有**一次性配對碼**：

1. 已進房的那台按「分享 → 配對這台電腦」，得到 8 碼（例如 `K7M2-9XPQ`）
2. 另一台在首頁輸入這 8 碼，直接進房
3. 90 秒後失效，取用一次也失效

伺服器一樣看不到金鑰。配對碼先經 PBKDF2（30 萬次）算出 master，
再用 HKDF 展開成兩個東西：

| 用途 | 伺服器看得到嗎 |
| --- | --- |
| 暫存格位置（slotId） | ✅ 只看得到這個 |
| 解開暫存格的金鑰 | ❌ 算不出來 |

短碼是 8 碼、32 字元字母表（去掉 0/1/I/O）＝ 40 bits。想暴力猜，得在 90 秒內
試上億次，而且每試一次都要付 30 萬次 PBKDF2。

房間代碼是先到先得：代碼被占用後，金鑰不符的人連 WebSocket 都握不了手。

## 自動清理

| 對象 | 規則 |
| --- | --- |
| 每筆內容 | 到期就刪，預設 7 天（可設 1／7／30 天） |
| 整個房間 | 空房 + 未釘選 + 閒置 30 天 → `storage.deleteAll()`，連 alarm 都停掉 |
| 釘選的房間 | 不受閒置回收影響，只有內容照 TTL 過期 |

Durable Object 沒有常駐實體，占空間的只有存進去的資料。一個寫過東西的空房約 12 KB，
免費方案給 5 GB。

## 開發

```bash
npm install
npm run dev          # http://127.0.0.1:8787
npm test             # 端對端測試，需要 dev server 開著
```

`npm test` 會模擬兩台裝置，驗證加密同步、認證拒絕、設定廣播、刪除、重連持久化、
以及完整的配對碼流程（共 25 項）。

打線上環境：`node test/e2e.mjs https://你的網址`。WebSocket 握手偶爾會因網路
逾時失敗，測試跟真實 client 一樣會自動重試。

## 部署

需要一顆 **Workers Scripts Edit** 權限的 API token（Workers AI 專用的 token 不夠）：

```bash
export CLOUDFLARE_API_TOKEN=...
export CLOUDFLARE_ACCOUNT_ID=...
npm run deploy
```

或用 `npx wrangler login` 走 OAuth。

## 架構

```
src/index.js      Worker 路由 + RoomDO（房間）+ PairDO（一次性配對暫存格）
public/index.html 單頁前端
public/app.js     加解密、WebSocket client、UI
public/style.css  樣式（深色／淺色）
public/vendor/    qrcodejs（本機化，不打 CDN）
test/e2e.mjs      端對端測試
```

WebSocket 訊息協定（都是 JSON）：

| 方向 | 型別 |
| --- | --- |
| client → server | `hello` `add` `delete` `clear` `settings` `typing` `ping` |
| server → client | `init` `add` `delete` `clear` `clips` `settings` `peers` `typing` `error` `pong` |

auth token 走 `Sec-WebSocket-Protocol` 而不是 query string，避免進到存取日誌。

配對用的 HTTP API：

| 方法 | 路徑 | 說明 |
| --- | --- | --- |
| `PUT` | `/api/pair/<slotId>` | 放進密文，90 秒後自動銷毀 |
| `GET` | `/api/pair/<slotId>` | 取走密文，取完即銷毀 |

`slotId` 是 64 個十六進位字元，格式不符一律 404。
