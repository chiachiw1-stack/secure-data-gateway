# Project Security Gateway
本專案為員工學習平台系列的第 10 個 Mini Project。
一個隱私保護中間層（Gateway），所有學習行為數據在進入分析資料庫之前，必須先通過 Gateway 進行 PII 偵測與 Tokenization。真實員工身份會被替換成匿名 UUID token，確保分析師永遠看不到真實個資，同時仍能進行完整的數據分析。

## 系統架構
```
原始資料（含個資）
        ↓
   [ Gateway ]
   PII (員工個人資料偵測) + Tokenization (Agent ID & Name 匿名化)
        ↓                                ← 分流至三個資料庫
┌──────────────────────────────────────┐
│ 🔴 IdentityVault (identity_vault.db) │  ← 真實身份 ↔ Token 對應，嚴格限制
│ 🟡 ApiTrafficLogs (API.db)           │  ← API 流量
│ 🟢 TelemetryLogs (telemetry.db)      │  ← 匿名行為數據，分析師可存取
└──────────────────────────────────────┘
```

## 資料庫設計 (SQLite)

### IdentityVault 
| 欄位 | 說明 |
|------|------|
| token_id | 匿名 UUID（Primary Key）|
| real_agent_id | 真實員工 ID |
| encryption_key_version | 加密金鑰版本 |
| creation_timestamp | 建立時間 |

### ApiTrafficLogs 
| 欄位 | 說明 |
|------|------|
| log_id | 流水號 |
| endpoint_accessed | 存取的 API 路由 |
| payload_size_bytes | 資料大小 |
| pii_detected_flag | 是否偵測到 PII |
| processing_time_ms | 處理時間 |
| timestamp | 時間戳記 |


### TelemetryLogs 
| 欄位 | 說明 |
|------|------|
| log_id | 流水號 |
| token_id | 匿名 UUID（Foreign Key）|
| module_id | 模組代號 |
| accuracy | 準確率 |
| interaction_speed | 互動速度 |
| personal_information | 自由文字欄位（PII 偵測目標）|
| timestamp | 時間戳記 |

### Dashboard 功能說明
顯示三個即時統計數字提供後台人員管理
- **Total Requests** — 總共收到幾筆資料流入
- **Clean Requests** — 沒有 PII 的乾淨請求數量
- **PII Detected** — 偵測到含有個資的資料數量

### Live Traffic Visualiser
每次有新資料進來，畫面會即時更新顯示：
- **左側 Dirty JSON** — 原始資料，包含真實姓名、員工 ID、分數 etc
- **右側 Clean JSON** — 經過 Gateway 處理後的匿名資料，真實身份已被 UUID token 取代

### Threat Alert
當 `personal_information` 欄位偵測到 PII（Email、手機、身分證），頁面頂部會出現紅色閃爍警示橫幅
這模擬真實系統中的安全警報機制，提醒管理員有個資試圖進入分析資料庫

## PII 偵測範圍

| 類型 | 格式 |
|------|------|
| Email | 包含 @ 且後綴有 .com |
| 台灣手機號碼 | 09 開頭，共 10 位數 |
| 台灣身分證號碼 | 英文字母接 9 個數字 |

## 如何執行

```bash
# 安裝套件
pip3 install flask requests

# 啟動伺服器
python3 kgi.py
```
瀏覽器開啟 `http://localhost:8080`

## 技術選用

| 項目 | 技術 |
|------|------|
| 後端 | Python Flask |
| 資料庫 | SQLite（三個實體分離的 .db 檔案）|
| 前端 | HTML + CSS + JavaScript |