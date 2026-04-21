# Project Security Gateway
本專案為員工學習平台 L.I.F.E. Pulse 的第 10 個 Mini Project。
建立一個隱私保護中間Gateway在前端應用與主資料庫中間。
所有員工學習行為數據在進入分析資料庫之前，必須先通過 Gateway 進行 PII 偵測與 Tokenization 並分流到三個資料庫。

**核心**：進行資料攔截與匿名化處理，透過 Tokenization 將身份與行為資料分離，並分別存入不同安全等級的資料庫，以符合最小權限原則與個資法規要求。

## 系統架構
```
原始資料（含個資）
        ↓
   [ Gateway ]
   PII (員工個人資料偵測) + Tokenization (Agent ID & Name 匿名化+ Fernet 加密）
        ↓                                ← 分流至三個資料庫
┌──────────────────────────────────────┐
│ 🔴 IdentityVault (identity_vault.db) │  ← 身份對應資料，嚴格限制
│ 🟡 ApiTrafficLogs (API.db)           │  ← API 流量
│ 🟢 TelemetryLogs (telemetry.db)      │  ← 匿名行為數據，分析師可存取
└──────────────────────────────────────┘
```
## 資料結構
```
secure_data_gateway/
├── kgi.py                   # Flask Backend（Gateway API）
├── templates/
│   └── dashboard.html       # UI
├── test.py                  # 模擬前端自動送資料
├── identity_vault.db        # 身份對照庫
├── API.db                   # API 稽核資料庫
├── telemetry.db             # 匿名分析資料庫
├── secret.key               # Fernet 加密金鑰 
├── .gitignore               # 排除 .db 與 .key 檔案
├── requirements.txt
└── README.md
```

## 資料庫設計 (SQLite)

### IdentityVault 
| 欄位 | 說明 |
|------|------|
| token_id | 匿名 UUID（Primary Key）|
| real_agent_id | 真實員工 ID（**Fernet 加密儲存**）|
| real_agent_hash | SHA-256 雜湊（用於查詢比對，不需解密）|
| encryption_key_version | 加密金鑰版本（支援 Key Rotation）|
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
| notes | 自由文字欄位（PII 偵測目標）|
| timestamp | 時間戳記 |

## Dashboard 資安儀表板

提供資安與 DevOps 團隊的高階監控畫面
| Metric | 說明 |
|------|------|
| Total Requests | 總共收到幾筆請求 |
| Clean Requests | 沒有 PII 的乾淨請求數量 |
| PII Detected | 偵測到含有個資的請求數量 |
| Threat Rate | PII 佔總請求的比例（%）|

## Live Traffic Visualiser 即時流量視覺化

每次有新資料進來，畫面會即時更新顯示：
- **左側 Dirty JSON** — 原始資料，包含真實姓名、員工 ID、分數 etc
- **右側 Clean JSON** — 經過 Gateway 處理後的匿名資料，真實身份已被 UUID token 取代

## Threat Alert
當 `notes` 欄位偵測到 PII（Email、手機、身分證），頁面頂部會出現紅色閃爍警示橫幅
這模擬真實系統中的安全警報機制，提醒管理員有個資試圖進入分析資料庫

## PII 偵測範圍

| 類型 | 格式 |
|------|------|
| Email | 包含 @ 且後綴有 .com |
| 台灣手機號碼 | 09 開頭，共 10 位數 |
| 台灣身分證號碼 | 英文字母接 9 個數字 |

## Recent Threat Events

顯示最近 10 筆含有 PII 的請求紀錄，方便資安團隊追蹤異常來源。


## 如何執行

```bash
# 安裝套件
pip3 install flask requests cryptography

# 啟動伺服器（資料庫與金鑰會自動建立）
python3 kgi.py
```

瀏覽器開啟 `http://localhost:8080`

**（選用）啟動自動測試腳本：**

```bash
python3 test.py
```

## 技術選用

| 項目 | 技術 |
|------|------|
| 後端 | Python Flask |
| 資料庫 | SQLite（三個實體分離的 .db 檔案）|
| 前端 | HTML + CSS + JavaScript |
| 加密 | Fernet（AES-128-CBC）|
| PII 偵測 | Rule-based（字元掃描）|