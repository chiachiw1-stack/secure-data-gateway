# 引入需要的工具
from flask import Flask, request, jsonify, render_template
import sqlite3   # 內建的資料庫工具，不需要另外安裝
import uuid      # 用來產生隨機 UUID（匿名 token）
import time      # 用來記錄時間

app = Flask(__name__)  # 建立 Flask 應用程式

# ── 資料庫檔案名稱 ──────────────────────────────────────────
# 兩個不同的 .db 檔案，代表兩個安全等級不同的資料庫
TELEMETRY_DB = "telemetry.db"      # 分析師可以存取（只有匿名 token，沒有個資）
IDENTITY_DB  = "identity_vault.db" # 高度限制（存放真實身份對應關係）

# ── PII 偵測函式 ────────────────────────────────────────────
# PII = 個人可識別資訊（Personal Identifiable Information）
def detect_pii(text):
    """掃描文字裡面有沒有 PII，有的話回傳 True"""
    text = str(text)

    # 檢查是否含有 @ 符號（Email 的特徵）
    if "@" in text:
        return True

    # 檢查每一個字，看有沒有符合手機號碼或身分證格式
    for word in text.split():
        # 台灣手機號碼：09 開頭、10 碼、全部是數字
        if word.startswith("09") and len(word) == 10 and word.isdigit():
            return True
        # 台灣身分證：第一個字是英文、後面 9 碼是數字、總長 10 碼
        if len(word) == 10 and word[0].isalpha() and word[1:].isdigit():
            return True

    return False  # 都沒有偵測到，代表安全

# ── 建立資料庫和資料表 ──────────────────────────────────────
# 程式啟動時自動執行，如果資料表已經存在就跳過
def init_db():
    # 建立 telemetry.db（分析用）
    conn = sqlite3.connect(TELEMETRY_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS TelemetryLogs (
            log_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id   TEXT NOT NULL,  -- 匿名 UUID，不含真實姓名
            quiz_id    TEXT,
            score      INTEGER,
            time_spent INTEGER,
            timestamp  TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ApiTrafficLogs (
            log_id             INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_accessed  TEXT,      -- 哪個 API 被呼叫
            payload_size_bytes INTEGER,   -- 這次請求的資料大小
            pii_detected_flag  INTEGER,   -- 0=安全 / 1=偵測到 PII
            processing_time_ms INTEGER,   -- 處理花了幾毫秒
            timestamp          TEXT
        )
    """)
    conn.commit()
    conn.close()

    # 建立 identity_vault.db（高安全等級）
    conn2 = sqlite3.connect(IDENTITY_DB)
    conn2.execute("""
        CREATE TABLE IF NOT EXISTS IdentityVault (
            token_id               TEXT PRIMARY KEY, -- 匿名 UUID
            real_agent_id          TEXT NOT NULL,    -- 真實員工 ID
            encryption_key_version TEXT DEFAULT 'v1',
            creation_timestamp     TEXT
        )
    """)
    conn2.commit()
    conn2.close()

# ── 首頁：顯示 Dashboard 介面 ───────────────────────────────
@app.route("/")
def dashboard():
    return render_template("dashboard.html")  # 去 templates 資料夾找 dashboard.html

# ── Gateway 核心 API ────────────────────────────────────────
# 這是整個專案的重點！平板 App 把資料 POST 到這裡
@app.route("/api/v1/submit_sprint", methods=["POST"])
def submit_sprint():
    start_time = time.time()
    raw = request.get_json()  # 接收前端傳來的 JSON
    if not raw:
        return jsonify({"error": "沒有收到資料"}), 400

    payload_str   = str(raw)
    pii_found     = detect_pii(payload_str)           # Step 1：掃描 PII
    payload_bytes = len(payload_str.encode("utf-8"))  # 計算資料大小

    # Step 2：Tokenization — 把真實身份換成匿名 UUID
    real_agent_id = raw.get("agent_id") or raw.get("agent_name", "unknown")
    token_id      = str(uuid.uuid4())  # 產生隨機 UUID，例如 a3f2b1c4-...
    now           = time.strftime("%Y-%m-%d %H:%M:%S")

    # Step 3：把真實身份對應關係存入 IdentityVault（高安全等級資料庫）
    conn = sqlite3.connect(IDENTITY_DB)
    conn.execute(
        "INSERT INTO IdentityVault VALUES (?, ?, 'v1', ?)",
        (token_id, real_agent_id, now)
    )
    conn.commit()
    conn.close()

    # Step 4：建立乾淨的匿名資料（完全不含真實身份）
    clean = {
        "token_id":   token_id,
        "quiz_id":    raw.get("quiz_id"),
        "score":      raw.get("score"),
        "time_spent": raw.get("time_spent"),
        "timestamp":  now,
    }

    # Step 5：把匿名資料和 API 紀錄存入 telemetry.db
    elapsed_ms = int((time.time() - start_time) * 1000)
    conn2 = sqlite3.connect(TELEMETRY_DB)
    conn2.execute(
        "INSERT INTO TelemetryLogs (token_id, quiz_id, score, time_spent, timestamp) VALUES (?,?,?,?,?)",
        (token_id, clean["quiz_id"], clean["score"], clean["time_spent"], now)
    )
    conn2.execute(
        "INSERT INTO ApiTrafficLogs (endpoint_accessed, payload_size_bytes, pii_detected_flag, processing_time_ms, timestamp) VALUES (?,?,?,?,?)",
        ("/api/v1/submit_sprint", payload_bytes, int(pii_found), elapsed_ms, now)
    )
    conn2.commit()
    conn2.close()

    # 回傳結果給前端
    return jsonify({
        "status":        "success",
        "token_id":      token_id,
        "pii_detected":  pii_found,
        "clean_payload": clean,
    })

# ── 取得 API 流量日誌（Dashboard 用）───────────────────────
@app.route("/api/logs")
def get_logs():
    conn = sqlite3.connect(TELEMETRY_DB)
    conn.row_factory = sqlite3.Row  # 讓結果可以用欄位名稱存取
    rows = conn.execute(
        "SELECT * FROM ApiTrafficLogs ORDER BY log_id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── 取得匿名行為數據（Dashboard 用）────────────────────────
@app.route("/api/telemetry")
def get_telemetry():
    conn = sqlite3.connect(TELEMETRY_DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM TelemetryLogs ORDER BY log_id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── 取得 IdentityVault（僅供展示）──────────────────────────
@app.route("/api/vault")
def get_vault():
    conn = sqlite3.connect(IDENTITY_DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT rowid, * FROM IdentityVault ORDER BY rowid DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── 啟動程式 ────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()                      # 先建立資料庫
    app.run(debug=True, port=5000) # 啟動伺服器