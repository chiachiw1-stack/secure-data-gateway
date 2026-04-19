from flask import Flask, request, jsonify, render_template
import sqlite3
import uuid
import time

app = Flask(__name__)  # 建立 Flask 應用程式

# =========================
# 資料庫檔案設定
# =========================
TELEMETRY_DB = "telemetry.db"
API_DB = "API.db"
IDENTITY_DB = "identity_vault.db"

# =========================
# PII 偵測函式
# =========================
def detect_pii(text):
    text = str(text)

    # 檢查 Email
    if '@' in text and '.com' in text.split('@')[-1]:
        return True

    # 檢查手機號碼：09 開頭共 10 碼
    digits = ''
    for char in text:
        if char.isdigit():
            digits += char
        else:
            if digits.startswith('09') and len(digits) == 10:
                return True
            digits = ''
    if digits.startswith('09') and len(digits) == 10:
        return True

    # 檢查台灣身分證：1 個英文字母 + 9 個數字
    for i in range(len(text) - 9):
        if text[i].isalpha() and text[i+1:i+10].isdigit() and len(text[i+1:i+10]) == 9:
            return True

    return False

# =========================
# 建立資料庫與資料表
# =========================
def create_db():
    conn = sqlite3.connect(IDENTITY_DB)
    conn2 = sqlite3.connect(API_DB)
    conn3 = sqlite3.connect(TELEMETRY_DB)

    # IdentityVault：存真實身份與 token 對照
    conn.execute("""
        CREATE TABLE IF NOT EXISTS IdentityVault (
            token_id               TEXT PRIMARY KEY,
            real_agent_id          TEXT NOT NULL,
            encryption_key_version TEXT DEFAULT 'v1',
            creation_timestamp     TEXT
        )
    """)

    # ApiTrafficLogs：存 API 呼叫與風險紀錄
    conn2.execute("""
        CREATE TABLE IF NOT EXISTS ApiTrafficLogs (
            log_id             INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_accessed  TEXT,
            payload_size_bytes INTEGER,
            pii_detected_flag  INTEGER,
            processing_time_ms INTEGER,
            timestamp          TEXT
        )
    """)

    # TelemetryLogs：匿名化後的分析資料
    # notes 欄位為一般備註欄，若有 PII 則改為 [BLOCKED]
    conn3.execute("""
        CREATE TABLE IF NOT EXISTS TelemetryLogs (
            log_id            INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id          TEXT NOT NULL,
            module_id         INTEGER,
            accuracy          INTEGER,
            interaction_speed INTEGER,
            notes             TEXT,
            timestamp         TEXT,
            FOREIGN KEY (token_id) REFERENCES IdentityVault(token_id)
        )
    """)

    conn.commit()
    conn.close()

    conn2.commit()
    conn2.close()

    conn3.commit()
    conn3.close()

# =========================
# 首頁：顯示 dashboard.html
# =========================
@app.route("/")
def dashboard():
    return render_template("dashboard.html")

# =========================
# Gateway API
# 接收前端資料 → 檢查 PII → Tokenization → 分流寫入三個 DB
# =========================
@app.route("/api/v1/submit_sprint", methods=["POST"])
def submit_sprint():
    start_time = time.time()
    raw = request.get_json()

    # 基本防呆：若沒有 JSON，直接回錯誤
    if not raw:
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

    payload_str = str(raw)
    payload_bytes = len(payload_str.encode("utf-8"))
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    # 從 notes 欄位檢查是否含有 PII
    pii_found = detect_pii(raw.get("notes", ""))

    # 找出真實身份（優先 agent_id）
    real_agent_id = raw.get("agent_id") or raw.get("agent_name", "unknown")

    # =========================
    # Step 1：查詢或建立 token_id
    # 同一個人固定對應同一個 token，方便後續分析
    # =========================
    conn = sqlite3.connect(IDENTITY_DB)
    existing = conn.execute(
        "SELECT token_id FROM IdentityVault WHERE real_agent_id = ?",
        (real_agent_id,)
    ).fetchone()

    if existing:
        token_id = existing[0]
    else:
        token_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO IdentityVault VALUES (?, ?, 'v1', ?)",
            (token_id, real_agent_id, now)
        )
        conn.commit()
    conn.close()

    # =========================
    # Step 2：建立 clean payload
    # 若 notes 含有 PII，則用 [BLOCKED] 遮罩
    # =========================
    clean = {
        "token_id": token_id,
        "module_id": raw.get("module_id"),
        "accuracy": raw.get("accuracy"),
        "interaction_speed": raw.get("interaction_speed"),
        "timestamp": now,
    }

    if pii_found:
        clean["notes"] = "[BLOCKED]"
    else:
        clean["notes"] = raw.get("notes", "")

    # 儲存最新一筆 dirty / clean，給 dashboard 即時顯示
    global latest
    latest = {
        "dirty": raw,
        "clean": clean,
        "pii_detected": pii_found
    }

    elapsed_ms = int((time.time() - start_time) * 1000)

    # =========================
    # Step 3：寫入 ApiTrafficLogs
    # =========================
    conn_api = sqlite3.connect(API_DB)
    conn_api.execute(
        """
        INSERT INTO ApiTrafficLogs
        (endpoint_accessed, payload_size_bytes, pii_detected_flag, processing_time_ms, timestamp)
        VALUES (?,?,?,?,?)
        """,
        ("/api/v1/submit_sprint", payload_bytes, int(pii_found), elapsed_ms, now)
    )
    conn_api.commit()
    conn_api.close()

    # =========================
    # Step 4：寫入 TelemetryLogs
    # =========================
    conn_tele = sqlite3.connect(TELEMETRY_DB)
    conn_tele.execute(
        """
        INSERT INTO TelemetryLogs
        (token_id, module_id, accuracy, interaction_speed, notes, timestamp)
        VALUES (?,?,?,?,?,?)
        """,
        (token_id, clean["module_id"], clean["accuracy"], clean["interaction_speed"], clean["notes"], now)
    )
    conn_tele.commit()
    conn_tele.close()

    # 回傳給前端
    return jsonify({
        "status": "success",
        "token_id": token_id,
        "pii_detected": pii_found,
        "clean_payload": clean,
    })

# =========================
# 取得 API Logs
# =========================
@app.route("/api/logs")
def get_logs():
    conn = sqlite3.connect(API_DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM ApiTrafficLogs ORDER BY log_id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# =========================
# 取得 TelemetryLogs
# =========================
@app.route("/api/telemetry")
def get_telemetry():
    conn = sqlite3.connect(TELEMETRY_DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM TelemetryLogs ORDER BY log_id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# =========================
# 取得 IdentityVault
# =========================
@app.route("/api/vault")
def get_vault():
    conn = sqlite3.connect(IDENTITY_DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM IdentityVault ORDER BY rowid DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# =========================
# 取得最近一筆 dirty / clean payload
# =========================
latest = {}

@app.route("/api/recent")
def get_recent():
    return jsonify(latest)

# =========================
# 給 dashboard 顯示更多 insight
# =========================
@app.route("/api/summary")
def get_summary():
    # 讀取 API logs
    conn_api = sqlite3.connect(API_DB)
    conn_api.row_factory = sqlite3.Row
    logs = conn_api.execute(
        "SELECT * FROM ApiTrafficLogs ORDER BY log_id DESC"
    ).fetchall()
    conn_api.close()

    # 讀取 telemetry
    conn_tele = sqlite3.connect(TELEMETRY_DB)
    conn_tele.row_factory = sqlite3.Row
    tele_rows = conn_tele.execute(
        "SELECT * FROM TelemetryLogs ORDER BY log_id DESC"
    ).fetchall()
    conn_tele.close()

    # 讀取 vault
    conn_vault = sqlite3.connect(IDENTITY_DB)
    conn_vault.row_factory = sqlite3.Row
    vault_rows = conn_vault.execute(
        "SELECT * FROM IdentityVault ORDER BY rowid DESC"
    ).fetchall()
    conn_vault.close()

    total_requests = len(logs)
    threat_count = sum(1 for r in logs if r["pii_detected_flag"] == 1)
    clean_count = total_requests - threat_count
    avg_processing = round(
        sum(r["processing_time_ms"] for r in logs) / total_requests, 2
    ) if total_requests > 0 else 0

    threat_rate = round((threat_count / total_requests) * 100, 2) if total_requests > 0 else 0

    return jsonify({
        "total_requests": total_requests,
        "clean_requests": clean_count,
        "threat_count": threat_count,
        "threat_rate": threat_rate,
        "avg_processing_time_ms": avg_processing,
    })

# =========================
# 新增：最近威脅事件 API
# =========================
@app.route("/api/threats")
def get_threats():
    conn = sqlite3.connect(API_DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT *
        FROM ApiTrafficLogs
        WHERE pii_detected_flag = 1
        ORDER BY log_id DESC
        LIMIT 10
        """
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# =========================
# 啟動程式
# =========================
if __name__ == "__main__":
    create_db()
    app.run(debug=True, port=8080)