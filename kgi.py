from flask import Flask, request, jsonify, render_template
import sqlite3
import uuid
import time
import hashlib
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)  # 建立 Flask 應用程式

# =========================
# 資料庫檔案設定
# 三個實體分離的 .db 對應三個安全等級
# =========================
TELEMETRY_DB = "telemetry.db"      # 分析師可存取（匿名資料）
API_DB       = "API.db"            # 資安團隊（API 稽核日誌）
IDENTITY_DB  = "identity_vault.db" # 嚴格限制（真實身份對應）
KEY_FILE     = "secret.key"        # Fernet 金鑰檔案

# =========================
# 金鑰管理
# 第一次執行時自動產生並儲存金鑰
# 之後每次啟動從檔案讀取，確保資料可以持續解密
# 正式環境不建議自動產生 key，應改用環境變數或 secret manager。
# =========================
def load_or_create_key():
    try:
        with open(KEY_FILE, "rb") as f:
            return f.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

cipher = Fernet(load_or_create_key())

def encrypt_id(text: str) -> str:
    """加密真實身份，存入資料庫"""
    return cipher.encrypt(text.encode()).decode()

def decrypt_id(token: str) -> str:
    """解密，供 Dashboard 展示用"""
    return cipher.decrypt(token.encode()).decode()

def hash_id(text: str) -> str:
    """SHA-256 雜湊，用於查詢比對"""
    return hashlib.sha256(text.encode()).hexdigest()

# =========================
# PII 偵測函式
# 可檢測 Email / 手機 / 身分證
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
    conn_identity = sqlite3.connect(IDENTITY_DB)
    conn_api      = sqlite3.connect(API_DB)
    conn_tele     = sqlite3.connect(TELEMETRY_DB)

    # IdentityVault：存真實身份與 token 對照
    conn_identity.execute("""
        CREATE TABLE IF NOT EXISTS IdentityVault (
            token_id               TEXT PRIMARY KEY,
            real_agent_id          TEXT NOT NULL,
            real_agent_hash        TEXT NOT NULL,
            encryption_key_version TEXT DEFAULT 'v1',
            creation_timestamp     TEXT
        )
    """)

    # ApiTrafficLogs：存 API 呼叫與風險紀錄
    conn_api.execute("""
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
    conn_tele.execute("""
        CREATE TABLE IF NOT EXISTS TelemetryLogs (
            log_id            INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id          TEXT NOT NULL,
            module_id         TEXT,
            accuracy          INTEGER,
            interaction_speed INTEGER,
            notes             TEXT,
            timestamp         TEXT,
            FOREIGN KEY (token_id) REFERENCES IdentityVault(token_id)
        )
    """)

    conn_identity.commit()
    conn_api.commit()
    conn_tele.commit()

    conn_identity.close()
    conn_api.close()
    conn_tele.close()

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
    raw = request.get_json(silent=True)

    # 基本防呆：若沒有 JSON，直接回錯誤
    if not raw:
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

    payload_str   = str(raw)
    payload_bytes = len(payload_str.encode("utf-8"))
    now           = time.strftime("%Y-%m-%d %H:%M:%S")

    # 從 notes 欄位檢查是否含有 PII
    pii_found = detect_pii(raw.get("notes", ""))

    # 找出真實身份
    real_agent_id = raw.get("agent_id") or raw.get("agent_name", "unknown")

    # =========================
    # Step 1：查詢或建立 token_id
    # 同一個人固定對應同一個 token
    # =========================
    conn_identity = sqlite3.connect(IDENTITY_DB)

    existing = conn_identity.execute(
        "SELECT token_id FROM IdentityVault WHERE real_agent_hash = ?",
        (hash_id(real_agent_id),)
    ).fetchone()

    if existing:
      token_id = existing[0]
    else:
      token_id = str(uuid.uuid4())
      conn_identity.execute(
          "INSERT INTO IdentityVault VALUES (?, ?, ?, 'v1', ?)",
          (token_id, encrypt_id(real_agent_id), hash_id(real_agent_id), now)
      )
      conn_identity.commit()

    conn_identity.close()

    # =========================
    # Step 2：建立 clean payload
    # 若 notes 含有 PII，則用 [BLOCKED] Masking
    # =========================
    clean = {
        "token_id": token_id,
        "module_id": raw.get("module_id"),
        "accuracy": raw.get("accuracy"),
        "interaction_speed": raw.get("interaction_speed"),
        "timestamp": now,
        "notes": "[BLOCKED]" if pii_found else raw.get("notes", "")
    }

    # 儲存最新一筆 dirty / clean，給 dashboard 即時顯示
    global latest
    latest = {
        "dirty": raw,
        "clean": clean,
        "pii_detected": pii_found
    }

    elapsed_ms = int((time.time() - start_time) * 1000)

    # =========================
    # Step 3：寫入 ApiTrafficLogs（API.db）
    # =========================
    conn_api = sqlite3.connect(API_DB)
    conn_api.execute(
        """
        INSERT INTO ApiTrafficLogs
        (endpoint_accessed, payload_size_bytes, pii_detected_flag, processing_time_ms, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        ("/api/v1/submit_sprint", payload_bytes, int(pii_found), elapsed_ms, now)
    )
    conn_api.commit()
    conn_api.close()

    # =========================
    # Step 4：寫入 TelemetryLogs（telemetry.db）
    # =========================
    conn_tele = sqlite3.connect(TELEMETRY_DB)
    conn_tele.execute(
        """
        INSERT INTO TelemetryLogs
        (token_id, module_id, accuracy, interaction_speed, notes, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            token_id,
            clean["module_id"],
            clean["accuracy"],
            clean["interaction_speed"],
            clean["notes"],
            now
        )
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
    try:
        conn = sqlite3.connect(API_DB)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM ApiTrafficLogs ORDER BY log_id DESC LIMIT 20"
        ).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": "Failed to load API logs", "detail": str(e)}), 500

# =========================
# 取得 TelemetryLogs
# =========================
@app.route("/api/telemetry")
def get_telemetry():
    try:
        conn = sqlite3.connect(TELEMETRY_DB)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM TelemetryLogs ORDER BY log_id DESC LIMIT 20"
        ).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": "Failed to load telemetry logs", "detail": str(e)}), 500

# =========================
# 取得 IdentityVault
# 真實系統中這個 API 應受權限控管
#
# 這裡加入解密例外處理
# 若某筆資料因 key 不一致或 token 損壞而無法解密
# API 不應整體 500，應標示該筆資料解密失敗
# =========================
@app.route("/api/vault")
def get_vault():
    try:
        conn = sqlite3.connect(IDENTITY_DB)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM IdentityVault ORDER BY rowid DESC LIMIT 20"
        ).fetchall()
        conn.close()

        result = []

        for r in rows:
            d = dict(r)

            try:
                d["real_agent_id"] = decrypt_id(d["real_agent_id"])
                d["decryption_status"] = "ok"
            except InvalidToken:
                d["real_agent_id"] = "[DECRYPTION FAILED]"
                d["decryption_status"] = "invalid_token"
            except Exception as e:
                d["real_agent_id"] = "[DECRYPTION FAILED]"
                d["decryption_status"] = f"error: {str(e)}"

            result.append(d)

        return jsonify(result)

    except Exception as e:
        # 就算整支 API 爆掉，也強制回 JSON，避免前端收到 HTML
        return jsonify({"error": "Failed to load identity vault", "detail": str(e)}), 500

# =========================
# 取得最近一筆 dirty / clean payload
# =========================
latest = {}

@app.route("/api/recent")
def get_recent():
    return jsonify(latest)

# =========================
# Summary API
# 給 dashboard insight
# =========================
@app.route("/api/summary")
def get_summary():
    try:
        conn_api = sqlite3.connect(API_DB)
        conn_api.row_factory = sqlite3.Row
        logs = conn_api.execute(
            "SELECT * FROM ApiTrafficLogs ORDER BY log_id DESC"
        ).fetchall()
        conn_api.close()

        total_requests = len(logs)
        threat_count   = sum(1 for r in logs if r["pii_detected_flag"] == 1)
        clean_count    = total_requests - threat_count

        avg_processing = round(
            sum(r["processing_time_ms"] for r in logs) / total_requests, 2
        ) if total_requests > 0 else 0

        threat_rate = round(
            (threat_count / total_requests) * 100, 2
        ) if total_requests > 0 else 0

        return jsonify({
            "total_requests": total_requests,
            "clean_requests": clean_count,
            "threat_count": threat_count,
            "threat_rate": threat_rate,
            "avg_processing_time_ms": avg_processing,
        })
    except Exception as e:
        return jsonify({"error": "Failed to load summary", "detail": str(e)}), 500

# =========================
# 最近威脅事件 API
# 取最近有偵測到 PII 的紀錄
# =========================
@app.route("/api/threats")
def get_threats():
    try:
        conn = sqlite3.connect(API_DB)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT * FROM ApiTrafficLogs
            WHERE pii_detected_flag = 1
            ORDER BY log_id DESC
            LIMIT 10
            """
        ).fetchall()
        conn.close()

        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": "Failed to load threats", "detail": str(e)}), 500

# =========================
# 啟動程式
# =========================
if __name__ == "__main__":
    create_db()
    app.run(debug=True, port=8080)