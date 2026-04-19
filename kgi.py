from flask import Flask, request, jsonify, render_template
import sqlite3  
import uuid  
import time     



app = Flask(__name__)  # 建立 Flask 應用程式

# 資料庫檔案
TELEMETRY_DB = "telemetry.db"     
API_DB     = "API.db"
IDENTITY_DB  = "identity_vault.db" 

# PII 
def detect_pii(text):
    text = str(text)

    # 檢查是否含有 @ 符號（Email）
    if '@' in text and '.com' in text.split('@')[-1]:
        return True

    # 把所有連續數字找出來
    digits = ''
    for char in text:
        if char.isdigit():
            digits += char
        else:
            # 檢查累積的數字片段
            if digits.startswith('09') and len(digits) == 10:
                return True
            digits = ''
    if digits.startswith('09') and len(digits) == 10:
        return True

    # 身分證：找「一個英文字母接著9個數字」的組合
    result = ''
    for i in range(len(text) - 9):
        if text[i].isalpha() and text[i+1:i+10].isdigit() and len(text[i+1:i+10]) == 9:
            return True
    return False

# 建立資料庫和資料表
def create_db():
    # 建立 identity_vault.db
    conn = sqlite3.connect(IDENTITY_DB)
    # 建立 api.db
    conn2 = sqlite3.connect(API_DB)
    # 建立 telemetry.db
    conn3 = sqlite3.connect(TELEMETRY_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS IdentityVault (
            token_id               TEXT PRIMARY KEY, -- 匿名 UUID
            real_agent_id          TEXT NOT NULL,    -- 真實員工 ID
            encryption_key_version TEXT DEFAULT 'v1',
            creation_timestamp     TEXT
        )
    """)
    # 建立 ApiTrafficlogs.db
    conn2.execute("""
        CREATE TABLE IF NOT EXISTS ApiTrafficLogs (
            log_id             INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_accessed  TEXT,      
            payload_size_bytes INTEGER,   -- 資料大小
            pii_detected_flag  INTEGER,   -- 0=安全 / 1=偵測到 PII
            processing_time_ms INTEGER,   -- 處理花了幾毫秒
            timestamp          TEXT
        )
    """)
    #建立Telemetrylogs.db
    conn3.execute("""
    CREATE TABLE IF NOT EXISTS TelemetryLogs (
            log_id            INTEGER PRIMARY KEY AUTOINCREMENT, 
            token_id          TEXT NOT NULL,
            module_id         INTEGER,
            accuracy          INTEGER,
            interaction_speed INTEGER,
            personal_information TEXT,  
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

#首頁：顯示 Dashboard 介面
@app.route("/")
def dashboard():
    return render_template("dashboard.html")  # 去 templates 資料夾找 dashboard.html

# Gateway API
@app.route("/api/v1/submit_sprint", methods=["POST"])
def submit_sprint():
    start_time = time.time()
    raw = request.get_json()  # 接收前端傳來的 JSON
    payload_str   = str(raw) 
    pii_found = detect_pii(raw.get("personal_information", "")) # 檢測PII
    payload_bytes = len(payload_str.encode("utf-8"))  # 計算資料大小

    # 查詢或建立 token_id
    real_agent_id = raw.get("agent_id") or raw.get("agent_name", "unknown")
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(IDENTITY_DB)
    existing = conn.execute(
        "SELECT token_id FROM IdentityVault WHERE real_agent_id = ?",
        (real_agent_id,)
    ).fetchone()

    # 已有tokenid
    if existing:
        token_id = existing[0]
    # 新員工資料
    else:
        token_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO IdentityVault VALUES (?, ?, 'v1', ?)",
            (token_id, real_agent_id, now)
        )
        conn.commit()
    conn.close()

    #  先建立 clean payload
    clean = {
        "token_id": token_id,
        "module_id": raw.get("module_id"),
        "accuracy": raw.get("accuracy"),
        "interaction_speed": raw.get("interaction_speed"),
        "timestamp": now,
    }

    #  PII masking
    if pii_found:
        clean["personal_information"] = "[BLOCKED]"
    else:
        clean["personal_information"] = raw.get("personal_information", "")
        
    global latest
    latest = {
        "dirty": raw,
        "clean": clean,
        "pii_detected": pii_found
    }

    elapsed_ms = int((time.time() - start_time) * 1000)

    # 寫入 ApiTrafficLogs → API.db
    conn_api = sqlite3.connect(API_DB)
    conn_api.execute(
        "INSERT INTO ApiTrafficLogs (endpoint_accessed, payload_size_bytes, pii_detected_flag, processing_time_ms, timestamp) VALUES (?,?,?,?,?)",
        ("/api/v1/submit_sprint", payload_bytes, int(pii_found), elapsed_ms, now)
    )
    conn_api.commit()
    conn_api.close()
    
    # 寫入 TelemetryLogs → telemetry.db
    conn_tele = sqlite3.connect(TELEMETRY_DB)
    conn_tele.execute(
        "INSERT INTO TelemetryLogs (token_id, module_id, accuracy, interaction_speed, personal_information, timestamp) VALUES (?,?,?,?,?,?)",
        (token_id, clean["module_id"], clean["accuracy"], clean["interaction_speed"], clean["personal_information"], now)
    )
    conn_tele.commit()
    conn_tele.close()

    # 回傳結果給前端
    return jsonify({
        "status":        "success",
        "token_id":      token_id,
        "pii_detected":  pii_found,
        "clean_payload": clean,
    })

#取得 API
@app.route("/api/logs")
def get_logs():
    conn = sqlite3.connect(API_DB)
    conn.row_factory = sqlite3.Row  # 讓結果可以用欄位名稱存取
    rows = conn.execute(
        "SELECT * FROM ApiTrafficLogs ORDER BY log_id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

#取得telemery
@app.route("/api/telemetry")
def get_telemetry():
    conn = sqlite3.connect(TELEMETRY_DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM TelemetryLogs ORDER BY log_id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

#取得 IdentityVault
@app.route("/api/vault")
def get_vault():
    conn = sqlite3.connect(IDENTITY_DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM IdentityVault ORDER BY rowid DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

latest = {}
@app.route("/api/recent")
def get_recent():
    return jsonify(latest)

#啟動程式
if __name__ == "__main__":
    create_db()                    
    app.run(debug=True, port=8080)