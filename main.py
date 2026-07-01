import io
import csv
import os
import uuid
import zipfile
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

import qrcode
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Alumni Entry Management")

DATA_DIR = Path(os.environ.get("DATA_DIR", "."))
DB_PATH  = str(DATA_DIR / "alumni.db")
QR_DIR   = DATA_DIR / "qr_codes"
QR_DIR.mkdir(parents=True, exist_ok=True)


# ── Database ──────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS participants (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            phone       TEXT,
            email       TEXT,
            token       TEXT    UNIQUE NOT NULL,
            qr_sent     INTEGER DEFAULT 0,
            entered     INTEGER DEFAULT 0,
            entered_at  TEXT,
            created_at  TEXT    DEFAULT (datetime('now','localtime'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entry_log (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            participant_id   INTEGER,
            participant_name TEXT,
            status           TEXT,
            scanned_at       TEXT DEFAULT (datetime('now','localtime'))
        )
    """)
    conn.commit()
    conn.close()


init_db()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── QR generation ─────────────────────────────────────────────────────────────

def qr_path_for(pid: int, name: str) -> Path:
    safe_name = name.replace(" ", "_").replace("/", "_")
    return QR_DIR / f"{pid}_{safe_name}.png"


def make_qr(token: str, pid: int, name: str) -> Path:
    path = qr_path_for(pid, name)
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(token)
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(str(path))
    return path


# ── Models ────────────────────────────────────────────────────────────────────

class ParticipantIn(BaseModel):
    name: str
    phone: Optional[str] = None
    email: Optional[str] = None


class MarkSentBody(BaseModel):
    sent: bool


class ScanBody(BaseModel):
    token: str


# ── API routes ────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def get_stats():
    conn = get_db()
    total    = conn.execute("SELECT COUNT(*) FROM participants").fetchone()[0]
    entered  = conn.execute("SELECT COUNT(*) FROM participants WHERE entered=1").fetchone()[0]
    qr_sent  = conn.execute("SELECT COUNT(*) FROM participants WHERE qr_sent=1").fetchone()[0]
    log_rows = conn.execute(
        "SELECT * FROM entry_log ORDER BY scanned_at DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return {
        "total": total,
        "entered": entered,
        "not_entered": total - entered,
        "qr_sent": qr_sent,
        "recent_log": [dict(r) for r in log_rows],
    }


@app.get("/api/participants")
def list_participants():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM participants ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/participants", status_code=201)
def add_participant(p: ParticipantIn):
    token = str(uuid.uuid4())
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO participants (name, phone, email, token) VALUES (?,?,?,?)",
            (p.name.strip(), (p.phone or "").strip(), (p.email or "").strip(), token),
        )
        pid = cur.lastrowid
        conn.commit()
        make_qr(token, pid, p.name.strip())
        return {"id": pid, "name": p.name, "token": token}
    except sqlite3.IntegrityError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()


@app.post("/api/participants/bulk")
async def bulk_import(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8-sig").splitlines()
    reader  = csv.DictReader(content)
    added, errors = 0, []
    conn = get_db()
    for row in reader:
        name = (row.get("name") or "").strip()
        if not name:
            continue
        token = str(uuid.uuid4())
        try:
            cur = conn.execute(
                "INSERT INTO participants (name, phone, email, token) VALUES (?,?,?,?)",
                (name, (row.get("phone") or "").strip(), (row.get("email") or "").strip(), token),
            )
            pid = cur.lastrowid
            conn.commit()
            make_qr(token, pid, name)
            added += 1
        except Exception as e:
            errors.append(f"{name}: {e}")
    conn.close()
    return {"added": added, "errors": errors}


@app.get("/api/participants/{pid}/qr")
def download_qr(pid: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM participants WHERE id=?", (pid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Participant not found")
    path = qr_path_for(pid, row["name"])
    if not path.exists():
        make_qr(row["token"], pid, row["name"])
    safe_name = row["name"].replace(" ", "_")
    return FileResponse(str(path), media_type="image/png", filename=f"{safe_name}_QR.png")


@app.get("/api/qr/download-all")
def download_all_qr():
    conn = get_db()
    rows = conn.execute("SELECT id, name FROM participants").fetchall()
    conn.close()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for row in rows:
            path = qr_path_for(row["id"], row["name"])
            if path.exists():
                zf.write(str(path), f"{row['name']}_QR.png")
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=alumni_qr_codes.zip"},
    )


@app.put("/api/participants/{pid}/sent")
def mark_sent(pid: int, body: MarkSentBody):
    conn = get_db()
    conn.execute("UPDATE participants SET qr_sent=? WHERE id=?", (1 if body.sent else 0, pid))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/participants/{pid}")
def delete_participant(pid: int):
    conn = get_db()
    row = conn.execute("SELECT name FROM participants WHERE id=?", (pid,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    conn.execute("DELETE FROM participants WHERE id=?", (pid,))
    conn.commit()
    conn.close()
    path = qr_path_for(pid, row["name"])
    if path.exists():
        path.unlink()
    return {"ok": True}


@app.post("/api/scan")
def scan_qr(body: ScanBody):
    token = body.token.strip()
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM participants WHERE token=?", (token,)
        ).fetchone()

        if not row:
            conn.execute(
                "INSERT INTO entry_log (participant_name, status) VALUES (?,?)",
                ("Unknown", "invalid"),
            )
            conn.commit()
            return {"status": "invalid", "message": "QR code not recognised"}

        if row["entered"]:
            conn.execute(
                "INSERT INTO entry_log (participant_id, participant_name, status) VALUES (?,?,?)",
                (row["id"], row["name"], "already_entered"),
            )
            conn.commit()
            return {
                "status": "already_entered",
                "name": row["name"],
                "message": f"Already entered at {row['entered_at']}",
            }

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "UPDATE participants SET entered=1, entered_at=? WHERE id=?",
            (now, row["id"]),
        )
        conn.execute(
            "INSERT INTO entry_log (participant_id, participant_name, status) VALUES (?,?,?)",
            (row["id"], row["name"], "valid"),
        )
        conn.commit()
        return {"status": "valid", "name": row["name"], "message": f"Welcome, {row['name']}!"}
    finally:
        conn.close()


# ── Static files & page routes ────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def admin_page():
    return FileResponse("static/admin.html")


@app.get("/scanner")
def scanner_page():
    return FileResponse("static/scanner.html")
