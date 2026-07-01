import io
import csv
import os
import secrets
import uuid
import zipfile
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

import hashlib
import hmac

import qrcode
from itsdangerous import URLSafeTimedSerializer, BadData
from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile, File, status
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Alumni Entry Management")

DATA_DIR = Path(os.environ.get("DATA_DIR", "."))
DB_PATH  = str(DATA_DIR / "alumni.db")
QR_DIR   = DATA_DIR / "qr_codes"
QR_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
_signer    = URLSafeTimedSerializer(SECRET_KEY)

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"pbkdf2:{salt}:{h.hex()}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, expected = stored.split(":")
    except ValueError:
        return False
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return hmac.compare_digest(h.hex(), expected)


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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS admin_users (
            id            INTEGER PRIMARY KEY,
            username      TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def init_admin():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT id FROM admin_users").fetchone()
    if not row:
        default_pass = os.environ.get("ADMIN_PASS", "Alumni@2024")
        conn.execute(
            "INSERT INTO admin_users (username, password_hash) VALUES (?,?)",
            ("admin", _hash_password(default_pass)),
        )
        conn.commit()
        print(f"[AUTH] Admin account created — username: admin  password: {default_pass}")
        print("[AUTH] Change your password after first login!")
    reset = os.environ.get("RESET_PASSWORD")
    if reset:
        conn.execute(
            "UPDATE admin_users SET password_hash=? WHERE username='admin'",
            (_hash_password(reset),),
        )
        conn.commit()
        print("[AUTH] Password reset via RESET_PASSWORD env var.")
    conn.close()


init_db()
init_admin()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── Auth ──────────────────────────────────────────────────────────────────────

def _get_user(request: Request) -> Optional[str]:
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        return _signer.loads(token, max_age=8 * 3600)
    except BadData:
        return None


def require_admin(request: Request) -> str:
    user = _get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


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


class LoginBody(BaseModel):
    username: str
    password: str


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.get("/login")
def login_page():
    return FileResponse("static/login.html")


@app.post("/login")
def do_login(body: LoginBody):
    conn = get_db()
    row = conn.execute(
        "SELECT password_hash FROM admin_users WHERE username=?", (body.username,)
    ).fetchone()
    conn.close()
    if not row or not _verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = _signer.dumps(body.username)
    resp = JSONResponse({"ok": True})
    resp.set_cookie("session", token, httponly=True, samesite="lax", max_age=8 * 3600)
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("session")
    return resp


@app.post("/api/auth/change-password")
def change_password(body: ChangePasswordBody, username: str = Depends(require_admin)):
    conn = get_db()
    row = conn.execute(
        "SELECT password_hash FROM admin_users WHERE username=?", (username,)
    ).fetchone()
    if not row or not _verify_password(body.current_password, row["password_hash"]):
        conn.close()
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    conn.execute(
        "UPDATE admin_users SET password_hash=? WHERE username=?",
        (_hash_password(body.new_password), username),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


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
def list_participants(_: str = Depends(require_admin)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM participants ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/participants", status_code=201)
def add_participant(p: ParticipantIn, _: str = Depends(require_admin)):
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
async def bulk_import(file: UploadFile = File(...), _: str = Depends(require_admin)):
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
def download_qr(pid: int, _: str = Depends(require_admin)):
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
def download_all_qr(_: str = Depends(require_admin)):
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
def mark_sent(pid: int, body: MarkSentBody, _: str = Depends(require_admin)):
    conn = get_db()
    conn.execute("UPDATE participants SET qr_sent=? WHERE id=?", (1 if body.sent else 0, pid))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/participants/{pid}")
def delete_participant(pid: int, _: str = Depends(require_admin)):
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
def admin_page(request: Request):
    if not _get_user(request):
        return RedirectResponse("/login", status_code=302)
    return FileResponse("static/admin.html")


@app.get("/scanner")
def scanner_page():
    return FileResponse("static/scanner.html")
