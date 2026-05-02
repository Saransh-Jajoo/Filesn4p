"""
FileSn4p - Secure File Transfer Application
Military-grade end-to-end encryption with zero-knowledge architecture
License: MIT
"""

import json
import logging
import os
import re
import secrets
import sqlite3
import time
from io import BytesIO
from pathlib import Path

from pythonjsonlogger import jsonlogger

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

# FileSn4p - Secure file sharing with browser-side E2E encryption

MAX_FILE_SIZE = 50 * 1024 * 1024
ACTIVE_USER_SECONDS = 45
STALE_USER_SECONDS = 120
MAX_ROOM_USERS = 32
ALLOWED_EXPIRES = {600, 1200, 1800, 3600, 5400, 7200, 10800}  # 10 min to 3 hours
MAX_VIEW_LIMIT = 1000
MIN_VIEW_LIMIT = 10
MAX_EXPIRY_SECONDS = 180 * 60  # 3 hours
MIN_EXPIRY_SECONDS = 10 * 60  # 10 minutes
ROOM_RE = re.compile(r"^[A-Z0-9]{6,32}$")
ROOM_STRIP_RE = re.compile(r"[^A-Za-z0-9]")
USER_RE = re.compile(r"^[A-Za-z0-9_. -]{1,32}$")
FINGERPRINT_RE = re.compile(r"^[A-F0-9]{4}(?:-[A-F0-9]{4}){3}$")
PUBLIC_LOBBY_ID = "LOBBY1"
PUBLIC_LOBBY_HASH = "public-lobby"

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Use a stable secret in production so CSRF/session signing survives restarts.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE + 256 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"

csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per hour", "80 per minute"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
handler.setFormatter(formatter)
logging.basicConfig(handlers=[handler], level=logging.INFO)

DATA_DIR = Path(os.environ.get("SECURE_VAULT_DATA_DIR", Path(app.instance_path) / "clipboard"))
BLOB_DIR = DATA_DIR / "blobs"
DB_PATH = DATA_DIR / "secure_vault.sqlite3"


def now_ts():
    return int(time.time())


def ensure_storage():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BLOB_DIR.mkdir(parents=True, exist_ok=True)


def db_connect():
    ensure_storage()
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    with db_connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS rooms (
                id TEXT PRIMARY KEY,
                access_key_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                username TEXT NOT NULL,
                public_key_json TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                joined_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_users_room_seen
                ON users (room_id, last_seen);

            CREATE TABLE IF NOT EXISTS clips (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                sender_name TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                original_name TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                metadata_json TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                views_left INTEGER NOT NULL,
                deleted_at INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_clips_recipient
                ON clips (recipient_id, deleted_at, expires_at);
            """
        )


def cleanup_expired():
    cutoff = now_ts()
    stale_cutoff = cutoff - STALE_USER_SECONDS
    with db_connect() as conn:
        expired = conn.execute(
            "SELECT id, stored_path FROM clips WHERE deleted_at IS NULL AND expires_at <= ?",
            (cutoff,),
        ).fetchall()
        stale_users = conn.execute(
            "SELECT id FROM users WHERE last_seen <= ?",
            (stale_cutoff,),
        ).fetchall()

        for row in expired:
            delete_blob(row["stored_path"])

        conn.execute(
            "UPDATE clips SET deleted_at = ? WHERE deleted_at IS NULL AND expires_at <= ?",
            (cutoff, cutoff),
        )

        for user in stale_users:
            rows = conn.execute(
                "SELECT stored_path FROM clips WHERE deleted_at IS NULL AND recipient_id = ?",
                (user["id"],),
            ).fetchall()
            for row in rows:
                delete_blob(row["stored_path"])
            conn.execute(
                "UPDATE clips SET deleted_at = ? WHERE deleted_at IS NULL AND recipient_id = ?",
                (cutoff, user["id"]),
            )

        conn.execute("DELETE FROM users WHERE last_seen <= ?", (stale_cutoff,))
        conn.execute(
            """
            DELETE FROM rooms
            WHERE last_seen <= ?
              AND id NOT IN (SELECT DISTINCT room_id FROM users)
            """,
            (stale_cutoff,),
        )


def delete_blob(path_value):
    if not path_value:
        return

    path = (BLOB_DIR / Path(path_value).name).resolve()
    try:
        if path.parent == BLOB_DIR.resolve() and path.exists():
            path.unlink()
    except OSError:
        logging.warning("Failed to delete expired clipboard blob: %s", path.name)


def validate_json_request():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="Expected a JSON request body.")
    return payload


def normalize_room_id(room_id):
    return ROOM_STRIP_RE.sub("", room_id or "").upper()


def validate_room_id(room_id):
    room_id = normalize_room_id(room_id)
    if not ROOM_RE.fullmatch(room_id):
        abort(400, description="Invalid lobby identifier.")
    return room_id


def validate_username(username):
    username = (username or "").strip()
    if not USER_RE.fullmatch(username):
        abort(400, description="Use a username with 1-32 letters, numbers, spaces, dots, underscores, or dashes.")
    return username


def validate_public_key(public_key):
    if not isinstance(public_key, dict):
        abort(400, description="Invalid public key.")

    encoded = json.dumps(public_key, separators=(",", ":"))
    if len(encoded) > 4096:
        abort(400, description="Public key is too large.")

    if public_key.get("type") != "secure-vault-live-public-key":
        abort(400, description="Unsupported public key type.")

    return encoded


def validate_fingerprint(fingerprint):
    fingerprint = (fingerprint or "").upper().strip()
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        abort(400, description="Invalid key fingerprint.")
    return fingerprint


def validate_clip_metadata(metadata):
    if not isinstance(metadata, dict):
        abort(400, description="Invalid clip metadata.")

    encoded = json.dumps(metadata, separators=(",", ":"))
    if len(encoded) > 8192:
        abort(400, description="Clip metadata is too large.")

    required = {"algorithm", "curve", "filename", "ephemeralPublicKey", "kdf", "cipher", "wrappedKey"}
    if not required.issubset(metadata):
        abort(400, description="Clip metadata is incomplete.")

    return encoded


def ensure_active_room_user(conn, room_id, user_id):
    if not user_id:
        abort(403, description="Join this room first.")

    row = conn.execute(
        "SELECT id FROM users WHERE id = ? AND room_id = ? AND last_seen > ?",
        (user_id, room_id, now_ts() - ACTIVE_USER_SECONDS),
    ).fetchone()
    if not row:
        abort(403, description="Join this room first.")
    return row


def json_error(message, status_code):
    response = jsonify({"error": message})
    response.status_code = status_code
    return response


@app.before_request
def run_periodic_cleanup():
    if request.endpoint != "static":
        cleanup_expired()


@app.after_request
def set_security_headers(response):
    # Content Security Policy - Strict policy for security
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "upgrade-insecure-requests"
    )
    
    # Additional security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    
    # HSTS for HTTPS enforcement
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    return response


@app.errorhandler(400)
def bad_request(error):
    message = getattr(error, "description", "Bad request.")
    if request.path.startswith("/api/"):
        return json_error(message, 400)
    flash(message, "error")
    return redirect(url_for("index"))


@app.errorhandler(403)
def forbidden(error):
    if request.path.startswith("/api/"):
        return json_error(getattr(error, "description", "Forbidden."), 403)
    flash("Forbidden.", "error")
    return redirect(url_for("index"))


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return json_error("Not found.", 404)
    return render_index(), 404


@app.errorhandler(413)
def request_entity_too_large(error):
    logging.warning("Upload rejected: File size exceeded the limit.")
    if request.path.startswith("/api/"):
        return json_error("File is too large. Maximum size is 50 MB.", 413)
    flash("File is too large. Maximum size is 50 MB.", "error")
    return redirect(url_for("index")), 413


@app.errorhandler(429)
def rate_limit_exceeded(error):
    if request.path.startswith("/api/"):
        return json_error("Too many requests. Slow down and try again.", 429)
    flash("Too many requests. Slow down and try again.", "error")
    return redirect(url_for("index")), 429


@app.route("/", methods=["GET"])
def index():
    return render_index()


def render_index():
    return render_template(
        "index.html",
        max_file_size_mb=MAX_FILE_SIZE // (1024 * 1024),
    )


@app.route("/healthz", methods=["GET"])
def healthz():
    return {"status": "ok"}


@app.route("/api/rooms", methods=["POST"])
@limiter.limit("12 per minute")
def join_room():
    payload = validate_json_request()
    username = validate_username(payload.get("username"))
    public_key = validate_public_key(payload.get("public_key"))
    fingerprint = validate_fingerprint(payload.get("fingerprint"))
    room_id = PUBLIC_LOBBY_ID

    user_id = secrets.token_urlsafe(18)
    timestamp = now_ts()

    with db_connect() as conn:
        room = conn.execute("SELECT access_key_hash FROM rooms WHERE id = ?", (room_id,)).fetchone()

        if not room:
            conn.execute(
                "INSERT INTO rooms (id, access_key_hash, created_at, last_seen) VALUES (?, ?, ?, ?)",
                (room_id, PUBLIC_LOBBY_HASH, timestamp, timestamp),
            )

        active_count = conn.execute(
            "SELECT COUNT(*) AS count FROM users WHERE room_id = ? AND last_seen > ?",
            (room_id, timestamp - ACTIVE_USER_SECONDS),
        ).fetchone()["count"]
        if active_count >= MAX_ROOM_USERS:
            abort(400, description="This room is full.")

        existing_user = conn.execute(
            "SELECT id FROM users WHERE room_id = ? AND username = ? AND last_seen > ?",
            (room_id, username, timestamp - ACTIVE_USER_SECONDS)
        ).fetchone()
        if existing_user:
            abort(400, description="Username is already taken in this room.")

        conn.execute(
            """
            INSERT INTO users (id, room_id, username, public_key_json, fingerprint, joined_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, room_id, username, public_key, fingerprint, timestamp, timestamp),
        )
        conn.execute("UPDATE rooms SET last_seen = ? WHERE id = ?", (timestamp, room_id))

    response = {"room_id": room_id, "user_id": user_id, "username": username}
    return jsonify(response)


@app.route("/api/rooms/<room_id>/heartbeat", methods=["POST"])
@limiter.limit("60 per minute")
def heartbeat(room_id):
    room_id = validate_room_id(room_id)
    payload = validate_json_request()
    user_id = payload.get("user_id")

    with db_connect() as conn:
        updated = conn.execute(
            "UPDATE users SET last_seen = ? WHERE id = ? AND room_id = ?",
            (now_ts(), user_id, room_id),
        ).rowcount
        if updated:
            conn.execute("UPDATE rooms SET last_seen = ? WHERE id = ?", (now_ts(), room_id))

    if not updated:
        abort(404, description="Temporary user is no longer active.")

    return jsonify({"status": "ok"})


@app.route("/api/rooms/<room_id>/users", methods=["GET"])
@limiter.limit("120 per minute")
def active_users(room_id):
    room_id = validate_room_id(room_id)
    current_user = request.args.get("user_id")

    with db_connect() as conn:
        ensure_active_room_user(conn, room_id, current_user)
        rows = conn.execute(
            """
            SELECT id, username, public_key_json, fingerprint, joined_at, last_seen
            FROM users
            WHERE room_id = ? AND last_seen > ?
            ORDER BY username COLLATE NOCASE, joined_at
            """,
            (room_id, now_ts() - ACTIVE_USER_SECONDS),
        ).fetchall()

    users = []
    for row in rows:
        users.append(
            {
                "id": row["id"],
                "username": row["username"],
                "public_key": json.loads(row["public_key_json"]),
                "fingerprint": row["fingerprint"],
                "joined_at": row["joined_at"],
                "last_seen": row["last_seen"],
                "is_self": row["id"] == current_user,
            }
        )

    return jsonify({"users": users})


@app.route("/api/rooms/<room_id>/users/search", methods=["GET"])
@limiter.limit("120 per minute")
def search_users(room_id):
    room_id = validate_room_id(room_id)
    query = (request.args.get("q") or "").strip().lower()
    current_user = request.args.get("user_id")

    if not query:
        return jsonify({"users": []})

    with db_connect() as conn:
        ensure_active_room_user(conn, room_id, current_user)
        rows = conn.execute(
            """
            SELECT id, username, public_key_json, fingerprint, joined_at, last_seen
            FROM users
            WHERE room_id = ? AND last_seen > ? AND id != ?
              AND LOWER(username) LIKE ?
            ORDER BY username COLLATE NOCASE
            LIMIT 10
            """,
            (room_id, now_ts() - ACTIVE_USER_SECONDS, current_user, f"%{query}%"),
        ).fetchall()

    users = [
        {
            "id": row["id"],
            "username": row["username"],
            "public_key": json.loads(row["public_key_json"]),
            "fingerprint": row["fingerprint"],
        }
        for row in rows
    ]

    return jsonify({"users": users})


@app.route("/api/rooms/<room_id>/clips", methods=["POST"])
@limiter.limit("20 per minute")
def create_clip(room_id):
    room_id = validate_room_id(room_id)
    sender_id = request.form.get("sender_id")
    recipient_ids = request.form.get("recipient_id", "").split(",") if request.form.get("recipient_id") else []
    recipient_ids = [r.strip() for r in recipient_ids if r.strip()]
    expiry_mode = request.form.get("expiry_mode", "time")

    try:
        metadata = validate_clip_metadata(json.loads(request.form.get("metadata") or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        abort(400, description="Invalid clip metadata.")

    payload = request.files.get("payload")

    # Validate recipients
    if not recipient_ids or len(recipient_ids) > 50:
        abort(400, description="Select 1-50 recipients.")

    # Exclusive expiry mode: only one of downloads or time is active
    if expiry_mode == "downloads":
        try:
            views_left = int(request.form.get("view_limit") or MIN_VIEW_LIMIT)
        except (TypeError, ValueError):
            abort(400, description="Invalid download limit.")
        if not (MIN_VIEW_LIMIT <= views_left <= MAX_VIEW_LIMIT):
            abort(400, description=f"Download limit must be between {MIN_VIEW_LIMIT} and {MAX_VIEW_LIMIT}.")
        expires_in = 30 * 24 * 3600  # 30 days — effectively infinite
    elif expiry_mode == "time":
        try:
            expires_in = int(request.form.get("expires_in") or MIN_EXPIRY_SECONDS)
        except (TypeError, ValueError):
            abort(400, description="Invalid expiration.")
        
        # Validate expiry is within min and max bounds
        if not (MIN_EXPIRY_SECONDS <= expires_in <= MAX_EXPIRY_SECONDS):
            abort(400, description=f"Expiration must be between 10 minutes and 3 hours.")
        views_left = 9999  # effectively infinite
    else:
        abort(400, description="Choose a valid expiry mode.")

    if not payload or not payload.filename:
        abort(400, description="Missing encrypted payload.")

    payload.seek(0, os.SEEK_END)
    size_bytes = payload.tell()
    payload.seek(0)
    if size_bytes < 1 or size_bytes > MAX_FILE_SIZE + 65536:
        abort(400, description="Encrypted payload size is invalid. Maximum 50 MB.")

    if size_bytes > MAX_FILE_SIZE:
        abort(413, description="File size exceeds 50 MB limit.")

    metadata_dict = json.loads(metadata)
    original_name = secure_filename(metadata_dict.get("filename") or payload.filename) or "shared-file"
    clip_id = secrets.token_urlsafe(18)
    stored_name = f"{clip_id}.bin"
    stored_path = BLOB_DIR / stored_name
    timestamp = now_ts()

    with db_connect() as conn:
        sender = conn.execute(
            "SELECT username FROM users WHERE id = ? AND room_id = ? AND last_seen > ?",
            (sender_id, room_id, timestamp - ACTIVE_USER_SECONDS),
        ).fetchone()

        if not sender:
            abort(400, description="Sender must be active in this room.")

        # Validate all recipients exist and are active
        recipients = []
        for recipient_id in recipient_ids:
            recipient = conn.execute(
                "SELECT id, username FROM users WHERE id = ? AND room_id = ? AND last_seen > ?",
                (recipient_id, room_id, timestamp - ACTIVE_USER_SECONDS),
            ).fetchone()
            if not recipient or recipient_id == sender_id:
                abort(400, description="Invalid or inactive recipient selected.")
            recipients.append(recipient)

        # Save the file once
        payload.save(stored_path)

        # Create a clip for each recipient
        clip_ids = []
        for recipient in recipients:
            clip_id = secrets.token_urlsafe(18)
            clip_ids.append(clip_id)
            
            conn.execute(
                """
                INSERT INTO clips (
                    id, room_id, sender_id, sender_name, recipient_id, original_name,
                    size_bytes, metadata_json, stored_path, created_at, expires_at,
                    views_left, deleted_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    clip_id,
                    room_id,
                    sender_id,
                    sender["username"],
                    recipient["id"],
                    original_name,
                    size_bytes,
                    metadata,
                    stored_name,
                    timestamp,
                    timestamp + expires_in,
                    views_left,
                ),
            )

        recipients_str = ", ".join([r["username"] for r in recipients])
        logging.info("Encrypted clipboard clip created: %s -> %s (%s bytes, %d recipients)", 
                    sender_id, recipients_str, size_bytes, len(recipients))

    return jsonify({
        "clip_ids": clip_ids,
        "clip_count": len(clip_ids),
        "expires_at": timestamp + expires_in,
        "views_left": views_left,
        "recipients": len(recipients)
    })


@app.route("/api/rooms/<room_id>/clips", methods=["GET"])
@limiter.limit("120 per minute")
def list_clips(room_id):
    room_id = validate_room_id(room_id)
    user_id = request.args.get("user_id")

    with db_connect() as conn:
        ensure_active_room_user(conn, room_id, user_id)
        rows = conn.execute(
            """
            SELECT id, sender_name, original_name, size_bytes, created_at, expires_at, views_left
            FROM clips
            WHERE room_id = ?
              AND recipient_id = ?
              AND deleted_at IS NULL
              AND expires_at > ?
              AND views_left > 0
            ORDER BY created_at DESC
            """,
            (room_id, user_id, now_ts()),
        ).fetchall()

    return jsonify(
        {
            "clips": [
                {
                    "id": row["id"],
                    "sender_name": row["sender_name"],
                    "filename": row["original_name"],
                    "size_bytes": row["size_bytes"],
                    "created_at": row["created_at"],
                    "expires_at": row["expires_at"],
                    "views_left": row["views_left"],
                }
                for row in rows
            ]
        }
    )


@app.route("/api/clips/<clip_id>/download", methods=["GET"])
@limiter.limit("60 per minute")
def download_clip(clip_id):
    user_id = request.args.get("user_id")
    timestamp = now_ts()

    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM clips
            WHERE id = ?
              AND recipient_id = ?
              AND deleted_at IS NULL
              AND expires_at > ?
              AND views_left > 0
              AND EXISTS (
                  SELECT 1 FROM users
                  WHERE users.id = clips.recipient_id
                    AND users.room_id = clips.room_id
                    AND users.last_seen > ?
              )
            """,
            (clip_id, user_id, timestamp, timestamp - ACTIVE_USER_SECONDS),
        ).fetchone()

        if not row:
            abort(404, description="This clip is no longer available.")

        blob_path = (BLOB_DIR / Path(row["stored_path"]).name).resolve()
        if blob_path.parent != BLOB_DIR.resolve() or not blob_path.exists():
            conn.execute("UPDATE clips SET deleted_at = ? WHERE id = ?", (timestamp, clip_id))
            abort(404, description="This clip is no longer available.")

        encrypted_data = blob_path.read_bytes()
        next_views = row["views_left"] - 1
        if next_views <= 0:
            conn.execute("UPDATE clips SET views_left = 0, deleted_at = ? WHERE id = ?", (timestamp, clip_id))
            delete_blob(row["stored_path"])
        else:
            conn.execute("UPDATE clips SET views_left = ? WHERE id = ?", (next_views, clip_id))

    output = BytesIO(encrypted_data)
    output.seek(0)
    response = send_file(
        output,
        mimetype="application/octet-stream",
        as_attachment=False,
        download_name=f"{clip_id}.bin",
    )
    response.headers["X-Clip-Metadata"] = row["metadata_json"]
    response.headers["X-Views-Left"] = str(max(next_views, 0))
    return response


# Manual encrypt/decrypt routes removed — all encryption is automatic E2E via browser-side ECDH+AES-GCM


init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
