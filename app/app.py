"""
PhotoVault — a deliberately vulnerable Flask photo gallery app, built for
practicing web app pentesting (file upload vulnerabilities specifically).

DO NOT deploy this anywhere public. DO NOT reuse these patterns in a real
project. Every vulnerability here is intentional and marked with a LAB tag.
See VULNERABILITIES.md for write-ups.

Run with: docker compose up    (see repo README)
Default URL: http://localhost:5001
"""

import base64
import os
import subprocess

from flask import Flask, request, render_template, redirect, url_for, abort, send_from_directory

import db
from db import get_db, init_db

app = Flask(__name__)
app.secret_key = "dev-only-not-a-real-secret"

UPLOADS_DIR = os.path.join(os.path.dirname(__file__), "static", "uploads")


def current_user():
    """Same deliberately weak cookie scheme as lab 1: base64(username), no
    signature, no server-side session table. Already written up there as
    LAB finding #2 (broken authentication) -- kept here unmodified since
    it's not the focus of this lab, but it's still present if you want to
    chain it."""
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        username = base64.b64decode(token).decode()
    except Exception:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def make_session_cookie(username):
    return base64.b64encode(username.encode()).decode()


@app.route("/")
def index():
    user = current_user()
    db = get_db()
    photos = db.execute(
        "SELECT photos.*, users.username FROM photos JOIN users ON photos.owner_id = users.id "
        "WHERE is_private = 0 ORDER BY photos.id DESC"
    ).fetchall()
    return render_template("index.html", user=user, photos=photos)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?", (username, password)
    ).fetchone()
    if user is None:
        return render_template("login.html", error="Invalid username or password.")
    resp = redirect(url_for("gallery"))
    resp.set_cookie("session", make_session_cookie(user["username"]))
    return resp


@app.route("/logout")
def logout():
    resp = redirect(url_for("index"))
    resp.delete_cookie("session")
    return resp


@app.route("/gallery")
def gallery():
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    db = get_db()
    photos = db.execute("SELECT * FROM photos WHERE owner_id = ?", (user["id"],)).fetchall()
    return render_template("gallery.html", user=user, photos=photos)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """
    LAB 1 — Unrestricted File Upload:
    The upload accepts any file, with no check on extension, content-type,
    or actual file content (no "magic byte" / image-header validation).
    The original filename is kept and the file is written directly into
    static/uploads/, which Flask serves as static content. Try uploading
    something other than an image and see what comes back when you request
    it directly from static/uploads/<filename>.
    """
    user = current_user()
    if user is None:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("upload.html", user=user)

    file = request.files.get("photo")
    caption = request.form.get("caption", "")
    is_private = 1 if request.form.get("private") else 0

    if file is None or file.filename == "":
        return render_template("upload.html", user=user, error="No file selected.")

    # LAB: filename is used as-is (just the basename stripped of directory
    # separators), with no extension allowlist and no content inspection.
    filename = os.path.basename(file.filename)
    save_path = os.path.join(UPLOADS_DIR, filename)
    file.save(save_path)

    db = get_db()
    db.execute(
        "INSERT INTO photos (owner_id, filename, caption, is_private) VALUES (?, ?, ?, ?)",
        (user["id"], filename, caption, is_private),
    )
    db.commit()
    return redirect(url_for("gallery"))


@app.route("/photos/<int:photo_id>/delete", methods=["POST"])
def delete_photo(photo_id):
    """
    LAB 2 — Broken Access Control:
    Deletes a photo by id with no check that the logged-in user owns it.
    Any logged-in user can delete any other user's photo.
    """
    user = current_user()
    if user is None:
        return redirect(url_for("login"))

    db = get_db()
    photo = db.execute("SELECT * FROM photos WHERE id = ?", (photo_id,)).fetchone()
    if photo is None:
        abort(404)

    path = os.path.join(UPLOADS_DIR, photo["filename"])
    if os.path.exists(path):
        os.remove(path)
    db.execute("DELETE FROM photos WHERE id = ?", (photo_id,))
    db.commit()
    return redirect(url_for("gallery"))


@app.route("/run-plugin")
def run_plugin():
    """
    LAB 3 — Insecure Script Execution (the RCE half of the chain):
    An internal "image processing plugin" feature that runs a Python file
    out of the uploads directory, meant for admin-authored post-processing
    scripts. It performs no check that the file was actually authored by an
    admin, and no check that it's even a legitimate plugin -- it will
    execute *any* .py file sitting in static/uploads/, including one a
    regular user just uploaded through the completely unrestricted
    /upload endpoint above. That combination (LAB 1 + LAB 3) is the
    vulnerability: upload a malicious .py file as a "photo", then request
    this endpoint with its filename to get the server to execute it.
    """
    filename = request.args.get("file", "")
    safe_name = os.path.basename(filename)
    full_path = os.path.join(UPLOADS_DIR, safe_name)

    if not full_path.endswith(".py") or not os.path.isfile(full_path):
        abort(404)

    try:
        result = subprocess.run(
            ["python3", full_path], capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
    except Exception as e:
        output = f"Error running plugin: {e}"

    return render_template("plugin_output.html", output=output, filename=safe_name)


if __name__ == "__main__":
    # Only seed the DB on first run -- not on every reload. The dev
    # reloader watches .py files anywhere under this directory, including
    # static/uploads, so uploading a .py file (exactly what LAB 1 + LAB 3
    # let you do) would otherwise trigger a reload that wipes the gallery.
    if not os.path.exists(db.DB_PATH):
        init_db()
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=5001, debug=True)
