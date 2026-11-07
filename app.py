"""TrustVault - Flask application entry point."""
import os
from datetime import timedelta, timezone

from dotenv import load_dotenv
from flask import Flask, g, redirect, render_template, request, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

import admin_panel
import auth
import documents
import permissions
import pin_gate
import storage

load_dotenv()


def create_app():
    app = Flask(__name__)

    secret = os.environ.get("SECRET_KEY", "")
    if len(secret) < 16 or secret.startswith("change-me"):
        raise RuntimeError("Set a long random SECRET_KEY in .env")
    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=30 * 60,          # 30 minutes
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_MB", "10")) * 1024 * 1024,
        # Private folder OUTSIDE static/: files are only reachable through checked routes.
        UPLOAD_DIR=os.path.abspath(os.environ.get("UPLOAD_DIR", "uploads")),
        # "disk" (local dev) or "db" (hosts with an ephemeral disk, e.g. Render). See storage.py.
        STORAGE_BACKEND=os.environ.get("STORAGE_BACKEND", "disk"),
    )
    if app.config["STORAGE_BACKEND"] not in storage.BACKENDS:
        raise RuntimeError("STORAGE_BACKEND must be 'disk' or 'db'")
    if app.config["STORAGE_BACKEND"] == "disk":
        os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    # Behind Render's proxy, trust one hop so request.remote_addr is the real client.
    if os.environ.get("TRUST_PROXY", "0") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    pin_gate.validate_configuration(app.config["SESSION_COOKIE_SECURE"])
    app.register_blueprint(pin_gate.pin_bp)      # FIRST: its before_request must run before auth's
    app.register_blueprint(auth.auth_bp)
    app.register_blueprint(documents.docs_bp)
    app.register_blueprint(permissions.perm_bp)
    app.register_blueprint(admin_panel.admin_bp)
    app.jinja_env.globals["csrf_token"] = auth.csrf_token
    app.jinja_env.globals["inline_types"] = documents.INLINE_TYPES

    IST = timezone(timedelta(hours=5, minutes=30))     # India has no daylight saving

    @app.template_filter("ist")
    def to_ist(value, seconds=False):
        if value is None:
            return ""
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(IST).strftime("%d %b %Y %H:%M:%S" if seconds else "%d %b %Y %H:%M")

    @app.template_filter("filetype")
    def filetype(mime):
        if mime == "application/pdf":
            return "pdf"
        if mime.startswith("image/"):
            return "img"
        for key, name in (("wordprocessingml", "doc"), ("spreadsheetml", "xls"),
                          ("presentationml", "ppt")):
            if key in mime:
                return name
        return "csv" if mime == "text/csv" else "txt"

    @app.template_filter("filesize")
    def filesize(n):
        for unit in ("B", "KB", "MB"):
            if n < 1024:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} GB"

    # ---------------------------------------------------------------- pages
    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "auth.login"))

    @app.route("/dashboard")
    @auth.login_required
    def dashboard():
        return redirect(url_for(g.user["role"]))   # endpoints: admin / owner / viewer

    @app.route("/admin")
    @auth.role_required("admin")
    def admin():
        return admin_panel.overview()

    @app.route("/owner")
    @auth.role_required("owner")
    def owner():
        docs = documents.search_documents(g.user["id"], role=g.user["role"],
                                   **documents.filters_from_request())
        return render_template("owner_dashboard.html", docs=docs, f=request.args,
                               categories=documents.list_categories(g.user["id"]))

    @app.route("/viewer")
    @auth.role_required("viewer")
    def viewer():
        docs = documents.search_documents(g.user["id"], role=g.user["role"],
                                   **documents.filters_from_request())
        return render_template("viewer_dashboard.html", docs=docs, f=request.args)

    # --------------------------------------------------------------- errors
    messages = {400: "Bad request.", 403: "You do not have permission to view this page.",
                404: "Page not found.", 413: "That file is too large.",
                429: "Too many attempts. Please wait and try again."}

    def make_handler(code):
        def handler(_err):
            return render_template("error.html", code=code, message=messages[code]), code
        return handler

    for code in messages:
        app.register_error_handler(code, make_handler(code))

    # ------------------------------------------------------ security headers
    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; "
            "script-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; "
            "frame-ancestors 'none'")
        if app.config["SESSION_COOKIE_SECURE"]:          # production over HTTPS
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if g.get("user"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
