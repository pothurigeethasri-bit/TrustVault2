"""TrustVault - Flask application entry point."""
import os

from dotenv import load_dotenv
from flask import Flask, g, redirect, render_template, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

import auth

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
    )

    # Behind Render's proxy, trust one hop so request.remote_addr is the real client.
    if os.environ.get("TRUST_PROXY", "0") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    app.register_blueprint(auth.auth_bp)
    app.jinja_env.globals["csrf_token"] = auth.csrf_token

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
        return render_template("admin_dashboard.html")

    @app.route("/owner")
    @auth.role_required("owner")
    def owner():
        return render_template("owner_dashboard.html")

    @app.route("/viewer")
    @auth.role_required("viewer")
    def viewer():
        return render_template("viewer_dashboard.html")

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
        if g.get("user"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
