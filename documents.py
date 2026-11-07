"""Document upload, categories, search, secure view/download, delete."""
import hashlib
import io
import re
import uuid
from datetime import datetime, timedelta

from flask import (Blueprint, abort, current_app, flash, g, redirect,
                   render_template, request, send_file, url_for)

import audit
import storage
from auth import login_required, role_required
from database import execute, execute_returning, fetch_all, fetch_one
from permissions import require_access
from validation import INLINE_TYPES, MAX_NAME_LEN, ValidationError, validate_upload
from werkzeug.utils import secure_filename

docs_bp = Blueprint("documents", __name__)


# --------------------------------------------------------------- DB functions
def insert_document(owner_id, category_id, original_name, stored_name, mime, size, sha256):
    return execute_returning(
        "INSERT INTO documents (owner_id, category_id, original_name, stored_name, "
        "mime_type, size_bytes, sha256) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (owner_id, category_id, original_name, stored_name, mime, size, sha256))


def update_document(doc_id, original_name, stored_name, size, sha256):
    execute("UPDATE documents SET original_name = %s, stored_name = %s, "
            "size_bytes = %s, sha256 = %s WHERE id = %s",
            (original_name, stored_name, size, sha256, doc_id))


def delete_document_row(doc_id):
    execute("DELETE FROM documents WHERE id = %s", (doc_id,))


def list_categories(owner_id):
    return fetch_all("SELECT id, name FROM categories WHERE owner_id = %s ORDER BY name",
                     (owner_id,))


def get_category(category_id, owner_id):
    return fetch_one("SELECT id, name FROM categories WHERE id = %s AND owner_id = %s",
                     (category_id, owner_id))


def create_category(owner_id, name):
    return execute_returning(
        "INSERT INTO categories (name, owner_id) VALUES (%s, %s) "
        "ON CONFLICT (owner_id, name) DO NOTHING RETURNING id", (name, owner_id))


def set_document_category(doc_id, category_id):
    execute("UPDATE documents SET category_id = %s WHERE id = %s", (category_id, doc_id))


def _like(text):
    return "%" + re.sub(r"([\\%_])", r"\\\1", text) + "%"


def search_documents(user_id, q=None, category=None, owner=None,
                     date_from=None, date_to=None, limit=200, role="viewer"):
    """Documents the user owns or has been granted. Filters: name, category,
    owner, upload date range. All values are bound parameters."""
    sql = """
        SELECT d.id, d.original_name, d.mime_type, d.size_bytes, d.uploaded_at,
               u.username AS owner, c.name AS category,
               CASE WHEN d.owner_id = %s THEN 'owner' ELSE p.access_level END AS access
        FROM documents d
        JOIN users u ON u.id = d.owner_id
        LEFT JOIN categories c ON c.id = d.category_id
        LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = %s
        WHERE (d.owner_id = %s OR p.user_id IS NOT NULL)"""
    params = [user_id, user_id, user_id]
    if q:
        sql += " AND d.original_name ILIKE %s ESCAPE '\\'"; params.append(_like(q))
    if category:
        sql += " AND c.name ILIKE %s ESCAPE '\\'"; params.append(_like(category))
    if owner:
        sql += " AND u.username ILIKE %s ESCAPE '\\'"; params.append(_like(owner))
    if date_from:
        sql += " AND d.uploaded_at >= %s"; params.append(date_from)
    if date_to:
        sql += " AND d.uploaded_at < %s"; params.append(date_to + timedelta(days=1))
    sql += " ORDER BY d.uploaded_at DESC LIMIT %s"
    params.append(limit)
    rows = fetch_all(sql, params)
    if role != "owner":                      # only the Owner role can edit or manage
        for r in rows:
            if r["access"] in ("edit", "owner"):
                r["access"] = "download"
    return rows


def filters_from_request():
    """Read and sanitise search filters from the query string."""
    def text(name):
        return request.args.get(name, "").strip()[:100] or None

    def date(name):
        raw = request.args.get(name, "").strip()
        if not raw:
            return None
        try:
            return datetime.strptime(raw, "%Y-%m-%d")
        except ValueError:
            flash(f"Ignored invalid date: {raw[:20]}", "warning")
            return None

    return dict(q=text("q"), category=text("category"), owner=text("owner"),
                date_from=date("date_from"), date_to=date("date_to"))


# -------------------------------------------------------------------- routes
@docs_bp.route("/documents/upload", methods=["POST"])
@role_required("owner")
def upload():
    ip = audit.client_ip(request)
    max_bytes = current_app.config["MAX_CONTENT_LENGTH"]
    f = request.files.get("file")
    if f is None or not f.filename:
        flash("Choose a file to upload.", "danger")
        return redirect(url_for("owner"))

    data = f.read(max_bytes + 1)
    try:
        name, _ext, mime = validate_upload(f.filename, data, max_bytes)
    except ValidationError as err:
        audit.log_event(audit.VALIDATION_FAIL, audit.FAILURE, user=g.user, ip_address=ip,
                        details=f"{f.filename[:100]}: {err}")
        flash(str(err), "danger")
        return redirect(url_for("owner"))

    category_id = None
    raw_cat = request.form.get("category_id", "").strip()
    if raw_cat:
        if not raw_cat.isdigit() or not get_category(int(raw_cat), g.user["id"]):
            flash("Invalid category.", "danger")
            return redirect(url_for("owner"))
        category_id = int(raw_cat)

    stored_name = uuid.uuid4().hex          # random; the user's filename is never used on disk
    storage.save(stored_name, data)
    try:
        doc_id = insert_document(g.user["id"], category_id, name, stored_name, mime,
                                 len(data), hashlib.sha256(data).hexdigest())
    except Exception:
        storage.delete(stored_name)
        raise
    audit.log_event(audit.UPLOAD, audit.SUCCESS, user=g.user, document_id=doc_id,
                    ip_address=ip, details=f"{name} ({len(data)} bytes)")
    flash(f"Uploaded {name}.", "success")
    return redirect(url_for("owner"))


@docs_bp.route("/categories", methods=["POST"])
@role_required("owner")
def add_category():
    name = request.form.get("name", "").strip()
    if not 1 <= len(name) <= 50:
        flash("Category name must be 1 to 50 characters.", "danger")
    elif create_category(g.user["id"], name) is None:
        flash("You already have that category.", "warning")
    else:
        audit.log_event(audit.CREATE_CATEGORY, audit.SUCCESS, user=g.user,
                        ip_address=audit.client_ip(request), details=name)
        flash(f"Category '{name}' created.", "success")
    return redirect(url_for("owner"))


def _serve(doc_id, action, inline):
    # View needs "view"; download needs "download" - two separate permissions.
    doc = require_access(doc_id, "view" if inline else "download", action)   # 403 + DENIED log
    if inline and doc["mime_type"] not in INLINE_TYPES:
        # The browser cannot preview this type, so "opening" it would hand over the whole
        # file. That is a download, so it needs download rights.
        doc = require_access(doc_id, "download", action)
    data = storage.load(doc["stored_name"])
    if data is None:
        audit.log_event(action, audit.FAILURE, user=g.user, document_id=doc_id,
                        ip_address=audit.client_ip(request), details="file missing on disk")
        abort(404)
    audit.log_event(action, audit.SUCCESS, user=g.user, document_id=doc_id,
                    ip_address=audit.client_ip(request), details=doc["original_name"])
    as_attachment = not (inline and doc["mime_type"] in INLINE_TYPES)
    return send_file(io.BytesIO(data), mimetype=doc["mime_type"], as_attachment=as_attachment,
                     download_name=doc["original_name"], max_age=0)


@docs_bp.route("/documents/<int:doc_id>/view")
@login_required
def view_document(doc_id):
    return _serve(doc_id, audit.VIEW, inline=True)


@docs_bp.route("/documents/<int:doc_id>/download")
@login_required
def download_document(doc_id):
    return _serve(doc_id, audit.DOWNLOAD, inline=False)


@docs_bp.route("/documents/<int:doc_id>/category", methods=["POST"])
@login_required
def change_category(doc_id):
    """Owner re-files one of their documents under another category (or none)."""
    doc = require_access(doc_id, "owner", audit.CATEGORY_CHANGE)
    ip = audit.client_ip(request)
    raw = request.form.get("category_id", "").strip()
    category = None
    if raw:
        category = (get_category(int(raw), g.user["id"])
                    if raw.isdigit() and len(raw) < 10 else None)
        if category is None:
            audit.log_event(audit.CATEGORY_CHANGE, audit.FAILURE, user=g.user, document_id=doc_id,
                            ip_address=ip, details="invalid category")
            flash("Invalid category.", "danger")
            return redirect(url_for("owner"))
    set_document_category(doc_id, category["id"] if category else None)
    label = category["name"] if category else "no category"
    audit.log_event(audit.CATEGORY_CHANGE, audit.SUCCESS, user=g.user, document_id=doc_id,
                    ip_address=ip, details=f"{doc['original_name']} -> {label}")
    flash(f"Moved {doc['original_name']} to {label}.", "success")
    return redirect(url_for("owner"))


@docs_bp.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    doc = require_access(doc_id, "owner", audit.DELETE_DOC)
    delete_document_row(doc_id)
    storage.delete(doc["stored_name"])
    audit.log_event(audit.DELETE_DOC, audit.SUCCESS, user=g.user, document_id=doc_id,
                    ip_address=audit.client_ip(request), details=doc["original_name"])
    flash(f"Deleted {doc['original_name']}.", "success")
    return redirect(url_for("owner"))


@docs_bp.route("/documents/<int:doc_id>/edit", methods=["GET", "POST"])
@role_required("owner")
def edit_document(doc_id):
    """Rename and/or replace the file. Needs edit access (or ownership)."""
    doc = require_access(doc_id, "edit", audit.EDIT)
    if request.method == "GET":
        return render_template("edit.html", doc=doc)
    old_stored = doc["stored_name"]          # remember before anything changes
    old_name = doc["original_name"]

    ip = audit.client_ip(request)
    max_bytes = current_app.config["MAX_CONTENT_LENGTH"]
    old_ext = doc["original_name"].rsplit(".", 1)[-1].lower()
    name, stored, size, sha = (doc["original_name"], doc["stored_name"],
                               doc["size_bytes"], doc["sha256"])
    new_stored = None

    new_name = request.form.get("name", "").strip()
    if new_name and new_name != name:
        clean = secure_filename(new_name)
        if (not clean or "." not in clean or len(clean) > MAX_NAME_LEN
                or clean.rsplit(".", 1)[1].lower() != old_ext):
            flash(f"Invalid name. It must keep the .{old_ext} extension.", "danger")
            return redirect(url_for("documents.edit_document", doc_id=doc_id))
        name = clean

    f = request.files.get("file")
    if f is not None and f.filename:
        data = f.read(max_bytes + 1)
        try:
            _n, _e, mime = validate_upload(f.filename, data, max_bytes)
        except ValidationError as err:
            audit.log_event(audit.VALIDATION_FAIL, audit.FAILURE, user=g.user,
                            document_id=doc_id, ip_address=ip,
                            details=f"{f.filename[:100]}: {err}")
            flash(str(err), "danger")
            return redirect(url_for("documents.edit_document", doc_id=doc_id))
        if mime != doc["mime_type"]:
            flash("The replacement must be the same type of file.", "danger")
            return redirect(url_for("documents.edit_document", doc_id=doc_id))
        stored = new_stored = uuid.uuid4().hex
        storage.save(stored, data)
        size, sha = len(data), hashlib.sha256(data).hexdigest()

    if name == old_name and new_stored is None:
        flash("No changes made.", "info")
        return redirect(url_for("documents.edit_document", doc_id=doc_id))

    try:
        update_document(doc_id, name, stored, size, sha)
    except Exception:
        if new_stored:
            storage.delete(new_stored)
        raise
    if new_stored:
        storage.delete(old_stored)
    what = ("replaced file" if new_stored else "") + (" and " if new_stored and name != old_name else "") \
        + (f"renamed to {name}" if name != old_name else "")
    audit.log_event(audit.EDIT, audit.SUCCESS, user=g.user, document_id=doc_id,
                    ip_address=ip, details=what)
    flash("Document updated.", "success")
    return redirect(url_for("owner"))
