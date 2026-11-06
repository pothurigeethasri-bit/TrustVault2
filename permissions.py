"""Access control: the central check, plus grant / revoke / share-page routes.

Access levels: owner > edit > read.
  * read  - view and download.
  * edit  - also rename and replace the file. Only users with the Owner ROLE can
            hold edit access; Viewer-role users are always capped at read.
Revoking deletes the permission row, so the very next request is refused.
"""
from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   request, url_for)

import audit
from auth import get_user_by_id, login_required
from database import execute_returning, fetch_all, fetch_one

perm_bp = Blueprint("permissions", __name__)
RANK = {"read": 1, "edit": 2, "owner": 3}


# --------------------------------------------------------------- DB functions
def get_document(doc_id):
    return fetch_one("SELECT * FROM documents WHERE id = %s", (doc_id,))


def get_permission(doc_id, user_id):
    row = fetch_one("SELECT access_level FROM permissions "
                    "WHERE document_id = %s AND user_id = %s", (doc_id, user_id))
    return row["access_level"] if row else None


def list_permissions(doc_id):
    return fetch_all(
        "SELECT p.user_id, u.username, u.role, p.access_level, p.granted_at "
        "FROM permissions p JOIN users u ON u.id = p.user_id "
        "WHERE p.document_id = %s ORDER BY u.username", (doc_id,))


def list_candidates(owner_id):
    return fetch_all(
        "SELECT id, username, role FROM users "
        "WHERE is_active AND role IN ('owner','viewer') AND id <> %s "
        "ORDER BY username", (owner_id,))


def upsert_permission(doc_id, user_id, level, granted_by):
    return execute_returning(
        "INSERT INTO permissions (document_id, user_id, access_level, granted_by) "
        "VALUES (%s,%s,%s,%s) ON CONFLICT (document_id, user_id) DO UPDATE "
        "SET access_level = EXCLUDED.access_level, granted_by = EXCLUDED.granted_by, "
        "granted_at = now() RETURNING id", (doc_id, user_id, level, granted_by))


def delete_permission(doc_id, user_id):
    """True if a permission existed and was removed."""
    return execute_returning(
        "DELETE FROM permissions WHERE document_id = %s AND user_id = %s RETURNING id",
        (doc_id, user_id)) is not None


# ------------------------------------------------------------ the access check
def access_level(user, doc):
    """'owner', 'edit', 'read' or None. Looked up in the DB on every call."""
    if user is None or doc is None:
        return None
    if doc["owner_id"] == user["id"]:
        # Ownership powers need the Owner ROLE. If an admin demotes someone, they
        # lose the right to share/delete/edit at once (they can still read their file).
        return "owner" if user["role"] == "owner" else "read"
    if user["role"] == "admin":
        return None                       # admins manage the system, not document contents
    level = get_permission(doc["id"], user["id"])
    if level == "edit" and user["role"] != "owner":
        return "read"                     # viewers can never edit
    return level


def require_access(doc_id, needed, action):
    """Return the document, or log DENIED and abort(403).
    Missing documents and forbidden documents give the SAME response."""
    doc = get_document(doc_id)
    level = access_level(g.user, doc)
    if level is None or RANK[level] < RANK[needed]:
        audit.log_event(action, audit.DENIED, user=g.user, document_id=doc_id,
                        ip_address=audit.client_ip(request),
                        details=f"needs {needed}; no access or not found")
        abort(403)
    return doc


# -------------------------------------------------------------------- routes
@perm_bp.route("/documents/<int:doc_id>/share")
@login_required
def share_page(doc_id):
    doc = require_access(doc_id, "owner", audit.GRANT)
    return render_template("share.html", doc=doc,
                           permissions=list_permissions(doc_id),
                           candidates=list_candidates(g.user["id"]),
                           events=audit.get_document_history(doc_id))


@perm_bp.route("/documents/<int:doc_id>/grant", methods=["POST"])
@login_required
def grant(doc_id):
    require_access(doc_id, "owner", audit.GRANT)
    ip = audit.client_ip(request)
    raw = request.form.get("user_id", "")
    level = request.form.get("access_level", "")
    target = get_user_by_id(int(raw)) if raw.isdigit() else None

    error = None
    if level not in ("read", "edit"):
        error = "Choose read or edit access."
    elif target is None or not target["is_active"] or target["role"] == "admin":
        error = "Choose a valid user."
    elif target["id"] == g.user["id"]:
        error = "You already own this document."
    elif level == "edit" and target["role"] != "owner":
        error = "Edit access can only be given to users with the Owner role."

    if error:
        audit.log_event(audit.GRANT, audit.FAILURE, user=g.user, document_id=doc_id,
                        target_user_id=target["id"] if target else None,
                        ip_address=ip, details=error)
        flash(error, "danger")
        return redirect(url_for("permissions.share_page", doc_id=doc_id))

    upsert_permission(doc_id, target["id"], level, g.user["id"])
    audit.log_event(audit.GRANT, audit.SUCCESS, user=g.user, document_id=doc_id,
                    target_user_id=target["id"], ip_address=ip,
                    details=f"{level} access to {target['username']}")
    flash(f"{target['username']} now has {level} access.", "success")
    return redirect(url_for("permissions.share_page", doc_id=doc_id))


@perm_bp.route("/documents/<int:doc_id>/revoke", methods=["POST"])
@login_required
def revoke(doc_id):
    require_access(doc_id, "owner", audit.REVOKE)
    ip = audit.client_ip(request)
    raw = request.form.get("user_id", "")
    target = get_user_by_id(int(raw)) if raw.isdigit() else None
    if target is None or not delete_permission(doc_id, target["id"]):
        audit.log_event(audit.REVOKE, audit.FAILURE, user=g.user, document_id=doc_id,
                        target_user_id=target["id"] if target else None,
                        ip_address=ip, details="no such permission")
        flash("That user does not have access.", "warning")
    else:
        audit.log_event(audit.REVOKE, audit.SUCCESS, user=g.user, document_id=doc_id,
                        target_user_id=target["id"], ip_address=ip,
                        details=f"revoked access from {target['username']}")
        flash(f"Access revoked from {target['username']}. It stops immediately.", "success")
    return redirect(url_for("permissions.share_page", doc_id=doc_id))
