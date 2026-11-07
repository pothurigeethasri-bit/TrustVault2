"""Admin console: user and role management, activity feeds, audit integrity check.

Every route here is admin-only (role_required). Every state change is written to
the audit trail, including rejected attempts.
"""
from flask import (Blueprint, flash, g, redirect, render_template, request,
                   url_for)

import audit
from auth import generate_temp_password, get_user_by_id, role_required, set_password
from database import execute, fetch_all

admin_bp = Blueprint("adminp", __name__)

ROLES = ("admin", "owner", "viewer")
PER_PAGE = 50
ALL_ACTIONS = (
    audit.LOGIN, audit.LOGOUT, audit.REGISTER, audit.UPLOAD, audit.VIEW,
    audit.DOWNLOAD, audit.EDIT, audit.DELETE_DOC, audit.GRANT, audit.REVOKE,
    audit.ROLE_CHANGE, audit.DEACTIVATE_USER, audit.ACTIVATE_USER,
    audit.CREATE_CATEGORY, audit.VALIDATION_FAIL, audit.ACCESS_DENIED,
    audit.CSRF_FAILURE, audit.INTEGRITY_CHECK, audit.PIN_ATTEMPT,
    audit.PASSWORD_CHANGE, audit.PASSWORD_RESET_ADMIN, audit.PASSWORD_RESET_REQUEST,
    audit.THROTTLED,
)


# --------------------------------------------------------------- DB functions
def list_users():
    return fetch_all(
        "SELECT u.id, u.username, u.role, u.is_active, u.created_at, u.reset_requested_at, "
        "  (SELECT count(*) FROM documents d WHERE d.owner_id = u.id) AS docs_owned, "
        "  (SELECT count(*) FROM permissions p WHERE p.user_id = u.id) AS docs_shared "
        "FROM users u ORDER BY u.username")


def set_role(user_id, role):
    execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))


def set_active(user_id, active):
    execute("UPDATE users SET is_active = %s WHERE id = %s", (active, user_id))


def _count(sql):
    return fetch_all(sql)[0]["n"]


# -------------------------------------------------------------------- helpers
def _page():
    raw = request.args.get("page", "1")
    return max(1, int(raw)) if raw.isdigit() and len(raw) < 7 else 1


def _feed(template_title, intro, endpoint, actions=None, only_problems=False,
          action_filter=False):
    """Render one filterable, paginated activity feed."""
    page = _page()
    username = request.args.get("user", "").strip()[:100] or None
    result = request.args.get("result", "")
    action = request.args.get("action", "")
    if action_filter and action in ALL_ACTIONS:
        actions = (action,)
    rows, total = audit.search_events(
        actions=actions, only_problems=only_problems, result=result or None,
        username=username, limit=PER_PAGE, offset=(page - 1) * PER_PAGE)
    pages = max(1, -(-total // PER_PAGE))
    return render_template(
        "admin_events.html", title=template_title, intro=intro, events=rows,
        total=total, page=page, pages=pages, endpoint=endpoint,
        f={"user": username or "", "result": result, "action": action},
        action_filter=action_filter, all_actions=ALL_ACTIONS,
        show_result_filter=not only_problems)


def _reject(action, target, message, ip):
    audit.log_event(action, audit.FAILURE, user=g.user, ip_address=ip,
                    target_user_id=target["id"] if target else None, details=message)
    flash(message, "danger")
    return redirect(url_for("adminp.users"))


# --------------------------------------------------------------------- pages
def overview():
    """Called by the /admin route in app.py (keeps url_for('admin') working)."""
    users = list_users()
    summary = audit.activity_summary(24)
    recent, _ = audit.search_events(limit=8)
    last_check, _ = audit.search_events(actions=(audit.INTEGRITY_CHECK,), limit=1)
    stats = {
        "users": len(users),
        "active": sum(1 for u in users if u["is_active"]),
        "documents": _count("SELECT count(*) AS n FROM documents"),
        "grants": _count("SELECT count(*) AS n FROM permissions"),
    }
    return render_template("admin_dashboard.html", stats=stats, summary=summary,
                           recent=recent, last_check=last_check[0] if last_check else None)


@admin_bp.route("/admin/users")
@role_required("admin")
def users():
    return render_template("admin_users.html", users=list_users(), roles=ROLES)


@admin_bp.route("/admin/activity")
@role_required("admin")
def activity():
    return _feed("Document activity",
                 "Every upload, view, download, edit and delete, including denied attempts.",
                 "adminp.activity", actions=audit.DOCUMENT_ACTIONS)


@admin_bp.route("/admin/permissions")
@role_required("admin")
def permission_changes():
    return _feed("Permission changes",
                 "Every grant, revoke, role change and account activation.",
                 "adminp.permission_changes", actions=audit.PERMISSION_ACTIONS)


@admin_bp.route("/admin/security")
@role_required("admin")
def security_events():
    return _feed("Security events",
                 "Denied and failed attempts: wrong passwords, blocked access, CSRF and bad uploads.",
                 "adminp.security_events", only_problems=True)


@admin_bp.route("/admin/audit")
@role_required("admin")
def audit_log():
    return _feed("Full audit log",
                 "The complete, append-only record. Nobody can edit or delete these rows.",
                 "adminp.audit_log", action_filter=True)


# ------------------------------------------------------------ state changes
@admin_bp.route("/admin/users/<int:user_id>/role", methods=["POST"])
@role_required("admin")
def change_role(user_id):
    ip = audit.client_ip(request)
    new_role = request.form.get("role", "")
    target = get_user_by_id(user_id)
    if target is None:
        return _reject(audit.ROLE_CHANGE, None, "No such user.", ip)
    if new_role not in ROLES:
        return _reject(audit.ROLE_CHANGE, target, "Choose a valid role.", ip)
    if target["id"] == g.user["id"]:
        return _reject(audit.ROLE_CHANGE, target, "You cannot change your own role.", ip)
    if target["role"] == new_role:
        flash(f"{target['username']} is already {new_role}.", "info")
        return redirect(url_for("adminp.users"))
    set_role(target["id"], new_role)
    audit.log_event(audit.ROLE_CHANGE, audit.SUCCESS, user=g.user, target_user_id=target["id"],
                    ip_address=ip, details=f"{target['username']}: {target['role']} -> {new_role}")
    flash(f"{target['username']} is now {new_role}. It applies on their next request.", "success")
    return redirect(url_for("adminp.users"))


@admin_bp.route("/admin/users/<int:user_id>/active", methods=["POST"])
@role_required("admin")
def change_active(user_id):
    ip = audit.client_ip(request)
    want_active = request.form.get("active") == "1"
    action = audit.ACTIVATE_USER if want_active else audit.DEACTIVATE_USER
    target = get_user_by_id(user_id)
    if target is None:
        return _reject(action, None, "No such user.", ip)
    if target["id"] == g.user["id"]:
        return _reject(action, target, "You cannot deactivate your own account.", ip)
    if bool(target["is_active"]) == want_active:
        flash(f"{target['username']} is already {'active' if want_active else 'deactivated'}.", "info")
        return redirect(url_for("adminp.users"))
    set_active(target["id"], want_active)
    audit.log_event(action, audit.SUCCESS, user=g.user, target_user_id=target["id"],
                    ip_address=ip, details=target["username"])
    flash(f"{target['username']} has been {'reactivated' if want_active else 'deactivated and signed out'}.",
          "success")
    return redirect(url_for("adminp.users"))


@admin_bp.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@role_required("admin")
def reset_password(user_id):
    """Issue a one-time temporary password. It is shown ONCE on this response, is never stored in
    readable form (only its hash) and never written to the audit log. The user must change it at
    next sign-in, every older session of theirs is ended, and any lockout is cleared."""
    ip = audit.client_ip(request)
    target = get_user_by_id(user_id)
    if target is None:
        return _reject(audit.PASSWORD_RESET_ADMIN, None, "No such user.", ip)
    if target["id"] == g.user["id"]:
        return _reject(audit.PASSWORD_RESET_ADMIN, target,
                       "Use 'Change password' for your own account.", ip)
    temp = generate_temp_password()
    set_password(target["id"], temp, must_change=True)
    audit.log_event(audit.PASSWORD_RESET_ADMIN, audit.SUCCESS, user=g.user,
                    target_user_id=target["id"], ip_address=ip,
                    details=f"temporary password issued for {target['username']}")
    return render_template("admin_users.html", users=list_users(), roles=ROLES,
                           temp=(target["username"], temp))


@admin_bp.route("/admin/integrity", methods=["POST"])
@role_required("admin")
def integrity_check():
    """Recompute the whole hash chain and report whether the log was tampered with."""
    ok, bad_id = audit.verify_chain()
    _rows, total = audit.search_events(limit=1)
    if ok:
        msg = f"Chain intact: all {total} audit rows verified."
        audit.log_event(audit.INTEGRITY_CHECK, audit.SUCCESS, user=g.user,
                        ip_address=audit.client_ip(request), details=msg)
        flash(msg, "success")
    else:
        msg = f"TAMPERING DETECTED: the chain breaks at audit row {bad_id}."
        audit.log_event(audit.INTEGRITY_CHECK, audit.FAILURE, user=g.user,
                        ip_address=audit.client_ip(request), details=msg)
        flash(msg, "danger")
    return redirect(url_for("admin"))
