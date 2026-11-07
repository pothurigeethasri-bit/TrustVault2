"""Emergency recovery when NO admin can sign in (the web reset needs an admin).
Needs database access, so it cannot be run by a website visitor.

    python reset_admin_password.py <username>

Prints a one-time temporary password; the user must change it at next sign-in.
The action is written to the audit log as PASSWORD_RESET_ADMIN by 'cli'.
"""
import sys

import audit
import auth


def main(username):
    user = auth.get_user_by_username(username.strip().lower())
    if not user:
        sys.exit("No such user.")
    temp = auth.generate_temp_password()
    auth.set_password(user["id"], temp, must_change=True)
    audit.log_event(audit.PASSWORD_RESET_ADMIN, audit.SUCCESS, username="cli",
                    target_user_id=user["id"], details=f"command-line reset for {user['username']}")
    print(f"Temporary password for {user['username']}: {temp}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
