"""Private file storage with two interchangeable backends.

  STORAGE_BACKEND=disk (default)  files live in UPLOAD_DIR, outside static/.
  STORAGE_BACKEND=db              file bytes live in the PostgreSQL table file_blobs.

Use `db` on hosts with an ephemeral disk (Render's free web service wipes the disk on
every deploy): documents then survive redeploys and are covered by the database's
own backups. Either way a file is reachable ONLY through the permission-checked
routes: there is no public URL, and the on-disk / in-database name is a random hex
string that never comes from the user.
"""
import os

import psycopg2
from flask import current_app

from database import execute, fetch_one

BACKENDS = ("disk", "db")


def _backend():
    return current_app.config["STORAGE_BACKEND"]


def _path(stored_name):
    return os.path.join(current_app.config["UPLOAD_DIR"], stored_name)


def save(stored_name, data):
    if _backend() == "db":
        execute("INSERT INTO file_blobs (stored_name, data) VALUES (%s, %s)",
                (stored_name, psycopg2.Binary(data)))
    else:
        with open(_path(stored_name), "wb") as fh:
            fh.write(data)


def load(stored_name):
    """Return the file's bytes, or None if it is missing."""
    if _backend() == "db":
        row = fetch_one("SELECT data FROM file_blobs WHERE stored_name = %s", (stored_name,))
        return bytes(row["data"]) if row else None
    try:
        with open(_path(stored_name), "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def delete(stored_name):
    if _backend() == "db":
        execute("DELETE FROM file_blobs WHERE stored_name = %s", (stored_name,))
    else:
        try:
            os.remove(_path(stored_name))
        except FileNotFoundError:
            pass
