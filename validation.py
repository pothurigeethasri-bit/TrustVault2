"""Upload validation: file name, type, size, and real content (magic bytes)."""
import io
import re
import zipfile

from werkzeug.utils import secure_filename


class ValidationError(ValueError):
    pass


# Files a browser can show inline. Only these can be shared as "view only"; every other
# type can only be opened by downloading it.
INLINE_TYPES = {"application/pdf", "image/png", "image/jpeg", "text/plain"}

EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9\-]+(\.[a-z0-9\-]+)*\.[a-z]{2,}$")


def normalise_email(raw):
    """Lower-cased, trimmed e-mail address, or None if it is not a plausible address."""
    email = (raw or "").strip().lower()
    return email if len(email) <= 254 and EMAIL_RE.match(email) else None


TYPES = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "txt": "text/plain",
    "csv": "text/csv",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
ZIP_MARKERS = {"docx": "word/document.xml", "xlsx": "xl/workbook.xml",
               "pptx": "ppt/presentation.xml"}
MAX_NAME_LEN = 150
MAX_ZIP_ENTRIES = 5000
MAX_UNZIPPED_BYTES = 200 * 1024 * 1024        # zip-bomb guard


def _check_content(ext, data):
    if ext == "pdf":
        ok = data.startswith(b"%PDF-")
    elif ext == "png":
        ok = data.startswith(b"\x89PNG\r\n\x1a\n")
    elif ext in ("jpg", "jpeg"):
        ok = data.startswith(b"\xff\xd8\xff")
    elif ext in ("txt", "csv"):
        try:
            data.decode("utf-8")
            ok = b"\x00" not in data
        except UnicodeDecodeError:
            ok = False
    else:  # Office files are zip containers with a known main part
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = zf.infolist()
                ok = (len(infos) <= MAX_ZIP_ENTRIES
                      and sum(i.file_size for i in infos) <= MAX_UNZIPPED_BYTES
                      and ZIP_MARKERS[ext] in zf.namelist())
        except zipfile.BadZipFile:
            ok = False
    if not ok:
        raise ValidationError("File content does not match its file type.")


def validate_upload(filename, data, max_bytes):
    """Return (clean_name, extension, mime). Raise ValidationError if unacceptable."""
    if not data:
        raise ValidationError("The file is empty.")
    if len(data) > max_bytes:
        raise ValidationError(f"File is larger than {max_bytes // (1024 * 1024)} MB.")
    name = secure_filename(filename or "")
    if not name or "." not in name:
        raise ValidationError("Invalid file name. Use letters, numbers and a file extension.")
    ext = name.rsplit(".", 1)[1].lower()
    if ext not in TYPES:
        raise ValidationError("File type not allowed. Allowed: " + ", ".join(sorted(TYPES)) + ".")
    if len(name) > MAX_NAME_LEN:
        name = name[: MAX_NAME_LEN - len(ext) - 1] + "." + ext
    _check_content(ext, data)
    return name, ext, TYPES[ext]
