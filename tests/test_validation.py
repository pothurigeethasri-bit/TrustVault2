import io
import zipfile

import pytest

from validation import ValidationError, validate_upload

MB = 1024 * 1024


def make_zip(member):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(member, "<x/>")
    return buf.getvalue()


def test_valid_files_accepted():
    assert validate_upload("Salary_Letter.pdf", b"%PDF-1.7 data", MB)[1:] == ("pdf", "application/pdf")
    assert validate_upload("a.png", b"\x89PNG\r\n\x1a\n...", MB)[1] == "png"
    assert validate_upload("a.jpg", b"\xff\xd8\xff\xe0...", MB)[1] == "jpg"
    assert validate_upload("n.txt", "héllo".encode(), MB)[1] == "txt"
    assert validate_upload("d.docx", make_zip("word/document.xml"), MB)[1] == "docx"
    assert validate_upload("s.xlsx", make_zip("xl/workbook.xml"), MB)[1] == "xlsx"


@pytest.mark.parametrize("name,data", [
    ("virus.exe", b"MZ..."),                       # type not allowed
    ("shell.php", b"<?php ?>"),
    ("page.html", b"<script>"),
    ("fake.pdf", b"MZ\x90\x00 not a pdf"),         # wrong content for extension
    ("fake.png", b"%PDF-1.4"),
    ("fake.docx", b"just text"),                   # not a zip
    ("fake.docx", make_zip("xl/workbook.xml")),    # zip but wrong office type
    ("bin.txt", b"abc\x00def"),                    # binary pretending to be text
    ("noext", b"%PDF-1.4"),
    ("..", b"%PDF-1.4"),
])
def test_bad_files_rejected(name, data):
    with pytest.raises(ValidationError):
        validate_upload(name, data, MB)


def test_empty_and_oversize_rejected():
    with pytest.raises(ValidationError):
        validate_upload("a.pdf", b"", MB)
    with pytest.raises(ValidationError):
        validate_upload("a.pdf", b"%PDF-" + b"x" * MB, MB)


def test_path_traversal_name_is_sanitised():
    name, ext, _ = validate_upload("../../etc/passwd.pdf", b"%PDF-1", MB)
    assert "/" not in name and ".." not in name and ext == "pdf"
