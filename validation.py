from __future__ import annotations

import csv
import io
import mimetypes
import os
import string
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable


ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"
SUSPICIOUS = "SUSPICIOUS"

DEFAULT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    "pdf": {"application/pdf"},
    "png": {"image/png"},
    "jpg": {"image/jpeg"},
    "jpeg": {"image/jpeg"},
    "csv": {"text/csv", "application/csv", "application/vnd.ms-excel", "text/plain"},
}

EXECUTABLE_SIGNATURES = (
    (b"MZ", "Windows executable"),
    (b"\x7fELF", "Linux executable"),
    (b"\xca\xfe\xba\xbe", "Java class or Mach-O binary"),
)


@dataclass(frozen=True)
class ValidationResult:
    status: str
    reason: str
    extension: str
    claimed_content_type: str
    detected_type: str
    suspicious: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "extension": self.extension,
            "claimed_content_type": self.claimed_content_type,
            "detected_type": self.detected_type,
            "suspicious": self.suspicious,
        }


def max_file_size_bytes() -> int:
    raw_value = os.environ.get("MAX_FILE_SIZE_BYTES")
    if not raw_value:
        return DEFAULT_MAX_FILE_SIZE_BYTES

    try:
        parsed = int(raw_value)
    except ValueError:
        return DEFAULT_MAX_FILE_SIZE_BYTES

    return parsed if parsed > 0 else DEFAULT_MAX_FILE_SIZE_BYTES


def validate_file(
    *,
    filename: str,
    claimed_content_type: str | None,
    size_bytes: int,
    content_sample: bytes,
    max_size_bytes: int | None = None,
) -> ValidationResult:
    extension = extract_extension(filename)
    claimed = normalize_content_type(claimed_content_type)
    max_size = max_size_bytes or max_file_size_bytes()

    detected_type, executable_reason = detect_content_type(content_sample, extension)

    if not extension:
        return reject("File has no extension.", extension, claimed, detected_type)

    if extension not in ALLOWED_EXTENSIONS:
        return reject(
            f"File extension .{extension} is not allowed.",
            extension,
            claimed,
            detected_type,
        )

    if size_bytes > max_size:
        return reject(
            f"File size exceeded the limit of {max_size} bytes.",
            extension,
            claimed,
            detected_type,
        )

    if executable_reason:
        return suspicious(
            f"File spoofing detected: content looks like {executable_reason}.",
            extension,
            claimed,
            detected_type,
        )

    allowed_mime_types = ALLOWED_EXTENSIONS[extension]
    if claimed and claimed not in allowed_mime_types and not is_generic_content_type(claimed):
        return reject(
            f"Claimed MIME type {claimed} does not match .{extension}.",
            extension,
            claimed,
            detected_type,
        )

    if not detected_type:
        return reject(
            "Could not detect a valid file signature.",
            extension,
            claimed,
            detected_type,
        )

    if detected_type not in allowed_mime_types:
        return suspicious(
            f"File spoofing detected: .{extension} does not match detected type {detected_type}.",
            extension,
            claimed,
            detected_type,
        )

    if extension == "csv" and not is_valid_csv_sample(content_sample):
        return reject(
            "Invalid CSV content.",
            extension,
            claimed,
            detected_type,
        )

    return ValidationResult(
        status=ACCEPTED,
        reason="File passed validation.",
        extension=extension,
        claimed_content_type=claimed,
        detected_type=detected_type,
    )


def extract_extension(filename: str) -> str:
    suffix = PurePosixPath(filename or "").suffix
    return suffix[1:].lower() if suffix.startswith(".") else ""


def normalize_content_type(content_type: str | None) -> str:
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def is_generic_content_type(content_type: str) -> bool:
    return content_type in {"application/octet-stream", "binary/octet-stream"}


def detect_content_type(content: bytes, extension: str) -> tuple[str, str | None]:
    for signature, description in EXECUTABLE_SIGNATURES:
        if content.startswith(signature):
            return "application/x-msdownload", description

    if content.startswith(b"%PDF-"):
        return "application/pdf", None

    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", None

    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", None

    if extension == "csv" and looks_like_text(content):
        return "text/csv", None

    guessed, _ = mimetypes.guess_type(f"file.{extension}")
    return guessed or "", None


def looks_like_text(content: bytes) -> bool:
    if not content:
        return False

    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False

    allowed_control_chars = {"\n", "\r", "\t"}
    printable = set(string.printable)

    return all(char in printable or char in allowed_control_chars for char in text)


def is_valid_csv_sample(content: bytes) -> bool:
    if not looks_like_text(content):
        return False

    text = content.decode("utf-8-sig").strip()
    if not text:
        return False

    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error:
        return False

    non_empty_rows = [row for row in rows if any(cell.strip() for cell in row)]
    if not non_empty_rows:
        return False

    expected_columns = len(non_empty_rows[0])
    if expected_columns == 0:
        return False

    return all(len(row) == expected_columns for row in non_empty_rows)


def reject(
    reason: str,
    extension: str,
    claimed_content_type: str,
    detected_type: str,
) -> ValidationResult:
    return ValidationResult(
        status=REJECTED,
        reason=reason,
        extension=extension,
        claimed_content_type=claimed_content_type,
        detected_type=detected_type,
    )


def suspicious(
    reason: str,
    extension: str,
    claimed_content_type: str,
    detected_type: str,
) -> ValidationResult:
    return ValidationResult(
        status=SUSPICIOUS,
        reason=reason,
        extension=extension,
        claimed_content_type=claimed_content_type,
        detected_type=detected_type,
        suspicious=True,
    )


def accepted_statuses() -> Iterable[str]:
    return (ACCEPTED, REJECTED, SUSPICIOUS)
