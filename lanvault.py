#!/usr/bin/env python3
"""LanVault: a single-account, dependency-free file server for a trusted LAN."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass
from email.utils import formatdate
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, quote, urlsplit

APP_NAME = "LanVault"
VERSION = "1.1.0"
SESSION_COOKIE = "lanvault_session"
REQUEST_HEADER = "X-LanVault-Request"
PASSWORD_ENV = "LANVAULT_PASSWORD"
PBKDF2_ITERATIONS = 600_000
CHUNK_SIZE = 128 * 1024
MAX_JSON_BODY = 64 * 1024
MAX_NAME_BYTES = 255
MAX_REL_PATH_CHARS = 8192
DRAIN_ON_CONFLICT = 64 * 1024
MAX_QUICK_ACCESS = 64
MAX_PUBLIC_KEYS = 16
CHALLENGE_TTL = 60
MAX_CHALLENGES_PER_CLIENT = 8
WEB_DIR = Path(__file__).resolve().parent / "web"


def default_state_file() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base).expanduser() / "lanvault" / "quick-access.json"

STATIC_FILES = {
    "app.js": "text/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "favicon.svg": "image/svg+xml",
}

PREVIEW_IMAGE_MIME = {
    "avif": "image/avif",
    "bmp": "image/bmp",
    "gif": "image/gif",
    "ico": "image/x-icon",
    "jpeg": "image/jpeg",
    "jpg": "image/jpeg",
    "png": "image/png",
    "svg": "image/svg+xml",
    "webp": "image/webp",
}
PREVIEW_VIDEO_MIME = {
    "m4v": "video/mp4",
    "mov": "video/quicktime",
    "mp4": "video/mp4",
    "ogv": "video/ogg",
    "webm": "video/webm",
}
PREVIEW_AUDIO_MIME = {
    "aac": "audio/aac",
    "flac": "audio/flac",
    "m4a": "audio/mp4",
    "mp3": "audio/mpeg",
    "oga": "audio/ogg",
    "ogg": "audio/ogg",
    "opus": "audio/ogg",
    "wav": "audio/wav",
    "weba": "audio/webm",
}
PREVIEW_TEXT_EXTENSIONS = {
    "adoc",
    "asm",
    "bash",
    "bat",
    "bib",
    "c",
    "cc",
    "cfg",
    "cmd",
    "conf",
    "cpp",
    "cs",
    "css",
    "csv",
    "cxx",
    "diff",
    "env",
    "fish",
    "go",
    "h",
    "hh",
    "hpp",
    "htm",
    "html",
    "ini",
    "java",
    "js",
    "json",
    "jsonl",
    "jsx",
    "kt",
    "kts",
    "less",
    "log",
    "lua",
    "m",
    "markdown",
    "md",
    "mjs",
    "patch",
    "php",
    "pl",
    "ps1",
    "py",
    "r",
    "rb",
    "rst",
    "rs",
    "sass",
    "scala",
    "scss",
    "sh",
    "sql",
    "srt",
    "swift",
    "tex",
    "toml",
    "ts",
    "tsv",
    "tsx",
    "txt",
    "vb",
    "vtt",
    "vue",
    "xml",
    "yaml",
    "yml",
    "zsh",
}

INDEX_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; media-src 'self'; frame-src 'self'; "
    "connect-src 'self'; form-action 'self'; base-uri 'none'; "
    "frame-ancestors 'none'"
)
STRICT_CSP = "default-src 'none'; frame-ancestors 'none'"

logger = logging.getLogger("lanvault")


@dataclass(frozen=True)
class Config:
    root: Path
    username: str
    password_salt: bytes
    password_digest: bytes
    state_file: Path
    keys_file: Path
    password_iterations: int = PBKDF2_ITERATIONS
    session_ttl: int = 12 * 60 * 60
    max_upload: int | None = None
    secure_cookie: bool = False
    web_dir: Path = WEB_DIR


class RequestError(Exception):
    def __init__(
        self,
        status: int | HTTPStatus,
        message: str,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = int(status)
        self.message = message
        self.headers = dict(headers or {})


class SessionStore:
    def __init__(self, ttl: int) -> None:
        self.ttl = ttl
        self._sessions: dict[bytes, float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(token: str) -> bytes:
        return hashlib.sha256(token.encode("utf-8", "surrogatepass")).digest()

    def create(self) -> str:
        token = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            self._sessions[self._key(token)] = now + self.ttl
        return token

    def is_valid(self, token: str) -> bool:
        key = self._key(token)
        now = time.monotonic()
        with self._lock:
            expires = self._sessions.get(key)
            if expires is None:
                return False
            if expires <= now:
                del self._sessions[key]
                return False
            return True

    def revoke(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(self._key(token), None)

    def _purge(self, now: float) -> None:
        expired = [key for key, expires in self._sessions.items() if expires <= now]
        for key in expired:
            del self._sessions[key]


class LoginLimiter:
    def __init__(self, max_failures: int = 8, window: int = 300) -> None:
        self.max_failures = max_failures
        self.window = window
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def retry_after(self, client: str) -> int:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            failures = self._failures.get(client)
            if not failures:
                return 0
            while failures and failures[0] < cutoff:
                failures.popleft()
            if not failures:
                del self._failures[client]
                return 0
            if len(failures) < self.max_failures:
                return 0
            return max(1, int(failures[0] + self.window - now) + 1)

    def record_failure(self, client: str) -> None:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            failures = self._failures.setdefault(client, deque())
            while failures and failures[0] < cutoff:
                failures.popleft()
            failures.append(now)

    def clear(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)


class ChallengeStore:
    """Single-use sign-in challenges bound to a client address."""

    def __init__(self, ttl: int = CHALLENGE_TTL) -> None:
        self.ttl = ttl
        self._challenges: dict[str, tuple[str, bytes, float]] = {}
        self._lock = threading.Lock()

    def create(self, client: str) -> tuple[str, str] | None:
        """Return (id, nonce_hex); None when the per-client limit is reached."""
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            pending = sum(
                1 for item_client, _, _ in self._challenges.values() if item_client == client
            )
            if pending >= MAX_CHALLENGES_PER_CLIENT:
                return None
            challenge_id = secrets.token_urlsafe(18)
            self._challenges[challenge_id] = (client, os.urandom(32), now + self.ttl)
            nonce = self._challenges[challenge_id][1]
            return challenge_id, nonce.hex()

    def consume(self, client: str, challenge_id: str) -> bytes | None:
        """Return the nonce when the challenge is valid for this client; always one-shot."""
        now = time.monotonic()
        with self._lock:
            item = self._challenges.pop(challenge_id, None)
            if item is None:
                return None
            item_client, nonce, expires = item
            if item_client != client or expires <= now:
                return None
            return nonce

    def _purge(self, now: float) -> None:
        expired = [
            key
            for key, (_, _, expires) in self._challenges.items()
            if expires <= now
        ]
        for key in expired:
            del self._challenges[key]


class QuickAccessStore:
    """Per-user quick access entries persisted in one JSON file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._users: dict[str, list[dict[str, Any]]] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return
        except OSError as exc:
            logger.warning("Cannot read quick access file %s: %s", self.path, exc)
            return
        try:
            data = json.loads(raw.decode("utf-8"))
            users = data.get("users", {})
            if not isinstance(users, dict):
                raise ValueError("users must be an object")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("Ignoring invalid quick access file %s: %s", self.path, exc)
            return
        for user, items in users.items():
            if not isinstance(user, str) or not isinstance(items, list):
                continue
            cleaned: list[dict[str, Any]] = []
            for item in items:
                if len(cleaned) >= MAX_QUICK_ACCESS:
                    break
                if not isinstance(item, dict):
                    continue
                item_path = item.get("path")
                item_name = item.get("name")
                is_dir = item.get("isDir")
                preview = item.get("preview")
                if not isinstance(item_path, str) or not isinstance(item_name, str):
                    continue
                if not isinstance(is_dir, bool):
                    continue
                if preview is not None and not isinstance(preview, str):
                    preview = None
                cleaned.append(
                    {
                        "path": item_path,
                        "name": item_name,
                        "isDir": is_dir,
                        "preview": preview,
                    }
                )
            if cleaned:
                self._users[user] = cleaned

    def entries(self, user: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._users.get(user, [])]

    def add(self, user: str, entry: dict[str, Any]) -> str:
        """Return "added", "duplicate", or "full"."""
        with self._lock:
            items = self._users.setdefault(user, [])
            if any(item["path"] == entry["path"] for item in items):
                return "duplicate"
            if len(items) >= MAX_QUICK_ACCESS:
                return "full"
            items.append(dict(entry))
            try:
                self._save_locked()
            except OSError:
                items.pop()
                raise
            return "added"

    def remove(self, user: str, path: str) -> bool:
        with self._lock:
            items = self._users.get(user, [])
            kept = [item for item in items if item["path"] != path]
            if len(kept) == len(items):
                return False
            previous = self._users[user]
            self._users[user] = kept
            try:
                self._save_locked()
            except OSError:
                self._users[user] = previous
                raise
            return True

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {"version": 1, "users": self._users},
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        descriptor, temp_name = tempfile.mkstemp(
            prefix=".quick-access-",
            suffix=".tmp",
            dir=self.path.parent,
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, self.path)
        except OSError:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise


class PublicKeyLimitError(Exception):
    """Raised when a user already has the maximum number of sign-in keys."""


class PublicKeyStore:
    """Per-user public keys for passwordless sign-in, persisted in one JSON file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._users: dict[str, list[dict[str, Any]]] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return
        except OSError as exc:
            logger.warning("Cannot read public key file %s: %s", self.path, exc)
            return
        try:
            data = json.loads(raw.decode("utf-8"))
            users = data.get("users", {})
            if not isinstance(users, dict):
                raise ValueError("users must be an object")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("Ignoring invalid public key file %s: %s", self.path, exc)
            return
        for user, items in users.items():
            if not isinstance(user, str) or not isinstance(items, list):
                continue
            cleaned: list[dict[str, Any]] = []
            for item in items:
                if len(cleaned) >= MAX_PUBLIC_KEYS:
                    break
                if not isinstance(item, dict):
                    continue
                key_id = item.get("id")
                public_key = item.get("public_key")
                fingerprint = item.get("fingerprint")
                label = item.get("label")
                created_at = item.get("created_at")
                last_used_at = item.get("last_used_at")
                if not isinstance(key_id, str) or not isinstance(public_key, str):
                    continue
                if not isinstance(fingerprint, str) or not isinstance(label, str):
                    continue
                if not isinstance(created_at, (int, float)):
                    continue
                if not isinstance(last_used_at, (int, float)):
                    last_used_at = created_at
                cleaned.append(
                    {
                        "id": key_id,
                        "public_key": public_key,
                        "fingerprint": fingerprint,
                        "label": label,
                        "created_at": float(created_at),
                        "last_used_at": float(last_used_at),
                    }
                )
            if cleaned:
                self._users[user] = cleaned

    def records(self, user: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._users.get(user, [])]

    def add(
        self, user: str, public_key: str, fingerprint: str, label: str
    ) -> tuple[dict[str, Any], bool]:
        """Add a key or return the existing one. Raises PublicKeyLimitError when full."""
        with self._lock:
            items = self._users.setdefault(user, [])
            for item in items:
                if item["fingerprint"] == fingerprint:
                    return dict(item), False
            if len(items) >= MAX_PUBLIC_KEYS:
                raise PublicKeyLimitError
            now = time.time()
            record = {
                "id": secrets.token_hex(8),
                "public_key": public_key,
                "fingerprint": fingerprint,
                "label": label,
                "created_at": now,
                "last_used_at": now,
            }
            items.append(record)
            try:
                self._save_locked()
            except OSError:
                items.pop()
                raise
            return dict(record), True

    def touch(self, user: str, key_id: str) -> None:
        with self._lock:
            for item in self._users.get(user, []):
                if item["id"] == key_id:
                    item["last_used_at"] = time.time()
                    try:
                        self._save_locked()
                    except OSError:
                        pass
                    return

    def remove(self, user: str, key_id: str) -> bool:
        with self._lock:
            items = self._users.get(user, [])
            kept = [item for item in items if item["id"] != key_id]
            if len(kept) == len(items):
                return False
            previous = self._users[user]
            self._users[user] = kept
            try:
                self._save_locked()
            except OSError:
                self._users[user] = previous
                raise
            if not kept:
                self._users.pop(user, None)
            return True

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {"version": 1, "users": self._users},
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        descriptor, temp_name = tempfile.mkstemp(
            prefix=".public-keys-",
            suffix=".tmp",
            dir=self.path.parent,
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, self.path)
        except OSError:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise


def create_config(
    root: Path | str,
    username: str,
    password: str,
    *,
    state_file: Path | str | None = None,
    session_ttl: int = 12 * 60 * 60,
    max_upload: int | None = None,
    secure_cookie: bool = False,
    iterations: int = PBKDF2_ITERATIONS,
) -> Config:
    root_path = Path(root).expanduser().resolve()
    if not root_path.is_dir():
        raise ValueError(f"Root is not a directory: {root_path}")
    if not isinstance(username, str) or not username or any(
        ord(char) < 32 or ord(char) == 127 for char in username
    ):
        raise ValueError("Username must be a non-empty single-line string.")
    if len(username.encode("utf-8")) > 128:
        raise ValueError("Username is too long.")
    if not isinstance(password, str) or not password:
        raise ValueError("Password must not be empty.")
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 1024:
        raise ValueError("Password is longer than 1024 bytes.")
    if session_ttl <= 0:
        raise ValueError("Session lifetime must be positive.")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, iterations)
    resolved_state_file = (
        Path(state_file).expanduser().resolve()
        if state_file is not None
        else default_state_file()
    )
    return Config(
        root=root_path,
        username=username,
        password_salt=salt,
        password_digest=digest,
        state_file=resolved_state_file,
        keys_file=resolved_state_file.with_name("public-keys.json"),
        password_iterations=iterations,
        session_ttl=int(session_ttl),
        max_upload=max_upload,
        secure_cookie=secure_cookie,
        web_dir=WEB_DIR,
    )


def verify_credentials(config: Config, username: str, password: str) -> bool:
    if not isinstance(username, str) or not isinstance(password, str):
        return False
    try:
        password_bytes = password.encode("utf-8")
        username_bytes = username.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if len(password_bytes) > 1024:
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256", password_bytes, config.password_salt, config.password_iterations
    )
    user_ok = hmac.compare_digest(username_bytes, config.username.encode("utf-8"))
    password_ok = hmac.compare_digest(digest, config.password_digest)
    return user_ok and password_ok


def _p256_der_from_raw(signature: bytes) -> bytes | None:
    """Convert a raw r||s ECDSA signature (64 bytes) to DER."""

    def encode_int(value: bytes) -> bytes:
        body = value.lstrip(b"\x00")
        if not body:
            body = b"\x00"
        if body[0] & 0x80:
            body = b"\x00" + body
        return b"\x02" + bytes([len(body)]) + body

    if len(signature) != 64:
        return None
    content = encode_int(signature[:32]) + encode_int(signature[32:])
    return b"\x30" + bytes([len(content)]) + content


def validate_public_key_pem(pem: str) -> bool:
    """Return True when openssl can parse pem as a public key."""
    with tempfile.TemporaryDirectory(prefix="lanvault-key-") as tmp:
        key_file = Path(tmp) / "key.pem"
        try:
            key_file.write_text(pem, encoding="utf-8")
            result = subprocess.run(
                ["openssl", "pkey", "-pubin", "-in", str(key_file), "-noout"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            return False
    return result.returncode == 0


def verify_public_key_signature(pem: str, message: bytes, signature: bytes) -> bool:
    """Verify an ECDSA/RSA signature over message with openssl."""
    if len(signature) == 64:
        # WebCrypto emits raw r||s for P-256; openssl expects DER.
        der = _p256_der_from_raw(signature)
        if der is None:
            return False
        signature = der
    with tempfile.TemporaryDirectory(prefix="lanvault-verify-") as tmp:
        tmp_path = Path(tmp)
        key_file = tmp_path / "key.pem"
        message_file = tmp_path / "message.bin"
        signature_file = tmp_path / "signature.der"
        try:
            key_file.write_text(pem, encoding="utf-8")
            message_file.write_bytes(message)
            signature_file.write_bytes(signature)
            result = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(key_file),
                    "-signature",
                    str(signature_file),
                    str(message_file),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            return False
    return result.returncode == 0


def _sanitize_device_label(user_agent: str) -> str:
    cleaned = "".join(ch for ch in user_agent if 32 <= ord(ch) < 127).strip()
    return cleaned[:80] or "Unknown device"


def _is_within(root: Path, candidate: Path) -> bool:
    return candidate == root or root in candidate.parents


def normalize_relative_path(raw: str) -> list[str]:
    if not isinstance(raw, str):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Path must be a string.")
    if len(raw) > MAX_REL_PATH_CHARS:
        raise RequestError(HTTPStatus.REQUEST_URI_TOO_LONG, "Path is too long.")
    try:
        raw.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RequestError(HTTPStatus.BAD_REQUEST, "Path is not valid UTF-8.") from exc
    if "\x00" in raw:
        raise RequestError(HTTPStatus.BAD_REQUEST, "Path contains a NUL byte.")
    if raw.startswith("/"):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Path must be relative to the shared root.")
    parts: list[str] = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise RequestError(HTTPStatus.FORBIDDEN, "Path traversal is not allowed.")
        if os.sep != "/" and os.sep in part:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Backslashes are not allowed in paths.")
        if os.altsep and os.altsep != "/" and os.altsep in part:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Backslashes are not allowed in paths.")
        parts.append(part)
    return parts


def resolve_relative(root: Path, parts: list[str]) -> Path:
    candidate = root.joinpath(*parts)
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid path.") from exc
    if not _is_within(root, resolved):
        raise RequestError(HTTPStatus.FORBIDDEN, "Path escapes the shared folder.")
    return resolved


def validate_name(name: Any) -> str:
    if not isinstance(name, str):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Name must be a string.")
    if name in ("", ".", ".."):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid name.")
    separators = {"/", os.sep}
    if os.altsep:
        separators.add(os.altsep)
    if any(separator and separator in name for separator in separators):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Name must not contain a path separator.")
    if "\x00" in name or any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Name contains control characters.")
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RequestError(HTTPStatus.BAD_REQUEST, "Name is not valid UTF-8.") from exc
    if len(encoded) > MAX_NAME_BYTES:
        raise RequestError(HTTPStatus.BAD_REQUEST, "Name is longer than 255 bytes.")
    return name


def content_disposition(filename: str, disposition: str = "attachment") -> str:
    fallback = "".join(
        char
        if 32 <= ord(char) <= 126 and char not in {'"', "\\"}
        else "_"
        for char in filename
    )
    fallback = fallback.strip() or ("preview" if disposition == "inline" else "download")
    return (
        f"{disposition}; filename=\"{fallback}\"; "
        f"filename*=UTF-8''{quote(filename, safe='')}"
    )


def preview_kind(filename: str) -> str | None:
    lower = filename.lower()
    if lower == ".env":
        return "text"
    if "." not in lower:
        return None
    extension = lower.rsplit(".", 1)[1]
    if extension in PREVIEW_IMAGE_MIME:
        return "image"
    if extension in PREVIEW_VIDEO_MIME:
        return "video"
    if extension in PREVIEW_AUDIO_MIME:
        return "audio"
    if extension == "pdf":
        return "pdf"
    if extension in PREVIEW_TEXT_EXTENSIONS:
        return "text"
    return None


def preview_content_type(filename: str, kind: str) -> str:
    extension = filename.lower().rsplit(".", 1)[-1]
    if kind == "image":
        return PREVIEW_IMAGE_MIME[extension]
    if kind == "video":
        return PREVIEW_VIDEO_MIME[extension]
    if kind == "audio":
        return PREVIEW_AUDIO_MIME[extension]
    if kind == "pdf":
        return "application/pdf"
    return "text/plain; charset=utf-8"


def preview_csp(filename: str, kind: str) -> str:
    if kind == "image" and filename.lower().endswith(".svg"):
        return (
            "sandbox; default-src 'none'; style-src 'unsafe-inline'; "
            "img-src data:; frame-ancestors 'self'"
        )
    return "sandbox; frame-ancestors 'self'"


def parse_range(header: str, size: int) -> tuple[int, int] | None:
    if not header.startswith("bytes="):
        return None
    spec = header[6:].strip()
    if not spec or "," in spec:
        raise RequestError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Only a single byte range is supported.",
            {"Content-Range": f"bytes */{size}"},
        )
    match = re.fullmatch(r"(\d*)-(\d*)", spec)
    if not match:
        raise RequestError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Invalid byte range.",
            {"Content-Range": f"bytes */{size}"},
        )
    start_text, end_text = match.groups()
    if not start_text and not end_text:
        raise RequestError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Invalid byte range.",
            {"Content-Range": f"bytes */{size}"},
        )
    if size <= 0:
        raise RequestError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Empty files do not support byte ranges.",
            {"Content-Range": f"bytes */{size}"},
        )
    if not start_text:
        suffix = int(end_text)
        if suffix <= 0:
            raise RequestError(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "Invalid byte range.",
                {"Content-Range": f"bytes */{size}"},
            )
        start = max(0, size - suffix)
        end = size - 1
    else:
        start = int(start_text)
        if start >= size:
            raise RequestError(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "Byte range starts beyond the end of the file.",
                {"Content-Range": f"bytes */{size}"},
            )
        end = int(end_text) if end_text else size - 1
        if end < start:
            raise RequestError(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "Invalid byte range.",
                {"Content-Range": f"bytes */{size}"},
            )
        end = min(end, size - 1)
    return start, end


def _etag_matches(header_value: str, etag: str) -> bool:
    for candidate in header_value.split(","):
        candidate = candidate.strip()
        if candidate == "*" or candidate == etag:
            return True
    return False


class LanVaultServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address: tuple[str, int], config: Config) -> None:
        self.config = config
        self.sessions = SessionStore(config.session_ttl)
        self.login_limiter = LoginLimiter()
        self.quick_access = QuickAccessStore(config.state_file)
        self.public_keys = PublicKeyStore(config.keys_file)
        self.challenges = ChallengeStore()
        self.public_key_auth = shutil.which("openssl") is not None
        if not self.public_key_auth:
            logger.warning(
                "openssl not found; passwordless public-key sign-in is disabled."
            )
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, LanVaultHandler)

    def handle_error(self, _request: Any, client_address: Any) -> None:
        logger.exception("Unhandled error while serving %s", client_address)


class LanVaultHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"LanVault/{VERSION}"
    timeout = 120

    def version_string(self) -> str:
        return self.server_version

    @property
    def config(self) -> Config:
        return self.server.config  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        self._handle("GET")

    def do_HEAD(self) -> None:
        self._handle("HEAD")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def log_request(self, code: int | str = "-", _size: int | str = "-") -> None:
        path = urlsplit(self.path).path
        logger.info("%s %s %s -> %s", self.client_address[0], self.command, path, code)

    def _handle(self, method: str) -> None:
        self._responded = False
        self._query: dict[str, list[str]] = {}
        try:
            split = urlsplit(self.path)
            self._query = parse_qs(
                split.query,
                keep_blank_values=True,
                max_num_fields=32,
                separator="&",
            )
            route = split.path

            if route in ("/", "/index.html") and method in ("GET", "HEAD"):
                self._serve_index(head=method == "HEAD")
                return
            if route.startswith("/static/") and method in ("GET", "HEAD"):
                self._serve_static(route[len("/static/") :], head=method == "HEAD")
                return
            if route.startswith("/api/"):
                self._handle_api(method, route)
                return
            raise RequestError(HTTPStatus.NOT_FOUND, "Not found.")
        except RequestError as exc:
            self._send_error(exc)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except ValueError:
            logger.exception("Invalid request from %s", self.client_address[0])
            self._send_error(RequestError(HTTPStatus.BAD_REQUEST, "Malformed request."))
        except Exception:
            logger.exception("Failed to handle %s %s", method, self.path)
            self._send_error(RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error."))

    def _handle_api(self, method: str, route: str) -> None:
        if route == "/api/login" and method == "POST":
            self._api_login()
            return
        if route == "/api/session" and method == "GET":
            self._require_auth()
            self._api_session()
            return
        if route == "/api/logout" and method == "POST":
            self._require_request_header()
            self._api_logout()
            return
        if route == "/api/auth/challenge" and method == "POST":
            self._require_request_header()
            self._api_auth_challenge()
            return
        if route == "/api/auth/verify" and method == "POST":
            self._require_request_header()
            self._api_auth_verify()
            return
        if route == "/api/auth/keys" and method == "GET":
            self._require_auth()
            self._api_auth_keys_list()
            return
        if route == "/api/auth/keys" and method == "POST":
            self._require_auth()
            self._require_request_header()
            self._api_auth_keys_add()
            return
        if route == "/api/auth/keys/remove" and method == "POST":
            self._require_auth()
            self._require_request_header()
            self._api_auth_keys_remove()
            return
        if route == "/api/list" and method == "GET":
            self._require_auth()
            self._api_list()
            return
        if route == "/api/download" and method in ("GET", "HEAD"):
            self._require_auth()
            self._api_download(head=method == "HEAD")
            return
        if route == "/api/preview" and method in ("GET", "HEAD"):
            self._require_auth()
            self._api_preview(head=method == "HEAD")
            return
        if route == "/api/mkdir" and method == "POST":
            self._require_auth()
            self._require_request_header()
            self._api_mkdir()
            return
        if route == "/api/upload" and method == "PUT":
            self._require_auth()
            self._require_request_header()
            self._api_upload()
            return
        if route == "/api/quick-access" and method == "GET":
            self._require_auth()
            self._api_quick_access_list()
            return
        if route == "/api/quick-access" and method == "POST":
            self._require_auth()
            self._require_request_header()
            self._api_quick_access_add()
            return
        if route == "/api/quick-access/remove" and method == "POST":
            self._require_auth()
            self._require_request_header()
            self._api_quick_access_remove()
            return
        if route in {
            "/api/login",
            "/api/session",
            "/api/logout",
            "/api/auth/challenge",
            "/api/auth/verify",
            "/api/auth/keys",
            "/api/auth/keys/remove",
            "/api/list",
            "/api/download",
            "/api/preview",
            "/api/mkdir",
            "/api/upload",
            "/api/quick-access",
            "/api/quick-access/remove",
        }:
            raise RequestError(
                HTTPStatus.METHOD_NOT_ALLOWED,
                "Method not allowed.",
                {"Allow": self._allowed_methods(route)},
            )
        raise RequestError(HTTPStatus.NOT_FOUND, "Unknown API endpoint.")

    @staticmethod
    def _allowed_methods(route: str) -> str:
        return {
            "/api/login": "POST",
            "/api/session": "GET",
            "/api/logout": "POST",
            "/api/auth/challenge": "POST",
            "/api/auth/verify": "POST",
            "/api/auth/keys": "GET, POST",
            "/api/auth/keys/remove": "POST",
            "/api/list": "GET",
            "/api/download": "GET, HEAD",
            "/api/preview": "GET, HEAD",
            "/api/mkdir": "POST",
            "/api/upload": "PUT",
            "/api/quick-access": "GET, POST",
            "/api/quick-access/remove": "POST",
        }.get(route, "")

    def _serve_index(self, *, head: bool) -> None:
        try:
            body = (self.config.web_dir / "index.html").read_bytes()
        except OSError as exc:
            logger.error("Cannot read index.html: %s", exc)
            raise RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "Dashboard files are missing.") from exc
        self._send_bytes(
            HTTPStatus.OK,
            body,
            "text/html; charset=utf-8",
            csp=INDEX_CSP,
            cache_control="no-store",
            head=head,
        )

    def _serve_static(self, name: str, *, head: bool) -> None:
        if "/" in name or name not in STATIC_FILES:
            raise RequestError(HTTPStatus.NOT_FOUND, "Not found.")
        try:
            body = (self.config.web_dir / name).read_bytes()
        except OSError as exc:
            logger.error("Cannot read static file %s: %s", name, exc)
            raise RequestError(HTTPStatus.NOT_FOUND, "Not found.") from exc
        self._send_bytes(
            HTTPStatus.OK,
            body,
            STATIC_FILES[name],
            csp=STRICT_CSP,
            cache_control="no-cache",
            head=head,
        )

    def _send_bytes(
        self,
        status: int | HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        csp: str,
        cache_control: str,
        head: bool,
    ) -> None:
        self.send_response(int(status))
        self._security_headers(csp)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self.end_headers()
        self._responded = True
        if not head:
            self.wfile.write(body)

    def _send_json(
        self,
        status: int | HTTPStatus,
        payload: Any,
        *,
        headers: Mapping[str, str] | None = None,
        close: bool = False,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(int(status))
        self._security_headers(STRICT_CSP)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        if close:
            self.close_connection = True
            self.send_header("Connection", "close")
        self.end_headers()
        self._responded = True
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_no_content(self, *, headers: Mapping[str, str] | None = None) -> None:
        self.send_response(int(HTTPStatus.NO_CONTENT))
        self._security_headers(STRICT_CSP)
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self._responded = True

    def _send_not_modified(
        self,
        etag: str,
        last_modified: str,
        *,
        csp: str = "sandbox",
        frameable: bool = False,
    ) -> None:
        self.send_response(int(HTTPStatus.NOT_MODIFIED))
        self._security_headers(csp, frameable=frameable)
        self.send_header("ETag", etag)
        self.send_header("Last-Modified", last_modified)
        self.send_header("Cache-Control", "private, max-age=0, must-revalidate")
        self.end_headers()
        self._responded = True

    def _security_headers(self, csp: str, *, frameable: bool = False) -> None:
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN" if frameable else "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def _send_error(self, exc: RequestError) -> None:
        if self._responded:
            self.close_connection = True
            return
        try:
            self._send_json(
                exc.status,
                {"error": exc.message},
                headers=exc.headers,
                close=True,
            )
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _query_value(self, key: str, default: str | None = None) -> str:
        values = self._query.get(key)
        if values is None:
            if default is None:
                raise RequestError(HTTPStatus.BAD_REQUEST, f"Missing query parameter: {key}.")
            return default
        if len(values) != 1:
            raise RequestError(HTTPStatus.BAD_REQUEST, f"Query parameter {key} must appear once.")
        return values[0]

    def _requested_path(self) -> tuple[list[str], Path]:
        raw = self._query_value("path", "")
        parts = normalize_relative_path(raw)
        return parts, resolve_relative(self.config.root, parts)

    def _session_token(self) -> str | None:
        header = self.headers.get("Cookie")
        if not header:
            return None
        jar = SimpleCookie()
        try:
            jar.load(header)
        except CookieError:
            return None
        morsel = jar.get(SESSION_COOKIE)
        if morsel is None or not morsel.value:
            return None
        return morsel.value

    def _require_auth(self) -> str:
        token = self._session_token()
        if token is None or not self.server.sessions.is_valid(token):  # type: ignore[attr-defined]
            raise RequestError(HTTPStatus.UNAUTHORIZED, "Authentication required.")
        return token

    def _require_request_header(self) -> None:
        if self.headers.get(REQUEST_HEADER) != "1":
            raise RequestError(
                HTTPStatus.FORBIDDEN,
                f"Missing required request header: {REQUEST_HEADER}: 1.",
            )

    def _body_length(self) -> int:
        transfer_encoding = self.headers.get_all("Transfer-Encoding")
        if transfer_encoding:
            raise RequestError(
                HTTPStatus.BAD_REQUEST,
                "Transfer-Encoding is not supported; send a Content-Length.",
            )
        if self.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Content-Encoding is not supported.")
        values = self.headers.get_all("Content-Length")
        if not values:
            raise RequestError(HTTPStatus.LENGTH_REQUIRED, "Content-Length is required.")
        stripped = {value.strip() for value in values}
        if len(stripped) != 1:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Conflicting Content-Length headers.")
        value = stripped.pop()
        if not value.isascii() or not value.isdigit():
            raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid Content-Length.")
        return int(value)

    def _read_exact(self, length: int) -> bytes:
        data = self.rfile.read(length)
        if len(data) != length:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Request body ended unexpectedly.")
        return data

    def _read_json(self) -> dict[str, Any]:
        length = self._body_length()
        if length > MAX_JSON_BODY:
            raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "JSON body is too large.")
        raw = self._read_exact(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Body must be valid JSON.") from exc
        if not isinstance(parsed, dict):
            raise RequestError(HTTPStatus.BAD_REQUEST, "JSON body must be an object.")
        return parsed

    def _discard_body_for_conflict(self, length: int) -> None:
        if length <= DRAIN_ON_CONFLICT:
            self._read_exact(length)

    def _api_login(self) -> None:
        self._require_request_header()
        client = self.client_address[0]
        retry_after = self.server.login_limiter.retry_after(client)  # type: ignore[attr-defined]
        if retry_after:
            raise RequestError(
                HTTPStatus.TOO_MANY_REQUESTS,
                f"Too many failed sign-in attempts. Try again in {retry_after} seconds.",
                {"Retry-After": str(retry_after)},
            )
        body = self._read_json()
        username = body.get("username")
        password = body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            raise RequestError(HTTPStatus.BAD_REQUEST, "Username and password are required.")
        if not verify_credentials(self.config, username, password):
            self.server.login_limiter.record_failure(client)  # type: ignore[attr-defined]
            logger.warning("Failed sign-in from %s", client)
            raise RequestError(HTTPStatus.UNAUTHORIZED, "Invalid username or password.")

        self.server.login_limiter.clear(client)  # type: ignore[attr-defined]
        logger.info("Signed in: %s from %s", self.config.username, client)
        self._issue_session()

    def _api_logout(self) -> None:
        token = self._session_token()
        if token:
            self.server.sessions.revoke(token)  # type: ignore[attr-defined]
        cookie = (
            f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        )
        if self.config.secure_cookie:
            cookie += "; Secure"
        self._send_no_content(headers={"Set-Cookie": cookie})

    def _issue_session(self) -> None:
        token = self.server.sessions.create()  # type: ignore[attr-defined]
        ttl = self.config.session_ttl
        cookie = (
            f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl}"
        )
        if self.config.secure_cookie:
            cookie += "; Secure"
        self._send_json(
            HTTPStatus.OK,
            {"user": self.config.username, "expiresIn": ttl},
            headers={"Set-Cookie": cookie},
        )

    def _api_session(self) -> None:
        self._send_json(
            HTTPStatus.OK,
            {
                "user": self.config.username,
                "app": APP_NAME,
                "version": VERSION,
                "rootName": self.config.root.name or str(self.config.root),
                "secure": self.config.secure_cookie,
                "maxUpload": self.config.max_upload,
                "publicKeyAuth": self.server.public_key_auth,  # type: ignore[attr-defined]
            },
        )

    def _require_public_key_auth(self) -> None:
        if not self.server.public_key_auth:  # type: ignore[attr-defined]
            raise RequestError(
                HTTPStatus.NOT_IMPLEMENTED,
                "Passwordless sign-in requires the openssl command-line tool.",
            )

    def _api_auth_challenge(self) -> None:
        self._require_public_key_auth()
        self._read_json()
        client = self.client_address[0]
        issued = self.server.challenges.create(client)  # type: ignore[attr-defined]
        if issued is None:
            raise RequestError(
                HTTPStatus.TOO_MANY_REQUESTS,
                "Too many pending sign-in challenges. Try again in a minute.",
            )
        challenge_id, nonce_hex = issued
        self._send_json(HTTPStatus.OK, {"id": challenge_id, "nonce": nonce_hex})

    def _api_auth_verify(self) -> None:
        self._require_public_key_auth()
        client = self.client_address[0]
        retry_after = self.server.login_limiter.retry_after(client)  # type: ignore[attr-defined]
        if retry_after:
            raise RequestError(
                HTTPStatus.TOO_MANY_REQUESTS,
                f"Too many failed sign-in attempts. Try again in {retry_after} seconds.",
                {"Retry-After": str(retry_after)},
            )
        body = self._read_json()
        challenge_id = body.get("id")
        signature_b64 = body.get("signature")
        if not isinstance(challenge_id, str) or not isinstance(signature_b64, str):
            raise RequestError(
                HTTPStatus.BAD_REQUEST, "Challenge id and signature are required."
            )
        nonce = self.server.challenges.consume(client, challenge_id)  # type: ignore[attr-defined]
        if nonce is None:
            raise RequestError(
                HTTPStatus.UNAUTHORIZED, "Challenge expired or already used."
            )
        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except ValueError:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Signature must be base64.")
        if not signature:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Signature is empty.")
        for record in self.server.public_keys.records(self.config.username):  # type: ignore[attr-defined]
            if verify_public_key_signature(record["public_key"], nonce, signature):
                self.server.public_keys.touch(  # type: ignore[attr-defined]
                    self.config.username, record["id"]
                )
                self.server.login_limiter.clear(client)  # type: ignore[attr-defined]
                logger.info(
                    "Passwordless sign-in for %s from %s",
                    self.config.username,
                    client,
                )
                self._issue_session()
                return
        self.server.login_limiter.record_failure(client)  # type: ignore[attr-defined]
        logger.warning("Failed public-key sign-in from %s", client)
        raise RequestError(HTTPStatus.UNAUTHORIZED, "Invalid signature.")

    def _api_auth_keys_list(self) -> None:
        keys = [
            {
                "id": record["id"],
                "fingerprint": record["fingerprint"],
                "label": record["label"],
                "createdAt": record["created_at"],
                "lastUsedAt": record["last_used_at"],
            }
            for record in self.server.public_keys.records(self.config.username)  # type: ignore[attr-defined]
        ]
        self._send_json(HTTPStatus.OK, {"keys": keys})

    def _api_auth_keys_add(self) -> None:
        self._require_public_key_auth()
        body = self._read_json()
        public_key = body.get("publicKey")
        if not isinstance(public_key, str) or not public_key.strip():
            raise RequestError(HTTPStatus.BAD_REQUEST, "publicKey is required.")
        if len(public_key) > 8192:
            raise RequestError(HTTPStatus.BAD_REQUEST, "publicKey is too long.")
        if not validate_public_key_pem(public_key):
            raise RequestError(
                HTTPStatus.BAD_REQUEST, "publicKey is not a valid PEM public key."
            )
        fingerprint = hashlib.sha256(public_key.encode("utf-8")).hexdigest()
        label = _sanitize_device_label(self.headers.get("User-Agent", ""))
        try:
            record, created = self.server.public_keys.add(  # type: ignore[attr-defined]
                self.config.username, public_key, fingerprint, label
            )
        except PublicKeyLimitError:
            raise RequestError(
                HTTPStatus.CONFLICT,
                f"This account already has the maximum of {MAX_PUBLIC_KEYS} sign-in keys.",
            )
        self._send_json(
            HTTPStatus.CREATED if created else HTTPStatus.OK,
            {
                "created": created,
                "key": {
                    "id": record["id"],
                    "fingerprint": record["fingerprint"],
                    "label": record["label"],
                    "createdAt": record["created_at"],
                    "lastUsedAt": record["last_used_at"],
                },
            },
        )

    def _api_auth_keys_remove(self) -> None:
        body = self._read_json()
        key_id = body.get("id")
        if not isinstance(key_id, str) or not key_id:
            raise RequestError(HTTPStatus.BAD_REQUEST, "id is required.")
        removed = self.server.public_keys.remove(  # type: ignore[attr-defined]
            self.config.username, key_id
        )
        if not removed:
            raise RequestError(HTTPStatus.NOT_FOUND, "Key not found.")
        logger.info("Sign-in key removed for %s: %s", self.config.username, key_id)
        self._send_no_content()

    def _api_list(self) -> None:
        parts, directory = self._requested_path()
        if not directory.exists():
            raise RequestError(HTTPStatus.NOT_FOUND, "Folder not found.")
        if not directory.is_dir():
            raise RequestError(HTTPStatus.BAD_REQUEST, "Path is not a folder.")

        entries: list[dict[str, Any]] = []
        try:
            iterator = os.scandir(directory)
        except PermissionError as exc:
            raise RequestError(HTTPStatus.FORBIDDEN, "Folder is not readable.") from exc
        except OSError as exc:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Cannot read folder.") from exc

        with iterator:
            for entry in iterator:
                try:
                    entry_path = Path(entry.path)
                    if entry.is_symlink():
                        resolved = entry_path.resolve(strict=True)
                        if not _is_within(self.config.root, resolved):
                            continue
                        file_stat = resolved.stat()
                    else:
                        resolved = entry_path
                        file_stat = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(file_stat.st_mode):
                        kind = "dir"
                    elif stat.S_ISREG(file_stat.st_mode):
                        kind = "file"
                    else:
                        continue
                    if entry.name.startswith(".lanvault-upload-") and entry.name.endswith(".part"):
                        continue
                    entry.name.encode("utf-8")
                    entries.append(
                        {
                            "name": entry.name,
                            "path": "/".join(parts + [entry.name]),
                            "kind": kind,
                            "isDir": kind == "dir",
                            "size": file_stat.st_size,
                            "mtime": int(file_stat.st_mtime),
                            "preview": preview_kind(entry.name) if kind == "file" else None,
                        }
                    )
                except (OSError, RuntimeError):
                    continue

        entries.sort(key=lambda item: (item["kind"] != "dir", item["name"].casefold(), item["name"]))
        total_size = sum(item["size"] for item in entries if not item["isDir"])
        try:
            usage = shutil.disk_usage(directory)
            disk = {"total": usage.total, "free": usage.free}
        except OSError:
            disk = None
        self._send_json(
            HTTPStatus.OK,
            {
                "path": "/".join(parts),
                "parent": "/".join(parts[:-1]) if parts else None,
                "rootName": self.config.root.name or str(self.config.root),
                "entries": entries,
                "totalSize": total_size,
                "writable": os.access(directory, os.W_OK | os.X_OK),
                "disk": disk,
            },
        )

    def _api_download(self, *, head: bool) -> None:
        parts, path = self._requested_path()
        if not parts:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Cannot download the root folder.")
        self._serve_file(parts[-1], path, head=head, inline=False, preview=None)

    def _api_preview(self, *, head: bool) -> None:
        parts, path = self._requested_path()
        if not parts:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Cannot preview the root folder.")
        filename = parts[-1]
        kind = preview_kind(filename)
        if kind is None:
            raise RequestError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "This file type cannot be previewed in the browser.",
            )
        self._serve_file(filename, path, head=head, inline=True, preview=kind)

    def _serve_file(
        self,
        filename: str,
        path: Path,
        *,
        head: bool,
        inline: bool,
        preview: str | None,
    ) -> None:
        if not path.exists():
            raise RequestError(HTTPStatus.NOT_FOUND, "File not found.")
        if path.is_dir():
            raise RequestError(HTTPStatus.NOT_FOUND, "File not found.")
        try:
            handle = path.open("rb")
        except FileNotFoundError as exc:
            raise RequestError(HTTPStatus.NOT_FOUND, "File not found.") from exc
        except PermissionError as exc:
            raise RequestError(HTTPStatus.FORBIDDEN, "File is not readable.") from exc
        except OSError as exc:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Cannot open file.") from exc

        with handle:
            file_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(file_stat.st_mode):
                raise RequestError(HTTPStatus.NOT_FOUND, "File not found.")
            size = file_stat.st_size
            etag = f'"{file_stat.st_mtime_ns:x}-{size:x}"'
            last_modified = formatdate(file_stat.st_mtime, usegmt=True)
            if preview is not None:
                content_type = preview_content_type(filename, preview)
                csp = preview_csp(filename, preview)
                disposition = "inline"
            else:
                content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
                csp = "sandbox"
                disposition = "attachment"
            conditional = self.headers.get("If-None-Match")
            if conditional and _etag_matches(conditional, etag):
                self._send_not_modified(
                    etag,
                    last_modified,
                    csp=csp,
                    frameable=preview is not None,
                )
                return

            range_header = self.headers.get("Range")
            byte_range = parse_range(range_header, size) if range_header else None
            if byte_range is None:
                start, end = 0, size - 1
                status = HTTPStatus.OK
                content_length = size
            else:
                start, end = byte_range
                status = HTTPStatus.PARTIAL_CONTENT
                content_length = end - start + 1

            self.send_response(int(status))
            self._security_headers(csp, frameable=preview is not None)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(content_length))
            self.send_header(
                "Content-Disposition",
                content_disposition(filename, disposition),
            )
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", etag)
            self.send_header("Last-Modified", last_modified)
            self.send_header("Cache-Control", "private, max-age=0, must-revalidate")
            if byte_range is not None:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.end_headers()
            self._responded = True
            if head:
                return

            handle.seek(start)
            remaining = content_length
            try:
                while remaining > 0:
                    chunk = handle.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

    def _api_mkdir(self) -> None:
        body = self._read_json()
        raw_path = body.get("path", "")
        name = validate_name(body.get("name"))
        if not isinstance(raw_path, str):
            raise RequestError(HTTPStatus.BAD_REQUEST, "Path must be a string.")
        parts = normalize_relative_path(raw_path)
        parent = resolve_relative(self.config.root, parts)
        if not parent.exists():
            raise RequestError(HTTPStatus.NOT_FOUND, "Parent folder not found.")
        if not parent.is_dir():
            raise RequestError(HTTPStatus.BAD_REQUEST, "Parent path is not a folder.")
        target = parent / name
        try:
            resolved_target = target.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid path.") from exc
        if not _is_within(self.config.root, resolved_target):
            raise RequestError(HTTPStatus.FORBIDDEN, "Path escapes the shared folder.")
        if os.path.lexists(target):
            raise RequestError(HTTPStatus.CONFLICT, "An item with that name already exists.")
        try:
            target.mkdir()
        except FileExistsError as exc:
            raise RequestError(HTTPStatus.CONFLICT, "An item with that name already exists.") from exc
        except PermissionError as exc:
            raise RequestError(HTTPStatus.FORBIDDEN, "Cannot create a folder here.") from exc
        except OSError as exc:
            logger.warning("mkdir failed in %s: %s", parent, exc)
            raise RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "Could not create the folder.") from exc
        self._send_json(
            HTTPStatus.CREATED,
            {"name": name, "path": "/".join(parts + [name])},
        )
        logger.info("Created folder: %s", target)

    def _quick_access_entries(self) -> list[dict[str, Any]]:
        return self.server.quick_access.entries(self.config.username)  # type: ignore[attr-defined]

    def _api_quick_access_list(self) -> None:
        self._send_json(HTTPStatus.OK, {"entries": self._quick_access_entries()})

    def _api_quick_access_add(self) -> None:
        body = self._read_json()
        raw_path = body.get("path")
        parts = normalize_relative_path(raw_path)
        if not parts:
            raise RequestError(HTTPStatus.BAD_REQUEST, "The shared root is always available.")
        target = resolve_relative(self.config.root, parts)
        try:
            target_stat = target.stat()
        except FileNotFoundError as exc:
            raise RequestError(HTTPStatus.NOT_FOUND, "That item no longer exists.") from exc
        except OSError as exc:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Cannot read that item.") from exc
        if stat.S_ISDIR(target_stat.st_mode):
            is_dir = True
        elif stat.S_ISREG(target_stat.st_mode):
            is_dir = False
        else:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Only files and folders can be pinned.")
        entry = {
            "path": "/".join(parts),
            "name": parts[-1],
            "isDir": is_dir,
            "preview": None if is_dir else preview_kind(parts[-1]),
        }
        try:
            result = self.server.quick_access.add(self.config.username, entry)  # type: ignore[attr-defined]
        except OSError as exc:
            logger.warning("Cannot save quick access file %s: %s", self.config.state_file, exc)
            raise RequestError(
                HTTPStatus.INTERNAL_SERVER_ERROR, "Cannot save quick access."
            ) from exc
        if result == "full":
            raise RequestError(
                HTTPStatus.CONFLICT,
                f"Quick access is limited to {MAX_QUICK_ACCESS} items.",
            )
        status = HTTPStatus.CREATED if result == "added" else HTTPStatus.OK
        self._send_json(status, {"entries": self._quick_access_entries()})
        if result == "added":
            logger.info("Pinned for %s: %s", self.config.username, entry["path"])

    def _api_quick_access_remove(self) -> None:
        body = self._read_json()
        raw_path = body.get("path")
        if not isinstance(raw_path, str):
            raise RequestError(HTTPStatus.BAD_REQUEST, "Path must be a string.")
        normalized = "/".join(normalize_relative_path(raw_path))
        try:
            removed = self.server.quick_access.remove(self.config.username, normalized)  # type: ignore[attr-defined]
        except OSError as exc:
            logger.warning("Cannot save quick access file %s: %s", self.config.state_file, exc)
            raise RequestError(
                HTTPStatus.INTERNAL_SERVER_ERROR, "Cannot save quick access."
            ) from exc
        self._send_json(HTTPStatus.OK, {"entries": self._quick_access_entries(), "removed": removed})

    def _api_upload(self) -> None:
        raw_path = self._query_value("path", "")
        name = validate_name(self._query_value("name"))
        overwrite_raw = self._query_value("overwrite", "0").lower()
        if overwrite_raw in ("1", "true", "yes"):
            overwrite = True
        elif overwrite_raw in ("0", "false", "no"):
            overwrite = False
        else:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid overwrite value.")

        parts = normalize_relative_path(raw_path)
        parent = resolve_relative(self.config.root, parts)
        if not parent.exists():
            raise RequestError(HTTPStatus.NOT_FOUND, "Upload folder not found.")
        if not parent.is_dir():
            raise RequestError(HTTPStatus.BAD_REQUEST, "Upload path is not a folder.")

        length = self._body_length()
        if self.config.max_upload is not None and length > self.config.max_upload:
            raise RequestError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"Upload exceeds the {self.config.max_upload} byte limit.",
            )

        target = parent / name
        try:
            resolved_target = target.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid path.") from exc
        if not _is_within(self.config.root, resolved_target):
            raise RequestError(HTTPStatus.FORBIDDEN, "Path escapes the shared folder.")
        existed = os.path.lexists(target)
        if existed and target.is_dir():
            self._discard_body_for_conflict(length)
            raise RequestError(HTTPStatus.CONFLICT, "A folder with that name already exists.")
        if existed and not overwrite:
            self._discard_body_for_conflict(length)
            raise RequestError(HTTPStatus.CONFLICT, "A file with that name already exists.")
        target_mode = 0o644
        if existed:
            try:
                target_stat = target.stat()
                if stat.S_ISREG(target_stat.st_mode):
                    target_mode = stat.S_IMODE(target_stat.st_mode)
            except OSError:
                pass

        try:
            descriptor, temp_name = tempfile.mkstemp(
                prefix=".lanvault-upload-",
                suffix=".part",
                dir=parent,
            )
        except PermissionError as exc:
            raise RequestError(HTTPStatus.FORBIDDEN, "Cannot write to this folder.") from exc
        except OSError as exc:
            logger.warning("Cannot create upload temp file in %s: %s", parent, exc)
            raise RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "Cannot start the upload.") from exc

        temp_path = Path(temp_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                remaining = length
                try:
                    while remaining > 0:
                        chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            raise RequestError(
                                HTTPStatus.BAD_REQUEST,
                                "Upload ended before Content-Length bytes arrived.",
                            )
                        output.write(chunk)
                        remaining -= len(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                except OSError as exc:
                    logger.warning("Upload write failed in %s: %s", parent, exc)
                    raise RequestError(HTTPStatus.INSUFFICIENT_STORAGE, "Could not write the upload.") from exc
            try:
                os.chmod(temp_path, target_mode)
            except OSError:
                pass

            try:
                if overwrite:
                    os.replace(temp_path, target)
                else:
                    try:
                        os.link(temp_path, target)
                    except FileExistsError as exc:
                        raise RequestError(
                            HTTPStatus.CONFLICT,
                            "A file with that name already exists.",
                        ) from exc
                    except OSError:
                        if os.path.lexists(target):
                            raise RequestError(
                                HTTPStatus.CONFLICT,
                                "A file with that name already exists.",
                            )
                        os.replace(temp_path, target)
                    else:
                        temp_path.unlink()
            except RequestError:
                raise
            except IsADirectoryError as exc:
                raise RequestError(HTTPStatus.CONFLICT, "A folder with that name already exists.") from exc
            except OSError as exc:
                logger.warning("Cannot finalize upload to %s: %s", target, exc)
                raise RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "Could not finish the upload.") from exc

            self._send_json(
                HTTPStatus.OK if existed else HTTPStatus.CREATED,
                {
                    "name": name,
                    "path": "/".join(parts + [name]),
                    "size": length,
                    "overwritten": existed,
                },
            )
            logger.info(
                "%s %s bytes from %s",
                "Overwrote" if existed else "Uploaded",
                length,
                target,
            )
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Could not remove temporary upload file: %s", temp_path)


def create_server(
    host: str,
    port: int,
    config: Config,
    ssl_context: ssl.SSLContext | None = None,
) -> LanVaultServer:
    server = LanVaultServer((host, port), config)
    if ssl_context is not None:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    return server


def build_ssl_context(cert: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return context


def _read_password_file(path: Path) -> str:
    raw = path.expanduser().read_text(encoding="utf-8")
    if raw.endswith("\r\n"):
        return raw[:-2]
    if raw.endswith("\n"):
        return raw[:-1]
    return raw


def _local_ipv4_hint() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))
        address = sock.getsockname()[0]
        if address and not address.startswith("0."):
            return address
    except OSError:
        return None
    finally:
        sock.close()
    return None


def _url_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _display_urls(bind_host: str, port: int, secure: bool) -> list[str]:
    scheme = "https" if secure else "http"
    wildcard = bind_host in ("", "0.0.0.0", "::")
    hosts: list[str] = []
    if wildcard:
        if bind_host == "::":
            hosts.append("::1")
        else:
            hosts.append("127.0.0.1")
            hint = _local_ipv4_hint()
            if hint and hint not in hosts:
                hosts.insert(0, hint)
    else:
        hosts.append(bind_host)
    return [f"{scheme}://{_url_host(host)}:{port}" for host in hosts]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lanvault.py",
        description="Serve a folder over the LAN with a small authenticated web dashboard.",
    )
    parser.add_argument("--root", required=True, type=Path, help="Folder to share.")
    parser.add_argument("--bind", default="0.0.0.0", help="Address to bind. Default: 0.0.0.0")
    parser.add_argument("--port", type=int, default=8080, help="TCP port. Default: 8080")
    parser.add_argument(
        "--user",
        help="Sign-in username. Default: the current OS user.",
    )
    parser.add_argument(
        "--password-file",
        type=Path,
        help="Read the password from this file. Overrides LANVAULT_PASSWORD.",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        help="Per-user quick access state file. "
        "Default: $XDG_STATE_HOME/lanvault/quick-access.json",
    )
    parser.add_argument(
        "--session-hours",
        type=float,
        default=12.0,
        help="Absolute session lifetime in hours. Default: 12",
    )
    parser.add_argument(
        "--max-upload-mb",
        type=int,
        default=0,
        help="Maximum upload size in MiB. 0 means unlimited. Default: 0",
    )
    parser.add_argument("--tls-cert", type=Path, help="TLS certificate chain (PEM).")
    parser.add_argument("--tls-key", type=Path, help="TLS private key (PEM).")
    parser.add_argument("--quiet", action="store_true", help="Only log warnings and errors.")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535.")
    if args.session_hours <= 0:
        parser.error("--session-hours must be positive.")
    if args.max_upload_mb < 0:
        parser.error("--max-upload-mb must be zero or positive.")
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key must be provided together.")

    root = args.root.expanduser().resolve()
    if not root.is_dir():
        parser.error(f"--root is not a directory: {root}")

    password: str
    if args.password_file:
        try:
            password = _read_password_file(args.password_file)
            mode = args.password_file.expanduser().stat().st_mode
            if mode & 0o077:
                logger.warning("Password file is readable by group or others: %s", args.password_file)
        except (OSError, UnicodeDecodeError) as exc:
            parser.error(f"Cannot read --password-file: {exc}")
    elif PASSWORD_ENV in os.environ:
        password = os.environ.pop(PASSWORD_ENV)
    else:
        username_hint = args.user or getpass.getuser()
        try:
            password = getpass.getpass(f"Password for {username_hint}: ")
        except (EOFError, KeyboardInterrupt):
            parser.error(f"No password supplied. Set {PASSWORD_ENV} for non-interactive use.")

    os.environ.pop(PASSWORD_ENV, None)
    username = args.user or getpass.getuser()
    max_upload = args.max_upload_mb * 1024 * 1024 if args.max_upload_mb else None
    tls_context: ssl.SSLContext | None = None
    if args.tls_cert and args.tls_key:
        try:
            tls_context = build_ssl_context(
                args.tls_cert.expanduser(), args.tls_key.expanduser()
            )
        except (OSError, ssl.SSLError) as exc:
            parser.error(f"Cannot load TLS certificate or key: {exc}")

    try:
        config = create_config(
            root,
            username,
            password,
            state_file=args.state_file,
            session_ttl=int(args.session_hours * 3600),
            max_upload=max_upload,
            secure_cookie=tls_context is not None,
        )
    except ValueError as exc:
        parser.error(str(exc))
    del password

    for filename in ("index.html", "app.js", "style.css", "favicon.svg"):
        if not (config.web_dir / filename).is_file():
            parser.error(f"Missing dashboard asset: {config.web_dir / filename}")

    try:
        server = create_server(args.bind, args.port, config, tls_context)
    except OSError as exc:
        parser.error(f"Cannot listen on {args.bind}:{args.port}: {exc}")

    port = int(server.server_address[1])
    urls = _display_urls(args.bind, port, tls_context is not None)
    logger.info("%s %s", APP_NAME, VERSION)
    logger.info("Root: %s", root)
    logger.info("User: %s", username)
    logger.info("State: %s", config.state_file)
    if server.public_key_auth:
        logger.info("Passwordless sign-in keys: %s", config.keys_file)
    for url in urls:
        logger.info("Open: %s", url)
    if tls_context is None and args.bind not in ("127.0.0.1", "::1", "localhost"):
        logger.warning("Plain HTTP sends the password and files unencrypted. Use a trusted LAN or TLS.")
    if tls_context is not None and args.tls_cert:
        logger.info("TLS enabled with %s", args.tls_cert)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        logger.warning("Running as root. Use an unprivileged account that owns only the shared folder.")

    previous_sigterm = None
    try:
        previous_sigterm = signal.getsignal(signal.SIGTERM)

        def stop_on_sigterm(_signum: int, _frame: Any) -> None:
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, stop_on_sigterm)
    except (ValueError, OSError, AttributeError):
        previous_sigterm = None

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        logger.info("Stopping.")
    finally:
        server.server_close()
        if previous_sigterm is not None:
            try:
                signal.signal(signal.SIGTERM, previous_sigterm)
            except (ValueError, OSError):
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
