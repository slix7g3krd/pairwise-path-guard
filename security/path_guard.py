"""Path traversal guard utilities.

The functions in this module are intentionally conservative: a path is only
accepted when two independent checks agree.

1.  The input is canonicalised (NUL handling, repeated URL decoding,
    Unicode NFKC normalisation, separator unification) and normalised with
    POSIX semantics.
2.  The *resolved* paths (``os.path.realpath``) are compared with
    ``os.path.commonpath`` so that symlinks and prefix tricks such as
    ``/data-evil`` cannot pass.

All public helpers never leak absolute host paths through error messages; use
:func:`sanitize_error` when surfacing an error to an untrusted caller.
"""

from __future__ import annotations

import errno
import os
import posixpath
import re
import stat
import unicodedata
from urllib.parse import unquote

__all__ = [
    "normalize_path",
    "is_safe_path",
    "safe_join",
    "strip_null",
    "is_symlink_escape",
    "safe_open",
    "sanitize_error",
    "safe_extract_path",
    "is_safe_archive_member",
]

# Upper bound for repeated percent-decoding.  Handles double/triple encoded
# input while guaranteeing termination on crafted strings.
_MAX_DECODE_ROUNDS = 8

# A Windows drive prefix ("C:", "C:/", "C:\") is never valid below a POSIX
# download root.
_DRIVE_RE = re.compile(r"^[A-Za-z]:")

# Used by sanitize_error() to redact absolute POSIX paths.
_ABS_POSIX_RE = re.compile(r"(?<![\w:/])/[^\s\"'<>|]*")
# Used by sanitize_error() to redact absolute Windows paths.
_ABS_WINDOWS_RE = re.compile(r"[A-Za-z]:[\\/][^\s\"'<>|]*")

_GENERIC_ERROR = "Requested resource is not available."


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _as_text(value):
    """Return *value* as ``str``; raise ``TypeError`` for unsupported types."""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "surrogateescape")
    if isinstance(value, os.PathLike):
        raw = os.fspath(value)
        if isinstance(raw, bytes):
            return raw.decode("utf-8", "surrogateescape")
        return raw
    raise TypeError("path must be str, bytes or os.PathLike")


def _canonicalize(text):
    """Repeatedly percent-decode and NFKC-normalise until stable.

    Repeating the decode catches double/triple encoding (``%252e`` ->
    ``%2e`` -> ``.``); NFKC folds compatibility characters such as the
    fullwidth solidus U+FF0F into ``/`` before any traversal check.
    """
    for _ in range(_MAX_DECODE_ROUNDS):
        updated = unicodedata.normalize("NFKC", unquote(text))
        if updated == text:
            return text
        text = updated
    return text


def _unify_separators(text):
    """Treat Windows separators as POSIX separators."""
    return text.replace("\\", "/")


def _is_within(path, root):
    """True when *path* is *root* or lives below it (component aware)."""
    try:
        path = os.path.normcase(os.path.abspath(path))
        root = os.path.normcase(os.path.abspath(root))
        return os.path.commonpath([path, root]) == root
    except (ValueError, OSError):
        # Different drives on Windows, or otherwise incomparable paths.
        return False


def _is_absolute_target(text):
    return text.startswith("/") or bool(_DRIVE_RE.match(text))


def strip_null(value):
    """Return *value* truncated at the first NUL byte.

    ``strip_null('a\\x00b') == 'a'``.
    """
    if isinstance(value, bytes):
        return value.split(b"\x00", 1)[0]
    text = _as_text(value)
    return text.split("\x00", 1)[0]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_path(path):
    """Canonicalise *path* without touching the filesystem.

    Performs, in order: NUL truncation, repeated URL decoding, Unicode NFKC
    normalisation, separator unification and lexical ``..``/``.`` collapse.
    Relative paths stay relative; absolute paths stay absolute.
    """
    text = _as_text(path)
    text = strip_null(text)
    text = _canonicalize(text)
    text = strip_null(text)
    text = _unify_separators(text)

    if not text:
        return ""

    normalized = posixpath.normpath(text)

    # POSIX allows an implementation-defined meaning for a leading "//".
    # Collapse it so comparisons are deterministic.
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")

    return normalized


def is_safe_path(path, root):
    """Return ``True`` only when *path* resolves inside *root*.

    *path* may be absolute or relative.  Relative inputs are resolved against
    *root*.  Absolute inputs are accepted only when they already live below
    *root* -- so ``/data/file`` is allowed for root ``/data`` while
    ``/etc/passwd`` is rejected.

    The check canonicalises encodings, rejects NUL bytes and drive/UNC
    prefixes, then compares resolved real paths using ``commonpath`` so that
    symlink escapes and sibling-prefix attacks (``/data-evil``) fail.
    """
    try:
        raw = _as_text(path)
        root_raw = _as_text(root)
    except (TypeError, ValueError):
        return False

    # A NUL byte can truncate a path inside libc; never trust such input.
    if "\x00" in raw or "\x00" in root_raw:
        return False

    try:
        root_abs = os.path.abspath(strip_null(root_raw))
    except (OSError, ValueError):
        return False

    root_norm = normalize_path(root_abs)
    if not root_norm:
        return False

    candidate_text = _canonicalize(raw)
    if "\x00" in candidate_text:
        return False
    candidate_text = _unify_separators(candidate_text)
    if not candidate_text.strip():
        return False

    # Never allow Windows drive-qualified paths (including "C:relative").
    if _DRIVE_RE.match(candidate_text):
        return False

    if candidate_text.startswith("/"):
        candidate = normalize_path(candidate_text)
    else:
        candidate = normalize_path(posixpath.join(root_norm, candidate_text))

    if not candidate:
        return False

    try:
        root_real = os.path.realpath(root_norm)
        candidate_real = os.path.realpath(candidate)
    except (OSError, ValueError):
        return False

    return _is_within(candidate_real, root_real)


def safe_join(root, *parts):
    """Join *parts* below *root*; return ``None`` when the result escapes.

    Each part is canonicalised independently so an encoded or Windows style
    component cannot smuggle an escape past the final check.
    """
    try:
        root_text = _as_text(root)
    except (TypeError, ValueError):
        return None

    if "\x00" in root_text:
        return None

    root_norm = normalize_path(os.path.abspath(root_text))
    if not root_norm:
        return None

    cleaned = []
    for part in parts:
        try:
            value = _as_text(part)
        except (TypeError, ValueError):
            return None
        if "\x00" in value:
            return None
        value = _canonicalize(value)
        if "\x00" in value:
            return None
        value = _unify_separators(value)
        if _DRIVE_RE.match(value):
            return None
        cleaned.append(value)

    joined = os.path.join(root_norm, *cleaned) if cleaned else root_norm

    if not is_safe_path(joined, root_norm):
        return None

    return normalize_path(joined)


def is_symlink_escape(path, root_or_target):
    """Return ``True`` when a symlink resolves outside its permitted root.

    Two calling conventions are supported, because both are useful:

    * ``is_symlink_escape('/data/link', '/data')`` -- when *path* is an
      existing symlink, the second argument is the root it must stay under.
    * ``is_symlink_escape('/data/link', '/etc/passwd')`` -- when *path* is not
      an existing symlink, the second argument is the prospective link
      target; it must stay inside the directory containing the link.

    The ambiguous case is resolved by checking whether the second argument is
    an ancestor of *path*.  If it is, it is treated as the root; otherwise it
    is treated as the target.
    """
    try:
        raw_path = _as_text(path)
        raw_other = _as_text(root_or_target)
    except (TypeError, ValueError):
        return True

    if "\x00" in raw_path or "\x00" in raw_other:
        return True

    link = normalize_path(strip_null(raw_path))
    other = normalize_path(strip_null(raw_other))
    if not link or not other:
        return True

    # Resolve the link (or the part of its prefix that exists).
    resolved_link = os.path.realpath(link)

    # Existing symlink: the second argument is the root boundary.
    if os.path.islink(link):
        return not _is_within(resolved_link, os.path.realpath(other))

    link_dir = posixpath.dirname(link) or os.curdir
    try:
        resolved_dir = os.path.realpath(link_dir)
    except (OSError, ValueError):
        return True

    # Resolve the second argument relative to the link's directory when it is
    # itself relative.
    if _is_absolute_target(other):
        other_resolved = os.path.realpath(other)
    else:
        other_resolved = os.path.realpath(posixpath.join(link_dir, other))

    # If the second argument is an ancestor of the link it is a root; the
    # (non-symlink) path itself then cannot escape it.
    if _is_within(resolved_link, other_resolved):
        return False

    # Otherwise treat it as the prospective target and compare it with the
    # directory the link lives in.
    return not _is_within(other_resolved, resolved_dir)


# ---------------------------------------------------------------------------
# TOCTOU-safe opening
# ---------------------------------------------------------------------------

def _fd_realpath(fd, fallback):
    """Best-effort real path of an open file descriptor."""
    proc_path = "/proc/self/fd/{}".format(fd)
    if os.path.exists(proc_path):
        try:
            return os.path.realpath(proc_path)
        except OSError:
            pass
    return os.path.realpath(fallback)


def safe_open(root, path, mode="rb", *, encoding=None, errors=None, newline=None):
    """Open a file below *root* without a check-then-use race.

    The path is validated, opened with ``O_NOFOLLOW`` (where available), and
    the *opened descriptor* is resolved again through ``/proc/self/fd``.  If
    the object on disk is not a regular file or no longer lives inside
    *root*, the descriptor is closed and ``PermissionError`` is raised.
    """
    if any(flag in mode for flag in ("w", "a", "x", "+")):
        raise ValueError("safe_open() only supports read-only modes")

    root_norm = normalize_path(os.path.abspath(_as_text(root)))
    if not root_norm:
        raise PermissionError(_GENERIC_ERROR)

    candidate = safe_join(root_norm, path)
    if candidate is None:
        raise PermissionError(_GENERIC_ERROR)

    # Re-validate immediately before opening to narrow the race window.
    if not is_safe_path(candidate, root_norm):
        raise PermissionError(_GENERIC_ERROR)

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)

    try:
        fd = os.open(candidate, flags | nofollow)
    except OSError as exc:
        # A final-component symlink is not rejected outright -- symlinks that
        # stay inside the root are legitimate.  Retry without O_NOFOLLOW and
        # let the descriptor-level check below decide.
        if nofollow and exc.errno in (errno.ELOOP, errno.EMLINK):
            try:
                fd = os.open(candidate, flags)
            except OSError:
                raise PermissionError(_GENERIC_ERROR) from None
        else:
            raise

    try:
        # Verify the object actually opened, not just the name we checked.
        opened_real = _fd_realpath(fd, candidate)
        root_real = os.path.realpath(root_norm)
        if not _is_within(opened_real, root_real):
            raise PermissionError(_GENERIC_ERROR)

        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PermissionError(_GENERIC_ERROR)

        if "b" in mode:
            return os.fdopen(fd, mode)
        return os.fdopen(
            fd,
            mode,
            encoding=encoding or "utf-8",
            errors=errors,
            newline=newline,
        )
    except BaseException:
        os.close(fd)
        raise


# ---------------------------------------------------------------------------
# Error sanitisation
# ---------------------------------------------------------------------------

def _redact_posix(match):
    token = match.group(0)
    name = token.rstrip("/").rsplit("/", 1)[-1]
    return name or "<path>"


def _redact_windows(match):
    token = match.group(0)
    name = re.split(r"[\\/]", token.rstrip("\\/"))[-1]
    return name or "<path>"


def sanitize_error(error, root=None):
    """Return a user-safe message with host absolute paths removed.

    *error* may be an exception or a string.  When *root* is supplied, the
    root path (and its real path) is replaced with ``<root>``; any remaining
    absolute POSIX/Windows path is reduced to its final component.
    """
    if isinstance(error, BaseException):
        message = str(error) or error.__class__.__name__
    else:
        try:
            message = str(error)
        except Exception:
            message = _GENERIC_ERROR

    secrets = set()
    if root is not None:
        try:
            root_text = _as_text(root)
        except (TypeError, ValueError):
            root_text = ""
        if root_text:
            secrets.add(root_text)
            try:
                root_abs = os.path.abspath(root_text)
                secrets.add(root_abs)
                secrets.add(os.path.realpath(root_abs))
            except (OSError, ValueError):
                pass

    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        message = message.replace(secret, "<root>")

    message = _ABS_WINDOWS_RE.sub(_redact_windows, message)
    message = _ABS_POSIX_RE.sub(_redact_posix, message)

    message = message.strip()
    return message or _GENERIC_ERROR


# ---------------------------------------------------------------------------
# Archive member validation (zip-slip / tar-slip)
# ---------------------------------------------------------------------------

def _relative_member_path(member):
    """Return a safe relative archive member path, or ``None``."""
    try:
        raw = _as_text(member)
    except (TypeError, ValueError):
        return None

    if "\x00" in raw:
        return None

    value = _canonicalize(raw)
    if "\x00" in value:
        return None

    value = _unify_separators(value)
    if not value.strip():
        return None

    # Archive members must be relative on every platform.
    if value.startswith("/") or _DRIVE_RE.match(value):
        return None

    normalized = posixpath.normpath(value)
    if normalized in ("", ".", ".."):
        return None
    if normalized.startswith("../") or posixpath.isabs(normalized):
        return None

    return normalized


def is_safe_archive_member(member):
    """Return ``True`` when an archive member name cannot escape extraction."""
    return _relative_member_path(member) is not None


def safe_extract_path(root, member):
    """Resolve an archive member to an absolute path below *root*.

    Raises ``PermissionError`` for absolute members, Windows drives, NUL
    bytes, encoded traversal and any member that normalises outside *root*.
    Callers must still reject symlink/hardlink members and re-check the
    destination on disk before writing.
    """
    relative = _relative_member_path(member)
    if relative is None:
        raise PermissionError(_GENERIC_ERROR)

    result = safe_join(root, relative)
    if result is None:
        raise PermissionError(_GENERIC_ERROR)

    return result
