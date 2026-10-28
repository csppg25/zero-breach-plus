"""Refuse Windows remote drives and filesystem redirections before reads.

Checks are conservative and use lstat so a reparse point is inspected rather
than followed. POSIX network mounts cannot always be distinguished from local
paths here. This is not a sandbox against concurrent filesystem changes.
"""

import os
import stat
import sys


def local_temp_dir():
    """Select a local temp directory without tempfile's write-probing fallback."""
    candidates = [os.environ.get(key, "") for key in ("TMPDIR", "TEMP", "TMP")]
    if sys.platform == "win32":
        candidates.extend(os.path.join(base, "Temp") for base in
                          (os.environ.get("LOCALAPPDATA", ""),
                           os.environ.get("SystemRoot", "")) if base)
    else:
        candidates.extend(("/tmp", "/var/tmp", "/private/tmp"))
    for candidate in candidates:
        if candidate and not path_problem(candidate) and os.path.isdir(candidate):
            return candidate
    raise PermissionError("no safe local temporary directory is available")


def path_problem(path):
    """Return why a path cannot safely be inspected, or an empty string."""
    path = os.fspath(path)
    if not os.path.isabs(path):
        return "relative path cannot be classified as local"
    if ".." in path.replace("\\", "/").split("/"):
        return "parent-directory traversal cannot be classified as local"
    if sys.platform == "win32":
        s = path.replace("/", "\\")
        if s.startswith("\\\\"):
            return "UNC or device path was not opened"
        drive, _tail = os.path.splitdrive(s)
        if len(drive) != 2 or drive[1] != ":":
            return "path does not name an absolute local drive"
        try:
            import ctypes
            kind = ctypes.windll.kernel32.GetDriveTypeW(drive + "\\")
        except (AttributeError, OSError):
            return "drive locality could not be established"
        if kind not in (2, 3, 5, 6):  # removable, fixed, CD-ROM, RAM disk
            return "drive is remote or its locality is unknown"

    drive, tail = os.path.splitdrive(path)
    current = drive + os.sep
    parts = [p for p in tail.replace("\\", os.sep).split(os.sep) if p]
    for index, part in enumerate(parts):
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return ""  # caller handles a genuinely absent artifact
        except OSError as exc:
            return "cannot safely inspect {}: {}".format(current, exc)
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            # macOS exposes its standard /var, /tmp and /etc directories through
            # root-owned aliases into /private. These exact system aliases are
            # safe to validate lexically; arbitrary user links remain refused.
            # readlink reads the link itself and does not traverse its target.
            aliases = {"/var": "/private/var", "/tmp": "/private/tmp",
                       "/etc": "/private/etc"}
            target = aliases.get(current) if sys.platform == "darwin" else None
            if (target and stat.S_ISLNK(info.st_mode)
                    and getattr(info, "st_uid", None) == 0):
                try:
                    link = os.readlink(current)
                except OSError as exc:
                    return "cannot inspect system alias {}: {}".format(current, exc)
                # Apple's links commonly use 'private/var', relative to '/'.
                # Accept only these two exact spellings of the expected target.
                if link in (target, target.lstrip("/")):
                    canonical = os.path.join(target, *parts[index + 1:])
                    return path_problem(canonical)
            return "symlink or reparse point was not followed: {}".format(current)
    return ""


def walk_local(root, onerror=None):
    """Top-down os.walk equivalent that never classifies a link by following it.

    The caller can prune the yielded dirs list in place, as with os.walk.
    Refused entries are delivered to onerror as PermissionError instances.
    """
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            problem = path_problem(current)
            if problem:
                raise PermissionError(13, problem, current)
            dirs, files = [], []
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if (stat.S_ISLNK(info.st_mode)
                                or getattr(info, "st_file_attributes", 0) & 0x400):
                            raise PermissionError(13, "symlink or reparse point "
                                                  "was not followed", entry.path)
                        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                            raise PermissionError(13, "special filesystem entry "
                                                  "was not opened", entry.path)
                        (dirs if stat.S_ISDIR(info.st_mode) else files).append(entry.name)
                    except OSError as exc:
                        if onerror:
                            onerror(exc)
        except OSError as exc:
            if onerror:
                onerror(exc)
            continue
        yield current, dirs, files
        pending.extend(os.path.join(current, d) for d in reversed(dirs))
