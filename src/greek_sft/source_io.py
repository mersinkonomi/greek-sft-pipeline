"""Read-only regular-file handles with best-effort access-time preservation.

This module never changes file metadata. Linux O_NOATIME suppresses the access
timestamp write normally caused by reading an old file on a relatime mount.
An EPERM-only fallback supports files owned by another user; that fallback (and
systems without O_NOATIME) may still incur an operating-system atime update.
"""
from __future__ import annotations

import errno
import os
import stat
from typing import BinaryIO


def open_source_readonly(path: str | bytes | os.PathLike, buffering: int = -1) -> BinaryIO:
    """Return a binary, read-only regular-file handle usable with ``with``.

The final path component cannot be a symlink. O_NONBLOCK prevents a substituted
FIFO from blocking the open, and the opened descriptor must be a regular file
before any read. Parent-directory containment, source identity, and stat/hash
comparisons before and after reading remain the caller's responsibility.

O_NOFOLLOW and O_NONBLOCK are required: platforms missing either fail closed.
O_NOATIME is used when available and retried without it only for EPERM. No
permission changes, timestamp restoration, or other source writes are made.
"""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if not nofollow or not nonblock:
        raise NotImplementedError("Safe source reads require O_NOFOLLOW and O_NONBLOCK")
    flags = os.O_RDONLY | nofollow | nonblock | getattr(os, "O_CLOEXEC", 0)
    noatime = getattr(os, "O_NOATIME", 0)
    try:
        descriptor = os.open(path, flags | noatime)
    except OSError as error:
        if not noatime or error.errno != errno.EPERM:
            raise
        descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(errno.EINVAL, "Source is not a regular file", os.fspath(path))
        return os.fdopen(descriptor, "rb", buffering=buffering)
    except BaseException:
        # fdopen owns the descriptor only on success. Preserve the original
        # exception even if a failed wrapper already closed its descriptor.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
