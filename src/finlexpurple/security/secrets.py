"""Secrets hygiene helpers (Phase 7; decisions.md §28 item 3).

Two concrete protections, complementing Phase 1's log redaction:

* Files that hold keys are written **owner-only (0600)** on POSIX, atomically,
  so a secret never lands in a world-readable file.
* Secrets handed to a sandboxed/containerized tool are passed **by reference at
  runtime** — ``docker run -e NAME`` passes the *name*, and Docker reads the
  value from the parent process environment at run time. The value is therefore
  never written into a command flag that could be logged, nor baked into an
  image layer.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable
from pathlib import Path


def ensure_owner_only(path: Path) -> None:
    """Restrict ``path`` to owner read/write (0600) on POSIX; no-op on Windows."""

    if os.name != "nt":
        path.chmod(0o600)


def write_secret_file(path: Path, content: str) -> None:
    """Atomically write ``content`` to ``path`` with owner-only (0600) permissions.

    Writes to a sibling temp file, fsyncs, sets 0600, then replaces — so a
    reader never sees a partial file and the secret is never briefly
    world-readable.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=".secret-", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            if os.name != "nt":
                temporary.chmod(0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        ensure_owner_only(path)
    except OSError:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def runtime_secret_flags(env_names: Iterable[str]) -> list[str]:
    """Return ``docker run`` flags that pass secrets *by name* at runtime.

    For each environment variable name, emit ``-e NAME`` (not ``-e NAME=value``)
    so Docker reads the value from the parent environment when the container
    starts. The secret value never appears in a flag string and is never baked
    into an image layer. Names are validated to be plain identifiers so nothing
    shell-special can be injected.
    """

    flags: list[str] = []
    for name in env_names:
        if not name or not name.replace("_", "").isalnum():
            raise ValueError(f"Invalid environment variable name for secret passthrough: {name!r}")
        flags.extend(["-e", name])
    return flags
