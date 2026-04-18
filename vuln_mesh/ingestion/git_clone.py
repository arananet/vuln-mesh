from __future__ import annotations

import shutil
import subprocess
import tempfile


def is_git_url(source: str) -> bool:
    return source.startswith(("https://", "http://", "git@", "github.com/"))


def _inject_token(url: str, token: str) -> str:
    for prefix in ("https://", "http://"):
        if url.startswith(prefix):
            return f"{prefix}{token}@{url[len(prefix):]}"
    return url


def clone_repo(url: str, token: str | None = None, timeout: int = 120) -> str:
    """Clone shallowly into a temp dir. Returns temp dir path — caller must clean up."""
    clone_url = _inject_token(url, token) if token else url
    temp_dir = tempfile.mkdtemp(prefix="vuln-mesh-clone-")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", clone_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            err = result.stderr.replace(token, "***") if token else result.stderr
            raise RuntimeError(f"git clone failed: {err.strip()}")
        return temp_dir
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def cleanup(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)
