from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


def _find_compiler() -> str:
    """Prefer gcc; clang is tried second (requires ASan runtime libs)."""
    for cc in ("gcc", "clang"):
        if shutil.which(cc):
            return cc
    raise RuntimeError("No C compiler found (gcc or clang required)")


def compile_with_asan(source_path: str, out_dir: str) -> tuple[str | None, str | None]:
    """Compile source with ASan. Returns (binary_path, None) or (None, stderr)."""
    compiler = _find_compiler()
    binary = str(Path(out_dir) / "target")
    result = subprocess.run(
        [compiler, "-fsanitize=address", "-g", "-o", binary, source_path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        return None, result.stderr
    return binary, None
