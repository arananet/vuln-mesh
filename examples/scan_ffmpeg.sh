#!/usr/bin/env bash
# Scan FFmpeg with vuln-mesh (v0.1 PoC)
# Prerequisites: git, gcc/clang with ASan, ollama running qwen2.5-coder:32b
set -euo pipefail

FFMPEG_DIR="${1:-/tmp/ffmpeg-src}"
REPORT_OUT="vuln-mesh-ffmpeg-report.md"

if [ ! -d "$FFMPEG_DIR" ]; then
  echo "[*] Cloning FFmpeg source..."
  git clone --depth=1 https://git.ffmpeg.org/ffmpeg.git "$FFMPEG_DIR"
fi

echo "[*] Running vuln-mesh against $FFMPEG_DIR"
vuln-mesh \
  --config config/default.yaml \
  --source "$FFMPEG_DIR" \
  --output "$REPORT_OUT" \
  --top-n 50

echo "[*] Done. Report: $REPORT_OUT"
