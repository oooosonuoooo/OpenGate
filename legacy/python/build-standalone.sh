#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required" >&2; exit 1; }
python3 -m venv "$ROOT/.venv-build"
"$ROOT/.venv-build/bin/pip" install --upgrade pip pyinstaller
"$ROOT/.venv-build/bin/pyinstaller" --clean --onefile --name opengate "$ROOT/opengate.py"
echo "Standalone binary: $ROOT/dist/opengate"
