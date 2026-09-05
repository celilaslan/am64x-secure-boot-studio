#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python -m pip install -e '.[gui,bundle]'
python -m PyInstaller --clean --noconfirm packaging/pyinstaller/securestudio.spec
printf 'Built: %s\n' "$ROOT/dist/AM64x-Secure-Boot-Studio"
