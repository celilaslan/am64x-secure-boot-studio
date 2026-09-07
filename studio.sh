#!/usr/bin/env bash
set -eu

STUDIO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_COMMAND=${AM64X_STUDIO_PYTHON:-python3}
CACHE_ROOT=${XDG_CACHE_HOME:-"${HOME}/.cache"}
STUDIO_ENV_DIR=${AM64X_STUDIO_VENV:-"${CACHE_ROOT}/am64x-secure-boot-studio/venv"}
STUDIO_PYTHON="${STUDIO_ENV_DIR}/bin/python"
INSTALL_MARKER="${STUDIO_ENV_DIR}/.securestudio-source"

if ! command -v "$PYTHON_COMMAND" >/dev/null 2>&1; then
    echo "HATA: python3 bulunamadı. Python 3.10 veya üzeri gereklidir." >&2
    exit 2
fi

if [ ! -x "$STUDIO_PYTHON" ]; then
    echo "[Secure Boot Studio] Kullanıcı dizininde ilk kullanım ortamı hazırlanıyor..."
    mkdir -p "$(dirname -- "$STUDIO_ENV_DIR")"
    if ! "$PYTHON_COMMAND" -m venv "$STUDIO_ENV_DIR"; then
        echo "Standart venv modülü kullanılamadı; mevcut virtualenv deneniyor..."
        if ! "$PYTHON_COMMAND" -m virtualenv "$STUDIO_ENV_DIR"; then
            echo "HATA: Python venv/virtualenv kullanılamıyor. Sudo gerekmez; sistem yöneticisinden python3-venv paketini istemeniz yeterlidir." >&2
            exit 2
        fi
    fi
fi

PROJECT_ID=$(printf '%s\n%s\n' "$STUDIO_ROOT" "$(cksum < "${STUDIO_ROOT}/pyproject.toml")")
INSTALLED_ID=""
if [ -f "$INSTALL_MARKER" ]; then
    INSTALLED_ID=$(cat "$INSTALL_MARKER")
fi

if [ "$PROJECT_ID" != "$INSTALLED_ID" ] || ! "$STUDIO_PYTHON" -c "import am64x_secure_toolkit, PySide6" >/dev/null 2>&1; then
    echo "[Secure Boot Studio] Bu kaynak klasörü kullanıcı ortamına bağlanıyor..."
    "$STUDIO_PYTHON" -m pip install -e "${STUDIO_ROOT}[gui]"
    printf '%s' "$PROJECT_ID" > "$INSTALL_MARKER"
fi

export PYTHONPATH="${STUDIO_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
exec "$STUDIO_PYTHON" -c "from am64x_secure_toolkit.gui import main; raise SystemExit(main())"
