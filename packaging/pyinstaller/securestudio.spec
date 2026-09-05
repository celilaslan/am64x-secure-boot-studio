# PyInstaller spec for AM64x Secure Boot Studio.
# Build only in a clean environment where PySide6 + PyInstaller are installed.
from PyInstaller.utils.hooks import collect_submodules

hidden = collect_submodules("PySide6")

a = Analysis(
    ["packaging/pyinstaller/securestudio_entry.py"],
    pathex=["src"],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="AM64x-Secure-Boot-Studio",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
)
