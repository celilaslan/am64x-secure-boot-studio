$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root
python -m pip install -e ".[gui,bundle]"
python -m PyInstaller --clean --noconfirm packaging/pyinstaller/securestudio.spec
Write-Host "Built: $Root\dist\AM64x-Secure-Boot-Studio.exe"
