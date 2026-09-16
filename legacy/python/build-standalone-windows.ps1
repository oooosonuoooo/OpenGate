$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
python -m venv "$Root\.venv-build"
& "$Root\.venv-build\Scripts\python.exe" -m pip install --upgrade pip pyinstaller
& "$Root\.venv-build\Scripts\pyinstaller.exe" --clean --onefile --name opengate "$Root\opengate.py"
Write-Host "Standalone EXE: $Root\dist\opengate.exe"
