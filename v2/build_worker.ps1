# Сборка wg_worker.exe (CPU-воркер поиска vanity-ключей) в standalone exe.
# Требуется: python 3.8 + pip install pynacl pyinstaller
# Результат кладётся в gui/bundled/wg_worker.exe (game подхватывает его автоматически).
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent   # корень v2
$core = Join-Path $root "core\wg_worker.py"
$out  = Join-Path $root "gui\bundled\wg_worker.exe"

$py = "python"
if (Test-Path "C:\Users\ilja\AppData\Local\Programs\Python\Python38\python.exe") {
    $py = "C:\Users\ilja\AppData\Local\Programs\Python\Python38\python.exe"
}

& $py -m PyInstaller --noconfirm --onefile --console=0 --name wg_worker "$core"
if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed" }
New-Item -ItemType Directory -Force -Path (Split-Path $out -Parent) | Out-Null
Copy-Item "dist\wg_worker.exe" $out -Force
Write-Host "worker built -> $out"
