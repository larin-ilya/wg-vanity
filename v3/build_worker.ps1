# Сборка wg_worker.exe (CPU-воркер поиска vanity-ключей и .onion v3-адресов)
# в standalone exe. Запускать из каталога v3/.
# Требуется: python 3.8 + pip install pynacl pyinstaller (или PYTHONPATH на pylibs).
# Результат кладётся в gui/bundled/wg_worker.exe (game подхватывает автоматически).
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent     # корень v3 (если вызывается из v3/)
if ((Split-Path $PSScriptRoot -Leaf) -ne "v3") {
    $root = $PSScriptRoot                    # или уже находимся внутри v3/
}
$core = Join-Path $root "core\wg_worker.py"
$out  = Join-Path $root "gui\bundled\wg_worker.exe"

$py = "python"
if (Test-Path "C:\Users\ilja\AppData\Local\Programs\Python\Python38\python.exe") {
    $py = "C:\Users\ilja\AppData\Local\Programs\Python\Python38\python.exe"
}

# зависимости (pynacl, pyinstaller) лежат в v3/pylibs при наличии
if (Test-Path (Join-Path $root "pylibs")) {
    $env:PYTHONPATH = Join-Path $root "pylibs"
}

& $py -m PyInstaller --noconfirm --onefile --windowed --name wg_worker "$core"
if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed" }
New-Item -ItemType Directory -Force -Path (Split-Path $out -Parent) | Out-Null
Copy-Item "dist\wg_worker.exe" $out -Force
Write-Host "worker built -> $out"

# установить иконку воркера (опционально), если есть rcedit
$rcedit = "rcedit-x64.exe"
if (Test-Path (Join-Path $root "rcedit-x64.exe")) {
    $rcedit = Join-Path $root "rcedit-x64.exe"
}
$icon = Join-Path $root "gui\assets\icon.ico"
if (Get-Command $rcedit -ErrorAction SilentlyContinue -and (Test-Path $icon)) {
    & $rcedit $out --set-icon $icon
    Write-Host "worker icon set"
}
