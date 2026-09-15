# Сборка wg_worker.exe (CPU-воркер поиска vanity-ключей и .onion v3-адресов)
# в standalone exe. Запускать из каталога v3/.
# Требуется: python 3.8 + pip install pynacl pyinstaller (или PYTHONPATH на pylibs).
# Результат кладётся в gui/bundled/wg_worker.exe (game подхватывает автоматически).
$ErrorActionPreference = "Stop"
# Корень v3 — каталог, в котором лежат core/wg_worker.py и gui/. Обычно это сам
# каталог скрипта (v3/); если скрипт положили в подкаталог — родительский.
$root = $PSScriptRoot
if (-not (Test-Path (Join-Path $root "core\wg_worker.py"))) {
    $root = Split-Path $PSScriptRoot -Parent
}
if (-not (Test-Path (Join-Path $root "core\wg_worker.py"))) {
    throw "не найден core\wg_worker.py — запускайте скрипт из каталога v3/"
}
$core = Join-Path $root "core\wg_worker.py"
$out  = Join-Path $root "gui\bundled\wg_worker.exe"

# Нативный движок .onion-поиска (mkp224o ed25519-donna). Если DLL нет — воркер
# продолжит работать на чистом Python-пути (WG_ONION_ENGINE=auto), поэтому это
# предупреждение, а не ошибка сборки.
$onionDll = Join-Path $root "core\onion_native\bin\wg_onion.dll"
if (-not (Test-Path $onionDll)) {
    Write-Warning "wg_onion.dll не найдена: $onionDll"
    Write-Warning "соберите её: powershell -ExecutionPolicy Bypass -File core\onion_native\build.ps1"
    Write-Warning "exe соберётся, но .onion-поиск будет медленным (python-путь)"
}

$py = "python"
if (Test-Path "C:\Users\ilja\AppData\Local\Programs\Python\Python38\python.exe") {
    $py = "C:\Users\ilja\AppData\Local\Programs\Python\Python38\python.exe"
}

# зависимости (pynacl, pyinstaller) лежат в v3/pylibs при наличии
if (Test-Path (Join-Path $root "pylibs")) {
    $env:PYTHONPATH = Join-Path $root "pylibs"
}

# --add-data кладёт wg_onion.dll в корень бандла: onion_native.py ищет её сначала
# рядом с собой, затем в sys._MEIPASS, затем рядом с exe.
$a = @("--noconfirm", "--onefile", "--windowed", "--name", "wg_worker")
if (Test-Path $onionDll) {
    $a += @("--add-data", "$onionDll;.")     # разделитель ";" в Windows-сборке
}
$a += $core

& $py -m PyInstaller @a
if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed" }
New-Item -ItemType Directory -Force -Path (Split-Path $out -Parent) | Out-Null
Copy-Item "dist\wg_worker.exe" $out -Force
if (Test-Path $onionDll) {
    # страховка для --onedir и ручных запусков: DLL рядом с exe
    Copy-Item $onionDll (Split-Path $out -Parent) -Force
    Write-Host "onion engine bundled -> wg_onion.dll"
}
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
