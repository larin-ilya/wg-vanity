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

# Нативный движок поиска (onion v3 + WireGuard, mkp224o ed25519-donna). Если DLL
# нет — воркер продолжит работать на чистом Python-пути
# (WG_NATIVE_ENGINE=auto), поэтому это предупреждение, а не ошибка сборки.
$coreDll = Join-Path $root "core\vanity_native\bin\vanity_core.dll"
if (-not (Test-Path $coreDll)) {
    Write-Warning "vanity_core.dll не найдена: $coreDll"
    Write-Warning "соберите её: powershell -ExecutionPolicy Bypass -File core\vanity_native\build.ps1"
    Write-Warning "exe соберётся, но поиск будет медленным (python-путь)"
}

$py = "python"
if (Test-Path "C:\Users\ilja\AppData\Local\Programs\Python\Python38\python.exe") {
    $py = "C:\Users\ilja\AppData\Local\Programs\Python\Python38\python.exe"
}

# зависимости (pynacl, pyinstaller) лежат в v3/pylibs при наличии
if (Test-Path (Join-Path $root "pylibs")) {
    $env:PYTHONPATH = Join-Path $root "pylibs"
}

# --add-data кладёт vanity_core.dll в корень бандла: vanity_native.py ищет её
# сначала рядом с собой, затем в sys._MEIPASS, затем рядом с exe.
$icon = Join-Path $root "gui\assets\icon.ico"
$a = @("--noconfirm", "--onefile", "--windowed", "--name", "wg_worker")
# Иконку вшиваем именно здесь: PyInstaller патчит ресурс загрузчика ДО того,
# как дописать архив. Внешний rcedit на --onefile-сборке применять НЕЛЬЗЯ:
# он перезаписывает PE и теряет дописанный архив (проверено: exe ужимался
# с 17 МБ до 406 КБ и переставал запускаться).
if (Test-Path $icon) {
    $a += @("--icon", $icon)
}
if (Test-Path $coreDll) {
    $a += @("--add-data", "$coreDll;.")     # разделитель ";" в Windows-сборке
}
$a += $core

& $py -m PyInstaller @a
if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed" }
New-Item -ItemType Directory -Force -Path (Split-Path $out -Parent) | Out-Null
Copy-Item "dist\wg_worker.exe" $out -Force
if (Test-Path $coreDll) {
    # страховка для --onedir и ручных запусков: DLL рядом с exe
    Copy-Item $coreDll (Split-Path $out -Parent) -Force
    Write-Host "native engine bundled -> vanity_core.dll"
}
Write-Host "worker built -> $out"
