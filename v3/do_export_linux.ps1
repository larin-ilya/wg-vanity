# Экспорт GUI (Godot 3.6.3) в Linux/X11-бинарник WG_Vanity_v3.x86_64.
# Запускать из каталога v3/. Требуется Godot 3.6.3 + export templates
# (linux_x11_64_release).
#
# Отличия от do_export.ps1 (Windows):
#   * пресет "Linux/X11" вместо "Windows Desktop";
#   * НЕТ rcedit: у ELF нет PE-ресурсов, иконку и версию в бинарник вшить
#     некуда — вызывать rcedit здесь нельзя (он бы испортил файл). Иконка окна
#     берётся из pck (project.godot -> config/icon).
#   * рядом с .x86_64 нужно положить воркер `wg_worker` (собранный
#     v3/build_worker_linux.sh) — GUI ищет его sidecar'ом рядом с собой.
#     См. v3/README.md, раздел «Linux».
$ErrorActionPreference = "Continue"

# убьём зависшие процессы, если они держат файлы (экспорт иначе падает)
Get-Process -Name "Godot_*","WG_Vanity*","wg_worker*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Каталог v3 — тот, где лежат gui/project.godot и core/. Обычно это сам каталог
# скрипта; если скрипт положили в подкаталог — родительский.
$here = $PSScriptRoot
if (-not (Test-Path (Join-Path $here "gui\project.godot"))) {
    $here = Split-Path $PSScriptRoot
}
if (-not (Test-Path (Join-Path $here "gui\project.godot"))) {
    Write-Host "не найден gui\project.godot — запускайте скрипт из каталога v3/"
    exit 1
}
$exeOut = Join-Path $here "export\linux\WG_Vanity_v3.x86_64"
$guiPath = Join-Path $here "gui"
$preset = "Linux/X11"

# Поиск движка: $env:GODOT -> godot в PATH -> известные пути машин сборки.
$godot = $null
if ($env:GODOT -and (Test-Path $env:GODOT)) {
    $godot = $env:GODOT
}
if (-not $godot) {
    $godot = Get-Command "godot" -ErrorAction SilentlyContinue
}
if (-not $godot) {
    foreach ($p in @("D:\AI_PROJEKTZ\Godot_v3.6.3-stable_win64.exe",
                     "D:\Godot_v3.6.3\Godot_v3.6.3-stable_win64.exe")) {
        if (Test-Path $p) { $godot = $p; break }
    }
}
if (-not $godot) { Write-Host "Godot не найден. Укажите путь в скрипте."; exit 1 }

New-Item -ItemType Directory -Force -Path (Split-Path $exeOut -Parent) | Out-Null
Remove-Item $exeOut -ErrorAction SilentlyContinue
$logOut = Join-Path $here "export_log_linux.txt"
& $godot --headless --path $guiPath --export $preset $exeOut 2>&1 | Out-File -Encoding ascii $logOut
Write-Host "export exitcode=$LASTEXITCODE"
# Полный лог — в export_log_linux.txt (там сотни строк savepack); сюда только
# то, что важно: ошибки/предупреждения.
$bad = Select-String -Path $logOut -Pattern "ERROR|WARNING|Cannot|failed|не найден" -ErrorAction SilentlyContinue
if ($bad) { Write-Host "--- проблемные строки лога ---"; $bad | ForEach-Object { Write-Host $_.Line } }
else       { Write-Host "лог чист: ERROR/WARNING нет (полностью: $logOut)" }

if (-not (Test-Path $exeOut)) {
    Write-Host "ОШИБКА: $exeOut не создан"
    exit 1
}
$size = (Get-Item $exeOut).Length
Write-Host ("done -> {0} ({1} bytes, {2:N1} MiB)" -f $exeOut, $size, ($size / 1MB))

# воркер рядом с бинарником (без него GUI не найдёт вычислитель)
$worker = Join-Path $here "gui\bundled\wg_worker"
if (Test-Path $worker) {
    Copy-Item $worker (Split-Path $exeOut -Parent) -Force
    Write-Host "worker copied -> $(Split-Path $exeOut -Parent)\wg_worker"
} else {
    Write-Warning "не найден gui\bundled\wg_worker — соберите его: v3\build_worker_linux.sh"
}
