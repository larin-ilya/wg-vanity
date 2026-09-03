# Экспорт GUI (Godot 3.6.3) в портативный WG_Vanity_v2.exe.
# Запускать из каталога v2/. Требуется установленный Godot 3.6.3 и export templates.
$ErrorActionPreference = "Continue"

# убьём зависшие процессы, если они держат файлы (экспорт иначе падает)
Get-Process -Name "Godot_*","WG_Vanity*","wg_worker*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$here = Split-Path $PSScriptRoot               # каталог v2 (где лежит скрипт)
$exeOut = Join-Path $here "export\WG_Vanity_v2.exe"
$guiPath = Join-Path $here "gui"

$godot = Get-Command "godot" -ErrorAction SilentlyContinue
if (-not $godot) {
    if (Test-Path "D:\Godot_v3.6.3\Godot_v3.6.3-stable_win64.exe") {
        $godot = "D:\Godot_v3.6.3\Godot_v3.6.3-stable_win64.exe"
    }
}
if (-not $godot) { Write-Host "Godot не найден. Укажите путь в скрипте."; exit 1 }

& $godot --headless --path $guiPath --export "Windows Desktop" $exeOut 2>&1 | Out-File -Encoding ascii (Join-Path $here "export_log.txt")
Write-Host "export exitcode=$LASTEXITCODE"
Write-Host "done -> $exeOut"
