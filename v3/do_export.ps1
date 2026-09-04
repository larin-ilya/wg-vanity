# Экспорт GUI (Godot 3.6.3) в портативный WG_Vanity_v3.exe + вшивка иконки.
# Запускать из каталога v3/. Требуется Godot 3.6.3 + export templates,
# а также rcedit-x64.exe рядом (для замены Godot-иконки на свою).
$ErrorActionPreference = "Continue"

# убьём зависшие процессы, если они держат файлы (экспорт иначе падает)
Get-Process -Name "Godot_*","WG_Vanity*","wg_worker*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$here = Split-Path $PSScriptRoot               # каталог v3 (где лежит скрипт)
$exeOut = Join-Path $here "export\WG_Vanity_v3.exe"
$guiPath = Join-Path $here "gui"
$rcedit = Join-Path $here "rcedit-x64.exe"
if (-not (Test-Path $rcedit)) { $rcedit = "D:\Godot_v3.6.3\rcedit-x64.exe" }
$icon = Join-Path $here "gui\assets\icon.ico"

$godot = Get-Command "godot" -ErrorAction SilentlyContinue
if (-not $godot) {
    if (Test-Path "D:\Godot_v3.6.3\Godot_v3.6.3-stable_win64.exe") {
        $godot = "D:\Godot_v3.6.3\Godot_v3.6.3-stable_win64.exe"
    }
}
if (-not $godot) { Write-Host "Godot не найден. Укажите путь в скрипте."; exit 1 }

New-Item -ItemType Directory -Force -Path (Join-Path $here "export") | Out-Null
Remove-Item $exeOut -ErrorAction SilentlyContinue
& $godot --headless --path $guiPath --export "Windows Desktop" $exeOut 2>&1 | Out-File -Encoding ascii (Join-Path $here "export_log.txt")
Write-Host "export exitcode=$LASTEXITCODE"

# Godot 3.6 НЕ вшивает иконку в exe сам — нужен внешний rcedit
if (Test-Path $exeOut -and (Test-Path $rcedit) -and (Test-Path $icon)) {
    & $rcedit $exeOut --set-icon $icon `
        --set-file-version "3.0.0" `
        --set-product-version "3.0.0" `
        --set-version-string "ProductName" "WG Vanity 3" `
        --set-version-string "FileDescription" "Podbor krasivyh WireGuard-klyuchey i onion v3-adresov" `
        --set-version-string "CompanyName" "larin-ilya"
    Write-Host "rcedit exit=$LASTEXITCODE"
}
Write-Host "done -> $exeOut"
