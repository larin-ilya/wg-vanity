# Экспорт Android-APK (Godot 3.6.3) для wg-vanity.
# Запускать из каталога v3/. Требуется:
#   * Godot 3.6.3 + export templates (android_debug.apk / android_release.apk);
#   * Android SDK (platform-tools + build-tools) и JDK 17;
#   * debug.keystore + алиас/пароли;
#   * пути к SDK/JDK прописаны в editor settings Godot (export/android/*)
#     ИЛИ заданы переменными окружения (см. ниже).
# Результат: v3/export/android/WG_Vanity_v3.apk — подписанный debug-ключом APK,
# с GDNative-библиотеками в lib/<abi>/ (см. repack_apk.py — почему).
$ErrorActionPreference = "Continue"

$here = $PSScriptRoot
if (-not (Test-Path (Join-Path $here "gui\project.godot"))) {
    $here = Split-Path $PSScriptRoot
}
if (-not (Test-Path (Join-Path $here "gui\project.godot"))) {
    Write-Host "не найден gui\project.godot — запускайте скрипт из каталога v3/"
    exit 1
}

$ANDROID_DIR = if ($env:WG_VANITY_ANDROID_DIR) { $env:WG_VANITY_ANDROID_DIR } else { "D:\AI_PROJEKTZ\Android" }
$SDK  = Join-Path $ANDROID_DIR "sdk"
$JDK  = Join-Path $ANDROID_DIR "jdk17"
$KS   = Join-Path $ANDROID_DIR "debug.keystore"

$godot = $env:GODOT
if (-not $godot) { $godot = Get-Command "godot" -ErrorAction SilentlyContinue }
if (-not $godot) {
    foreach ($p in @("D:\AI_PROJEKTZ\Godot_v3.6.3-stable_win64.exe",
                     "D:\Godot_v3.6.3\Godot_v3.6.3-stable_win64.exe")) {
        if (Test-Path $p) { $godot = $p; break }
    }
}
if (-not $godot) { Write-Host "Godot не найден. Задайте переменную GODOT."; exit 1 }

$gui = Join-Path $here "gui"
$outDir = Join-Path $here "export\android"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$apk = Join-Path $outDir "WG_Vanity_v3.apk"
Remove-Item $apk -ErrorAction SilentlyContinue

$env:JAVA_HOME = $JDK
Write-Host "godot : $godot"
Write-Host "jdk   : $JDK"
Write-Host "sdk   : $SDK"

# --export-debug: нужен debug-keystore. Release-экспорт потребовал бы
# release-keystore, которого в комплекте нет.
& $godot --path $gui --export-debug "Android" $apk | Out-File -Encoding ascii (Join-Path $here "export_log_android.txt")
Write-Host "export exitcode=$LASTEXITCODE"
if (-not (Test-Path $apk)) { Write-Host "APK не создан — смотрите export_log_android.txt"; exit 1 }

# GDNative-библиотеки -> lib/<abi>/ + подпись
python (Join-Path $here "repack_apk.py") --apk $apk --sdk $SDK --jdk $JDK --keystore $KS
if ($LASTEXITCODE -ne 0) { Write-Host "repack/подпись не удались"; exit 1 }
Write-Host "done -> $apk"
