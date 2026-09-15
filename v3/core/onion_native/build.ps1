# build.ps1 - build bin\wg_onion.dll from the vendored mkp224o subset.
#
# Run from anywhere:  powershell -ExecutionPolicy Bypass -File v3\core\onion_native\build.ps1
#
# Why zig and why no libc:
#   There is no MSVC/gcc/mingw on the machines this project is built on. zig is
#   available through the bundled Python (`python -m ziglang`, 0.13.0) and
#   cross-compiles fine to x86_64-windows-gnu. Passing -lc on this machine
#   breaks with `error: CacheCheckFailed` while zig sets up libc, so the module
#   is linked WITHOUT any C runtime:
#     - include\ holds minimal <string.h>/<stdlib.h>/<sys/param.h> stand-ins
#     - include\sodium\ stands in for the two libsodium headers the vendored
#       ed25519-donna glue includes
#     - wg_onion_crypto.c supplies SHA-512, the ChaCha20 DRBG and memset
#     - wg_onion_dllentry.c supplies _tls_index and _DllMainCRTStartup
#     - memcpy/memset/memmove/memcmp come from zig's compiler_rt
#   Nothing here calls malloc/printf/exit, so no CRT is needed.

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$bin  = Join-Path $root "bin"
$dll  = Join-Path $bin "wg_onion.dll"

# ---------------------------------------------------------------- toolchain
$py = $null
foreach ($cand in @("python", "py", "python3")) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cand; break }
}
if (-not $py) { throw "no python found on PATH (needed for 'python -m ziglang')" }

$zigver = & $py -m ziglang version 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "'$py -m ziglang version' failed - install with: $py -m pip install ziglang`n$zigver"
}
Write-Host "zig      : $zigver (via $py -m ziglang)"

# ------------------------------------------------------------------- inputs
$sources = @(
    (Join-Path $root "wg_onion_bridge.c")
    (Join-Path $root "wg_onion_crypto.c")
    (Join-Path $root "wg_onion_dllentry.c")
    (Join-Path $root "vendor\keccak.c")
    (Join-Path $root "vendor\base32_to.c")
)
foreach ($s in $sources) {
    if (-not (Test-Path $s)) { throw "missing source file: $s" }
}

$includeDirs = @(
    (Join-Path $root "include")          # string.h / stdlib.h / sys/param.h / sodium/*
    (Join-Path $root "vendor")           # keccak.h / base32.h / types.h / likely.h
    (Join-Path $root "vendor\ed25519")   # ed25519_impl_pre.h + ed25519-donna/
    $root                                # wg_onion_crypto.h
)

New-Item -ItemType Directory -Force -Path $bin | Out-Null
$cacheDir = Join-Path $root ".zig-cache"
$globalCacheDir = Join-Path $root ".zig-global-cache"
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
New-Item -ItemType Directory -Force -Path $globalCacheDir | Out-Null

# -------------------------------------------------------------------- build
$zigArgs = @("build-lib") + $sources + @(
    "-dynamic",
    "-target", "x86_64-windows-gnu",
    "-O", "ReleaseFast"
)
foreach ($inc in $includeDirs) { $zigArgs += @("-I", $inc) }
$zigArgs += @(
    "--cache-dir", $cacheDir,
    "--global-cache-dir", $globalCacheDir,
    "--name", "wg_onion",
    "-femit-bin=$dll"
)

Write-Host ""
Write-Host "$py -m ziglang $($zigArgs -join ' ')"
Write-Host ""

& $py -m ziglang @zigArgs
if ($LASTEXITCODE -ne 0) { throw "zig build-lib failed with exit code $LASTEXITCODE" }

# zig also drops a .lib import library and a .pdb next to the DLL; we only ship
# the DLL, so remove them to keep bin/ reproducible.
foreach ($extra in @("wg_onion.lib", "wg_onion.pdb")) {
    $p = Join-Path $bin $extra
    if (Test-Path $p) { Remove-Item $p -Force }
}

if (-not (Test-Path $dll)) { throw "build reported success but $dll does not exist" }

$size = (Get-Item $dll).Length
Write-Host ""
Write-Host ("built: {0}" -f $dll)
Write-Host ("size : {0} bytes ({1:N1} KiB)" -f $size, ($size / 1KB))
