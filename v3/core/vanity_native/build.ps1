# build.ps1 - build the native vanity-search engine (Windows DLL or Linux/ARM .so)
# from the vendored mkp224o subset.
#
# The module serves BOTH vanity searches: .onion v3 addresses (base32) and
# WireGuard keys (base64), see vanity_bridge.c.
#
# Run from anywhere:
#   powershell -ExecutionPolicy Bypass -File v3\core\vanity_native\build.ps1
#   powershell -ExecutionPolicy Bypass -File v3\core\vanity_native\build.ps1 -Target linux
#
# -Target selects the output; the default (windows) is byte-for-byte the build
# this project has always shipped:
#
#   windows           x86_64-windows-gnu     -> bin\vanity_core.dll      (default)
#   linux             x86_64-linux-gnu       -> bin\libvanity_core.so
#   linux-aarch64     aarch64-linux-gnu      -> bin\libvanity_core-aarch64.so
#   linux-armv7       arm-linux-gnueabihf   -> bin\libvanity_core-armv7.so
#
# ("linux-arm" and "aarch64"/"armv7" are accepted as aliases.) The non-x86_64
# Linux targets exist for Raspberry Pi / ARM boards; nothing but -target (and
# -mcpu for 32-bit ARM) changes between them, the sources are already portable
# (see the _WIN32 guards in vanity_bridge.c / vanity_dllentry.c).
#
# 32-bit ARM note: zig has no "armv7" *architecture* name - 32-bit ARM is
# "arm", and the ARMv7-A level is selected with -mcpu. We pin cortex_a8
# (ARMv7-A + VFPv3, no NEON), which every 32-bit-capable Raspberry Pi (2/3/4/5
# in AArch32) and most other ARMv7 boards can run. zig's default "generic" ARM
# CPU does NOT work here (it emits an inline-asm `bx lr` the CPU rejects), and
# `armv7a` is not a valid -mcpu name in zig 0.13.
#
# Why zig and why no libc:
#   There is no MSVC/gcc/mingw on the machines this project is built on. zig is
#   available through the bundled Python (`python -m ziglang`, 0.13.0) and
#   cross-compiles to x86_64-windows-gnu AND to the Linux targets above from the
#   same Windows host - that is how bin\libvanity_core.so gets produced without
#   a Linux toolchain. Passing -lc on this machine breaks with
#   `error: CacheCheckFailed` while zig sets up libc, so the module is linked
#   WITHOUT any C runtime:
#     - include\ holds minimal <string.h>/<stdlib.h>/<sys/param.h> stand-ins
#     - include\sodium\ stands in for the two libsodium headers the vendored
#       ed25519-donna glue includes
#     - vanity_crypto.c supplies SHA-512, the ChaCha20 DRBG and memset
#     - vanity_dllentry.c supplies _tls_index and _DllMainCRTStartup (Windows
#       only; empty translation unit elsewhere)
#     - memcpy/memset/memmove/memcmp come from zig's compiler_rt
#   Nothing here calls malloc/printf/exit, so no CRT is needed. The resulting
#   .so has an empty DT_NEEDED list - it loads with no dependencies at all.
#
# NOTE on -femit-bin: it MUST be passed with "=" (see $args below). Written as
# two arguments ("-femit-bin" "<path>") zig treats the path as an input object
# file and the link fails with
#   ld.lld: cannot open <path>: No such file or directory

param(
    [ValidateSet("windows", "linux", "linux-x86_64", "linux-aarch64",
                 "linux-armv7", "x86_64", "aarch64", "armv7", "linux-arm")]
    [string]$Target = "windows"
)

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$bin  = Join-Path $root "bin"

# ------------------------------------------------------------- target table
# $mcpu is $null for targets that do not need one (all of them except ARMv7).
$mcpu = $null
switch ($Target) {
    "windows"       { $trip = "x86_64-windows-gnu" ; $out = "vanity_core.dll"          ; $key = "windows"       }
    "linux"         { $trip = "x86_64-linux-gnu"   ; $out = "libvanity_core.so"        ; $key = "linux"         }
    "linux-x86_64"  { $trip = "x86_64-linux-gnu"   ; $out = "libvanity_core.so"        ; $key = "linux"         }
    "x86_64"        { $trip = "x86_64-linux-gnu"   ; $out = "libvanity_core.so"        ; $key = "linux"         }
    "linux-aarch64" { $trip = "aarch64-linux-gnu"  ; $out = "libvanity_core-aarch64.so"; $key = "linux-aarch64" }
    "aarch64"       { $trip = "aarch64-linux-gnu"  ; $out = "libvanity_core-aarch64.so"; $key = "linux-aarch64" }
    "linux-armv7"   { $trip = "arm-linux-gnueabihf"; $out = "libvanity_core-armv7.so"  ; $key = "linux-armv7"; $mcpu = "cortex_a8" }
    "armv7"         { $trip = "arm-linux-gnueabihf"; $out = "libvanity_core-armv7.so"  ; $key = "linux-armv7"; $mcpu = "cortex_a8" }
    "linux-arm"     { $trip = "arm-linux-gnueabihf"; $out = "libvanity_core-armv7.so"  ; $key = "linux-armv7"; $mcpu = "cortex_a8" }
}
$artifact = Join-Path $bin $out

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
Write-Host "target   : $Target ($trip)"

# ------------------------------------------------------------------- inputs
$sources = @(
    (Join-Path $root "vanity_bridge.c")
    (Join-Path $root "vanity_crypto.c")
    (Join-Path $root "vanity_dllentry.c")
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
    $root                                # vanity_crypto.h
)

New-Item -ItemType Directory -Force -Path $bin | Out-Null
# The Windows cache paths are left exactly as they were (.zig-cache /
# .zig-global-cache); every other target gets its own pair so a Linux build can
# never invalidate the shipped Windows one.
if ($key -eq "windows") {
    $cacheDir = Join-Path $root ".zig-cache"
    $globalCacheDir = Join-Path $root ".zig-global-cache"
} else {
    $cacheDir = Join-Path $root (".zig-cache-" + $key)
    $globalCacheDir = Join-Path $root (".zig-global-cache-" + $key)
}
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
New-Item -ItemType Directory -Force -Path $globalCacheDir | Out-Null

# -------------------------------------------------------------------- build
$zigArgs = @("build-lib") + $sources + @(
    "-dynamic",
    "-target", $trip,
    "-O", "ReleaseFast"
)
if ($mcpu) { $zigArgs += @("-mcpu", $mcpu) }
foreach ($inc in $includeDirs) { $zigArgs += @("-I", $inc) }
$zigArgs += @(
    "--cache-dir", $cacheDir,
    "--global-cache-dir", $globalCacheDir,
    "--name", "vanity_core",
    "-femit-bin=$artifact"          # "=" is required, see the header comment
)

Write-Host ""
Write-Host "$py -m ziglang $($zigArgs -join ' ')"
Write-Host ""

& $py -m ziglang @zigArgs
if ($LASTEXITCODE -ne 0) { throw "zig build-lib failed with exit code $LASTEXITCODE" }

# zig also drops a .lib import library and a .pdb next to the DLL; we only ship
# the DLL, so remove them to keep bin/ reproducible.
foreach ($extra in @("vanity_core.lib", "vanity_core.pdb")) {
    $p = Join-Path $bin $extra
    if (Test-Path $p) { Remove-Item $p -Force }
}
# ...and .o/.a leftovers for the shared-object targets.
foreach ($extra in @("libvanity_core.so.o", "libvanity_core.a",
                     "libvanity_core-aarch64.a", "libvanity_core-armv7.a")) {
    $p = Join-Path $bin $extra
    if (Test-Path $p) { Remove-Item $p -Force }
}

if (-not (Test-Path $artifact)) {
    throw "build reported success but $artifact does not exist"
}

$size = (Get-Item $artifact).Length
Write-Host ""
Write-Host ("built: {0}" -f $artifact)
Write-Host ("size : {0} bytes ({1:N1} KiB)" -f $size, ($size / 1KB))
