#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Постобработка Android-APK для wg-vanity.

Что делает:
 1) переносит GDNative-библиотеки из assets/android/<abi>/ в lib/<abi>/ APK
    (иначе Android не найдёт их при dlopen; на Android 10+ распаковка .so
    из assets не работает), десктопные копии выбрасывает;
 2) правит android:screenOrientation в бинарном AndroidManifest.xml
    (при экспорте без gradle Godot заливает pck в готовый шаблон APK, поэтому
    настройка проекта display/window/handheld/orientation в манифест не попадает);
 3) выравнивает (zipalign) и подписывает debug-ключом (apksigner).

Запуск (обычно вызывается из do_export_android.ps1):
    python v3/repack_apk.py [--apk path] [--sdk path] [--jdk path] [--keystore path]
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import zipfile

ABIS = ("arm64-v8a", "armeabi-v7a")

CHUNK_STRING_POOL = 0x0001
CHUNK_START_ELEMENT = 0x0102
TYPE_INT_DEC = 0x10
ORIENT = {"portrait": 1, "landscape": 0, "sensorPortrait": 7,
          "sensorLandscape": 6, "userPortrait": 12}


def pool_strings(buf: bytes) -> dict:
    if len(buf) < 8:
        return {}
    ctype, hsize, _csize = struct.unpack_from("<HHI", buf, 8)
    if ctype != CHUNK_STRING_POOL:
        return {}
    base = 8
    count, _sc, flags, strings_start, _ss = struct.unpack_from("<IIIII", buf, base + 8)
    utf8 = bool(flags & (1 << 8))
    out = {}
    for i in range(count):
        off = struct.unpack_from("<I", buf, base + hsize + 4 * i)[0]
        p = base + strings_start + off
        try:
            if utf8:
                n = buf[p]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | buf[p + 1]
                    start = p + 2
                else:
                    start = p + 1
                out[i] = buf[start:start + n].decode("utf-8", "ignore")
            else:
                n = struct.unpack_from("<H", buf, p)[0]
                out[i] = buf[p + 2:p + 2 + n * 2].decode("utf-16-le", "ignore")
        except Exception:
            pass
    return out


def patch_manifest(data: bytes, value: int) -> bytes:
    buf = bytearray(data)
    idx = [i for i, s in pool_strings(bytes(buf)).items() if s == "screenOrientation"]
    if not idx:
        raise SystemExit("screenOrientation нет в пуле строк манифеста")
    idx = idx[0]
    patched = 0
    off = 8
    while off + 8 <= len(buf):
        ctype, _hsize, csize = struct.unpack_from("<HHI", buf, off)
        if csize < 8 or off + csize > len(buf):
            break
        if ctype == CHUNK_START_ELEMENT and csize >= 36:
            attr_start = struct.unpack_from("<H", buf, off + 24)[0]
            attr_size = struct.unpack_from("<H", buf, off + 26)[0]
            attr_count = struct.unpack_from("<H", buf, off + 28)[0]
            aoff = off + 16 + attr_start
            for i in range(attr_count):
                a = aoff + i * (attr_size or 20)
                if a + 20 > len(buf):
                    break
                if struct.unpack_from("<I", buf, a + 4)[0] == idx and buf[a + 15] == TYPE_INT_DEC:
                    struct.pack_into("<I", buf, a + 16, value)
                    patched += 1
        off += csize
    if not patched:
        raise SystemExit("атрибут screenOrientation не найден")
    return bytes(buf)


def run(args, env):
    r = subprocess.run(args, capture_output=True, text=True, env=env, shell=False)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                 "export", "android", "WG_Vanity_v3.apk"))
    ap.add_argument("--sdk", default=os.environ.get("WG_VANITY_ANDROID_DIR", r"D:\AI_PROJEKTZ\Android") + r"\sdk")
    ap.add_argument("--jdk", default=os.environ.get("WG_VANITY_ANDROID_DIR", r"D:\AI_PROJEKTZ\Android") + r"\jdk17")
    ap.add_argument("--keystore", default=os.environ.get("WG_VANITY_ANDROID_DIR", r"D:\AI_PROJEKTZ\Android") + r"\debug.keystore")
    ap.add_argument("--alias", default="androiddebugkey")
    ap.add_argument("--ks-pass", default="android")
    ap.add_argument("--orientation", default="sensorPortrait", choices=list(ORIENT))
    ap.add_argument("--work", default=None)
    a = ap.parse_args()

    apk = os.path.abspath(a.apk)
    if not os.path.exists(apk):
        print("нет APK:", apk)
        return 1
    work = a.work or os.path.join(os.path.dirname(apk), "_repack")
    os.makedirs(work, exist_ok=True)
    unsigned = os.path.join(work, "unsigned.apk")
    aligned = os.path.join(work, "aligned.apk")
    signed = os.path.join(work, "signed.apk")
    for p in (unsigned, aligned, signed):
        if os.path.exists(p):
            os.remove(p)

    print("входной APK:", apk, os.path.getsize(apk), "байт")
    src = zipfile.ZipFile(apk)
    libbytes = {}
    manifest = None
    with zipfile.ZipFile(unsigned, "w", zipfile.ZIP_DEFLATED) as out:
        for item in src.infolist():
            n = item.filename
            parts = n.split("/")
            if n.startswith("assets/android/") and len(parts) > 2:
                abi = parts[2]
                if abi not in ABIS:
                    continue                      # десктопные копии не нужны
                if n.endswith("libvanity_gdnative.so"):
                    libbytes[abi] = src.read(n)
            data = src.read(n)
            if n == "AndroidManifest.xml":
                manifest = patch_manifest(data, ORIENT[a.orientation])
                data = manifest
            out.writestr(item, data)
        for abi in ABIS:
            if abi in libbytes:
                out.writestr("lib/%s/libvanity_gdnative.so" % abi, libbytes[abi])
                print("  -> lib/%s/libvanity_gdnative.so (%d байт)" % (abi, len(libbytes[abi])))
    src.close()
    if len(libbytes) != 2:
        print("ОШИБКА: не найдены обе ABI-библиотеки в assets/android/<abi>/")
        return 1
    print("  -> манифест: screenOrientation = %s (%d)" % (a.orientation, ORIENT[a.orientation]))

    env = dict(os.environ, JAVA_HOME=a.jdk)
    btdir = os.path.join(a.sdk, "build-tools")
    if not os.path.isdir(btdir):
        print("ОШИБКА: не найден", btdir)
        return 1
    bt = os.path.join(btdir, sorted(os.listdir(btdir))[-1])

    rc, out = run([os.path.join(bt, "zipalign.exe"), "-f", "-p", "4", unsigned, aligned], env)
    if rc != 0:
        print("zipalign провалился:", out[:300]); return 1
    rc, out = run([os.path.join(bt, "apksigner.bat"), "sign", "--ks", a.keystore,
                   "--ks-key-alias", a.alias, "--ks-pass", "pass:" + a.ks_pass,
                   "--key-pass", "pass:" + a.ks_pass, "--out", signed, aligned], env)
    if rc != 0:
        print("apksigner sign провалился:", out[:300]); return 1
    rc, out = run([os.path.join(bt, "apksigner.bat"), "verify", "--print-certs", signed], env)
    if rc != 0:
        print("apksigner verify провалился:", out[:300]); return 1
    print("подпись:", out.strip().splitlines()[0] if out.strip() else "ok")
    rc, out = run([os.path.join(bt, "aapt.exe"), "dump", "xmltree", signed, "AndroidManifest.xml"], env)
    line = [l for l in out.splitlines() if "screenOrientation" in l]
    print("проверка ориентации:", line[0].strip() if line else "(не найдено)")
    if not line or ("0x%x" % ORIENT[a.orientation]) not in line[0]:
        print("ориентация не применилась"); return 1

    shutil.copy2(signed, apk)
    print("готово:", apk, os.path.getsize(apk), "байт")
    return 0


if __name__ == "__main__":
    sys.exit(main())
