#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Постобработка Android-APK для wg-vanity.

Godot 3.6 при экспорте кладёт GDNative-библиотеки из res://android/<abi>/*.so
в assets/ APK. Android'у же для dlopen нужна библиотека в lib/<abi>/ (начиная
с Android 10 запускать код из каталога данных приложения запрещено, поэтому
вариант «распаковать .so из assets и загрузить» не работает).

Скрипт: копирует библиотеки в lib/<abi>/, выбрасывает десктопные копии,
выравнивает (zipalign) и подписывает debug-ключом (apksigner).

Запуск (после do_export_android.ps1):
    python v3/repack_apk.py [--apk path] [--sdk path] [--jdk path] [--keystore path]
"""
import argparse
import os
import shutil
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ABIS = ("arm64-v8a", "armeabi-v7a")


def run(args, env):
    r = subprocess.run(args, capture_output=True, text=True, env=env, shell=False)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", default=os.path.join(HERE, "export", "android", "WG_Vanity_v3.apk"))
    ap.add_argument("--sdk", default=r"D:\AI_PROJEKTZ\Android\sdk")
    ap.add_argument("--jdk", default=r"D:\AI_PROJEKTZ\Android\jdk17")
    ap.add_argument("--keystore", default=r"D:\AI_PROJEKTZ\Android\debug.keystore")
    ap.add_argument("--alias", default="androiddebugkey")
    ap.add_argument("--ks-pass", default="android")
    ap.add_argument("--work", default=None, help="каталог для промежуточных файлов")
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
            out.writestr(item, src.read(n))
        for abi in ABIS:
            if abi in libbytes:
                out.writestr("lib/%s/libvanity_gdnative.so" % abi, libbytes[abi])
                print("  -> lib/%s/libvanity_gdnative.so (%d байт)" % (abi, len(libbytes[abi])))
    src.close()
    if len(libbytes) != 2:
        print("ОШИБКА: не найдены обе ABI-библиотеки в assets/android/<abi>/")
        return 1

    env = dict(os.environ, JAVA_HOME=a.jdk)
    bt = os.path.join(a.sdk, "build-tools")
    if not os.path.isdir(bt):
        print("ОШИБКА: не найден", bt)
        return 1
    ver = sorted(os.listdir(bt))[-1]
    bt = os.path.join(bt, ver)

    rc, out = run([os.path.join(bt, "zipalign.exe"), "-f", "-p", "4", unsigned, aligned], env)
    if rc != 0:
        print("zipalign провалился:", out[:300])
        return 1
    rc, out = run([os.path.join(bt, "apksigner.bat"), "sign", "--ks", a.keystore,
                   "--ks-key-alias", a.alias, "--ks-pass", "pass:" + a.ks_pass,
                   "--key-pass", "pass:" + a.ks_pass, "--out", signed, aligned], env)
    if rc != 0:
        print("apksigner sign провалился:", out[:300])
        return 1
    rc, out = run([os.path.join(bt, "apksigner.bat"), "verify", "--print-certs", signed], env)
    if rc != 0:
        print("apksigner verify провалился:", out[:300])
        return 1
    print("подпись:", out.strip().splitlines()[0] if out.strip() else "ok")

    shutil.copy2(signed, apk)
    print("готово:", apk, os.path.getsize(apk), "байт")
    return 0


if __name__ == "__main__":
    sys.exit(main())
