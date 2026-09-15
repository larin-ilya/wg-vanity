#!/bin/bash
# build_worker_linux.sh — сборка standalone-воркера `wg_worker` под Linux.
#
# Результат: v3/gui/bundled/wg_worker  (ELF-бинарник, ~10-15 МБ, без внешних
# зависимостей от python3/pip на целевой машине; нативный движок
# libvanity_core.so вшит внутрь бандла).
#
# Запускать ИЗ LINUX (в т.ч. из WSL), из любого каталога:
#     bash build_worker_linux.sh
#
# ---------------------------------------------------------------------------
# ЧТО НУЖНО НА МАШИНЕ СБОРКИ
# ---------------------------------------------------------------------------
#   * Linux x86_64 (или aarch64/armv7 — тогда см. «ARM» ниже);
#   * интерпретатор Python 3.8+ с pip. Системный python3 подойдёт, но его может
#     не быть и/или не быть прав на pip install --user (нет sudo). Поэтому
#     скрипт умеет брать ПОРТАТИВНЫЙ CPython:
#
#       astral-sh/python-build-standalone, ассет
#       cpython-3.11.*+*-x86_64-unknown-linux-gnu-install_only.tar.gz
#
#     Он распаковывается без root и без системных пакетов:
#
#       mkdir -p ~/pbs ~/dl && cd ~/dl
#       curl -fLO https://github.com/astral-sh/python-build-standalone/releases/download/\
#     <TAG>/cpython-3.11.16%2B<TAG>-x86_64-unknown-linux-gnu-install_only.tar.gz
#       tar -xzf cpython-3.11.*.tar.gz -C ~/pbs
#       ~/pbs/python/bin/python3 -m pip install pyinstaller pynacl
#
#     (~/pbs/python/bin/python3 — то, что скрипт ищет сам, если в PATH нет
#      python3 или в нём нет PyInstaller. Можно указать явно: WG_PY=<путь>.)
#
#   * PyInstaller:   python3 -m pip install pyinstaller
#   * (необязательно, но нужно для QR в файлах результата) qrcode + Pillow:
#                    python3 -m pip install qrcode pillow
#     GUI получает QR как base64 в сообщении found, а в .txt/.conf-набор
#     дополнительно кладётся файл <prefix>_qr.png. Без qrcode/Pillow воркер
#     работает, но PNG не создаётся (в wg_worker.py этот блок в try/except) —
#     поэтому здесь это ПРЕДУПРЕЖДЕНИЕ, а не ошибка. На Windows-сборке qrcode
#     и Pillow берутся из системного python, поэтому для полного паритета их
#     лучше поставить и тут.
#   * (необязательно) PyNaCl:           python3 -m pip install pynacl
#     Нужен только как резерв (WG_NATIVE_ENGINE=python). С нативным движком
#     воркер работает и без него: `import nacl` в wg_worker.py обёрнут в
#     try/except, а тесты (test_vanity_native.py) сравнивают C-движок с PyNaCl,
#     поэтому для сборки релиза PyNaCl всё же желателен.
#     ВНИМАНИЕ: PyNaCl — cffi-расширение, и PyInstaller 6.x НЕ подтягивает
#     `_cffi_backend` сам (нет штатного hook-cffi). Без него `import nacl` в
#     бандле падает, и воркер пишет «PyNaCl недоступен». Поэтому скрипт ниже
#     явно добавляет --hidden-import _cffi_backend, когда cffi есть.
#
# ---------------------------------------------------------------------------
# НАТИВНЫЙ ДВИЖОК
# ---------------------------------------------------------------------------
# Берётся уже собранный v3/core/vanity_native/bin/libvanity_core.so — он
# коммитится в репозиторий и кросс-компилируется С WINDOWS:
#
#     powershell -ExecutionPolicy Bypass -File v3\core\vanity_native\build.ps1 -Target linux
#     (варианты: -Target linux-aarch64 | -Target linux-armv7)
#
# Отдельного компилятора на Linux не требуется — .so просто кладётся в бандл.
# Если файла нет, воркер всё равно соберётся (будет медленный python-путь).
#
# ARM: движок для ARMv7 отличается только -Target у build.ps1 (имя
#     libvanity_core-armv7.so), а PyInstaller нужно запускать НА самой плате
#     (кросс-сборка PyInstaller невозможна) — обёртка vanity_native.py сама
#     выберет `libvanity_core-armv7.so` по platform.machine().
set -euo pipefail

# --- где мы ---------------------------------------------------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -f "$HERE/core/wg_worker.py" ]; then
    HERE="$(cd "$HERE/.." && pwd)"
fi
if [ ! -f "$HERE/core/wg_worker.py" ]; then
    echo "не найден core/wg_worker.py — положите скрипт в каталог v3/" >&2
    exit 1
fi

SO="$HERE/core/vanity_native/bin/libvanity_core.so"
OUTDIR="$HERE/gui/bundled"
WORKDIR="${WG_WORKDIR:-${TMPDIR:-/tmp}/wgv-worker-build}"

# --- какой python ---------------------------------------------------------
pick_py() {
    if [ -n "${WG_PY:-}" ]; then echo "$WG_PY"; return; fi
    for c in python3 python "$HOME/pbs/python/bin/python3"; do
        if command -v "$c" >/dev/null 2>&1; then
            if "$c" -c 'import PyInstaller' >/dev/null 2>&1; then echo "$c"; return; fi
        fi
    done
    # ни у кого нет PyInstaller — вернём хоть что-то вменяемое для диагностики
    if command -v python3 >/dev/null 2>&1; then echo python3; return; fi
    if [ -x "$HOME/pbs/python/bin/python3" ]; then echo "$HOME/pbs/python/bin/python3"; return; fi
    echo ""
}
PY="$(pick_py)"
if [ -z "$PY" ]; then
    echo "не найден python3 (см. комментарий в начале файла про портативный CPython)" >&2
    exit 1
fi
echo "python   : $PY ($("$PY" -c 'import sys;print(sys.version.split()[0])'))"
if ! "$PY" -c 'import PyInstaller' >/dev/null 2>&1; then
    echo "в этом python нет PyInstaller: $PY -m pip install pyinstaller" >&2
    exit 1
fi
"$PY" -c 'import PyInstaller, sys; print("pyinstaller:", PyInstaller.__version__)'
if "$PY" -c 'import nacl' >/dev/null 2>&1; then
    echo "pynacl   : есть"
else
    echo "pynacl   : НЕТ (не обязательно: с нативным движком не используется)"
fi
if "$PY" -c 'import qrcode, PIL' >/dev/null 2>&1; then
    echo "qrcode   : есть (+ Pillow)"
else
    echo "qrcode   : НЕТ — в результатах не будет <prefix>_qr.png" >&2
    echo "           поставьте:  $PY -m pip install qrcode pillow" >&2
fi

# --- нативный движок ------------------------------------------------------
if [ -f "$SO" ]; then
    echo "engine   : $SO ($(stat -c %s "$SO") bytes)"
    ADD_DATA=(--add-data "$SO:.")
else
    echo "ПРЕДУПРЕЖДЕНИЕ: нет $SO" >&2
    echo "  соберите на машине с ziglang:  powershell -File v3/core/vanity_native/build.ps1 -Target linux" >&2
    echo "  воркер соберётся, но поиск пойдёт медленным python-путём" >&2
    ADD_DATA=()
fi

# --- сборка ---------------------------------------------------------------
# Собираем в чистом каталоге вне репозитория: PyInstaller пишет build/ и
# dist/, а на drvfs (/mnt/c) это ещё и заметно медленнее.
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
cp "$HERE/core/wg_worker.py"    "$WORKDIR/"
cp "$HERE/core/vanity_native.py" "$WORKDIR/"
if [ -f "$SO" ]; then
    mkdir -p "$WORKDIR/vanity_native/bin"
    cp "$SO" "$WORKDIR/vanity_native/bin/"
fi

echo "workdir  : $WORKDIR"
cd "$WORKDIR"

ARGS=(--noconfirm --onefile --name wg_worker --distpath "$WORKDIR/dist"
      --workpath "$WORKDIR/build" --specpath "$WORKDIR")
# --windowed на Linux для ELF ничего не меняет (флаг только для PE/приложений
# macOS), но оставляем его для единообразия с Windows-сборкой.
ARGS+=(--windowed)
# Иконку здесь НЕ вшиваем: у ELF нет PE-ресурсов, и PyInstaller на Linux --icon
# игнорирует (иконка окна у GUI своя, из project.godot). На Windows-сборке
# вшивание делает build_worker.ps1.
# PyInstaller 6.x сам находит `import nacl` в wg_worker.py (hook-nacl.py есть в
# pyinstaller-hooks-contrib), но НЕ находит cffi-бэкенд, который PyNaCl тянет
# уже в рантайме: без этой строки `import nacl` внутри бандла падает, и воркер
# печатает «PyNaCl недоступен» (нативный движок при этом работает).
if "$PY" -c 'import _cffi_backend' >/dev/null 2>&1; then
    ARGS+=(--hidden-import _cffi_backend)
fi
ARGS+=("${ADD_DATA[@]}")
ARGS+=(wg_worker.py)

echo "--- pyinstaller ${ARGS[*]}"
"$PY" -m PyInstaller "${ARGS[@]}"

if [ ! -f "$WORKDIR/dist/wg_worker" ]; then
    echo "PyInstaller не создал dist/wg_worker" >&2
    exit 1
fi

mkdir -p "$OUTDIR"
cp "$WORKDIR/dist/wg_worker" "$OUTDIR/wg_worker"
chmod +x "$OUTDIR/wg_worker"
# страховка для ручных запусков и для --onedir: .so рядом с бинарником
if [ -f "$SO" ]; then cp "$SO" "$OUTDIR/libvanity_core.so"; fi

echo
echo "built: $OUTDIR/wg_worker"
echo "size : $(stat -c %s "$OUTDIR/wg_worker") bytes"
echo "sha256: $(sha256sum "$OUTDIR/wg_worker" | cut -d' ' -f1)"
