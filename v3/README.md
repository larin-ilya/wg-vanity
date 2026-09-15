# WG Vanity v3 — GUI: WireGuard + красивые .onion v3-адреса

Ищет **vanity-ключи WireGuard** И **красивые Tor .onion v3-адреса** в одном
интерфейсе. Оба вида поиска идут через нативный batch-движок (mkp224o
`ed25519-donna`) на всех ядрах CPU — сотни миллионов ключей в секунду;
чистый Python/NaCl остаётся как запасной путь. Интерфейс — Godot 3.6.3
(GLES2, работает на слабых видеокартах).

Скриншот интерфейса — в корневом [README](../README.md).

---

## 🚀 Быстрый старт из готового билда

Скачайте **WG_Vanity_v3.exe** из [Releases](../../releases) — это портативный
`.exe`, внутри уже вшит воркер. Ничего не устанавливает.

Выберите тип поиска вверху левой колонки:

- **WireGuard-ключ** — задайте слово/префикс (например `bitcoin`, `vpn`).
  Найденный ключ сохраняется (`.conf`, `_keys.txt`, `_qr.png`).
- **.onion адрес** — задайте префикс из `a–z` и `2–7` (например `cook`, `tor`,
  `coin`). При нахождении в папку рядом с exe кладётся каталог
  `<адрес>.onion/` с `hostname`, `hs_ed25519_public_key`,
  `hs_ed25519_secret_key` — Tor подхватит их как `HiddenServiceDir`.

Нажмите **«Найти»** и следите за живой статистикой поиска.

---

## ✨ Возможности

- Два режима поиска: WireGuard (Curve25519/X25519) и **.onion v3** (адрес из
  ed25519-ключа).
- Нативный движок для обоих режимов: batch-цикл из mkp224o (одна инверсия на
  2048 точек) — 3.7 млн ключей/с на ядро, ~32 млн/с на 12 логических ядрах.
- Один процессорный воркер на ядро — поиск использует весь CPU.
- Живые метрики: проверено ключей/адресов, скорость, примерное время до успеха.
- QR-код и конфиг клиента для WireGuard-ключа.
- Сохранение onion-ключей в готовом для Tor формате (как mkp224o).
- Lofi-звук: фоновый трек (`Uctumi_Equanimity`) сжат до 32 кбит/с (вариант C).
- Визуальные эффекты: цифровой шум/сканлайны (шейдер `noise.gdshader`) +
  глитч-вспышка в момент находки.
- Работает на **GLES2** (проверено на NVIDIA GeForce GTX 550 Ti).

---

## 🛠 Сборка из исходников

### 1. Воркер (`wg_worker.exe`)

Нужен Python 3.8+ с `pynacl` и `pyinstaller`:

```powershell
pip install pynacl pyinstaller
./build_worker.ps1        # соберёт gui/bundled/wg_worker.exe
```

### 2. Нативный движок поиска (`core/vanity_native/bin/vanity_core.dll`)

И поиск .onion v3, и поиск WireGuard-ключей идут через нативный модуль,
собранный из [mkp224o](https://github.com/cathugger/mkp224o) (batch-режим
`ed25519-donna`: одна обратная инверсия на 2048 точек). Для WireGuard внутри
считается эдвардсова точка и переводится в Монтгомери-координату
`u = (z + y) / (z - y)` — это ровно то, что кладёт в публичный ключ X25519.
Готовая DLL **закоммичена** — пересобирать её нужно только если правите C-код
или вендоринг. Нужен только `zig`, ставить ничего не надо:

```powershell
python -m pip install ziglang          # если zig ещё нет
./core/vanity_native/build.ps1         # соберёт core/vanity_native/bin/vanity_core.dll
```

**Движок кросс-платформенный.** Тот же C-код собирается тем же скриптом и в
разделяемый объект для Linux (и ARM) — компилятор на Linux для этого не нужен,
всё делает `zig` с Windows-машины (см. раздел «🐧 Linux» ниже):

```powershell
./core/vanity_native/build.ps1 -Target linux           # bin/libvanity_core.so
./core/vanity_native/build.ps1 -Target linux-aarch64   # bin/libvanity_core-aarch64.so
./core/vanity_native/build.ps1 -Target linux-armv7     # bin/libvanity_core-armv7.so
```

`-femit-bin` внутри передаётся обязательно через `=`; если записать его через
пробел, zig отдаёт путь линкеру как входной объектный файл и падает с
`ld.lld: cannot open ...: No such file or directory`.

Проверить движок:

```powershell
cd core
python test_vanity_native.py           # 103 проверки, exit code 0 = всё хорошо
python ../bench/bench_native.py --kind wg    --engine native --seconds 10 --cores 12
python ../bench/bench_native.py --kind onion --engine native --seconds 10 --cores 12
```

Если библиотеки нет, воркер молча работает на прежнем Python-пути (PyNaCl).
Принудительно выбрать движок: переменная окружения `WG_NATIVE_ENGINE`
(`auto` по умолчанию, `native`, `python`) — общая для обоих видов поиска.
Старое имя `WG_ONION_ENGINE` тоже понимается (только для .onion) и имеет
меньший приоритет.

### 3. Иконка (многоразмерный .ico)

```powershell
python core/make_icon.py  # соберёт gui/assets/icon.ico из icon.png (16–256 px)
```

### 4. Экспорт Godot (Windows)

- Установите **Godot 3.6.3** + export templates для Windows, положите
  `rcedit-x64.exe` рядом (в каталог v3/).
- Godot 3.6 НЕ вшивает иконку в exe сам — это делает `rcedit` в скрипте.

```powershell
./do_export.ps1           # соберёт WG_Vanity_v3.exe в v3/export/
```

Результат — портативный exe с вшитым воркером и своей иконкой.

---

## 🐧 Linux

Поддерживаются **x86_64**, **aarch64** и **armv7** (Raspberry Pi 2+). Собирается
всё с Windows-машины: `zig` кросс-компилирует движок, Godot — экспортирует GUI,
а воркер замораживает `PyInstaller` внутри Linux (или WSL). На целевой машине
**ничего ставить не нужно** — ни Python, ни pip, ни компилятор.

### Что нужно на целевой машине

- 64-битный Linux с OpenGL 2.0 (GLES2) — GUI статически линкует всё, что ему
  нужно, кроме системного `libGL`/`libX11`;
- два файла рядом: `WG_Vanity_v3.x86_64` и `wg_worker`;
- больше ничего: нативный движок (`libvanity_core.so`) вшит внутрь `wg_worker`.

### 1. Движок (`core/vanity_native/bin/libvanity_core*.so`)

Собирается **на Windows** тем же `build.ps1` (см. §2 выше):

```powershell
./core/vanity_native/build.ps1 -Target linux           # bin/libvanity_core.so         (x86_64)
./core/vanity_native/build.ps1 -Target linux-aarch64   # bin/libvanity_core-aarch64.so (aarch64)
./core/vanity_native/build.ps1 -Target linux-armv7     # bin/libvanity_core-armv7.so   (armv7)
```

Готовые `.so` **закоммичены** — как и `vanity_core.dll`, чтобы машина сборки
воркера не нуждалась в компиляторе. Все три файла — честные ELF без единой
`DT_NEEDED`-зависимости (`zig` линкует без libc) и с теми же 7 экспортами
`vanity_*`, что и DLL; `vanity_native.py` выбирает имя по `platform.machine()`.
ARMv7 собирается с `-mcpu=cortex_a8` (ARMv7-A + VFPv3) — работает на любом
32-битном raspberry-совместимом ядре; в zig 0.13 нет ни `armv7` как
архитектуры, ни `armv7a` как `-mcpu`, а дефолтный `generic` ARM генерирует
код, который CPU не принимает.

### 2. Воркер (`gui/bundled/wg_worker`)

Запускать **из Linux** (в том числе из WSL). Нужен Python 3.8+ с PyInstaller;
если системного Python нет или нет прав на `pip install` (нет `sudo`) —
берётся портативный CPython от
[astral-sh/python-build-standalone](https://github.com/astral-sh/python-build-standalone):

```bash
mkdir -p ~/pbs ~/dl && cd ~/dl
curl -fLO https://github.com/astral-sh/python-build-standalone/releases/download/\
<TAG>/cpython-3.11.16%2B<TAG>-x86_64-unknown-linux-gnu-install_only.tar.gz
tar -xzf cpython-3.11.*-x86_64-unknown-linux-gnu-install_only.tar.gz -C ~/pbs
~/pbs/python/bin/python3 -m pip install pyinstaller pynacl qrcode pillow

bash v3/build_worker_linux.sh          # -> v3/gui/bundled/wg_worker (+ libvanity_core.so рядом)
```

Скрипт сам найдёт `python3` в `PATH`, либо `~/pbs/python/bin/python3`
(можно задать явно `WG_PY=<путь>`). `libvanity_core.so` вшивается в бандл
(`--add-data`), плюс копируется рядом с бинарником как страховка.
Зависимости: `pynacl` — опционально (запасной python-путь; без него воркер
печатает «PyNaCl недоступен», нативный движок работает), `qrcode`+`Pillow` —
для `<prefix>_qr.png` (без них QR не сохраняется). PyInstaller 6.x не
подтягивает `_cffi_backend` сам, поэтому скрипт добавляет
`--hidden-import _cffi_backend` — без этого `import nacl` внутри бандла падает.

### 3. Экспорт GUI (`export/linux/WG_Vanity_v3.x86_64`)

Нужны Godot 3.6.3 + export templates `linux_x11_64_release`:

```powershell
./do_export_linux.ps1      # экспорт пресета "Linux/X11" + копия wg_worker рядом
```

`rcedit` здесь **не** вызывается (у ELF нет PE-ресурсов), иконка окна берётся
из pck. Рядом с бинарником скрипт кладёт `wg_worker` — GUI ищет его sidecar'ом
рядом с собой (а если воркер оказался внутри pck как `res://bundled/wg_worker`,
извлекает его в `user://` и делает `chmod +x`). Запуск:

```bash
cd v3/export/linux && ./WG_Vanity_v3.x86_64
```

Переменная `WG_VANITY_WORKER` задаёт путь к воркеру вручную.

---

## 📁 Структура

```
v3/
├─ core/                    # Python: wg_worker.py (поиск wg+onion),
│  │                        # vanity_native.py (обёртка над нативным движком),
│  │                        # test_vanity_native.py, gen_tracker_music.py, make_icon.py
│  └─ vanity_native/        # нативный движок (onion v3 + wg): C-код + вендоренный mkp224o
│     ├─ vanity_bridge.c    #   batch-цикл поиска обоих видов и публичный C ABI
│     ├─ vanity_crypto.c    #   SHA-512 + ChaCha20-DRBG (без libc)
│     ├─ vanity_dllentry.c  #   PE entry point (только под _WIN32)
│     ├─ vendor/            #   subset mkp224o (CC0), см. vendor/UPSTREAM.txt
│     ├─ build.ps1          #   сборка через zig, -Target windows|linux|linux-aarch64|linux-armv7
│     └─ bin/               #   vanity_core.dll + libvanity_core*.so (закоммичены)
├─ bench/                   # замеры скорости: bench_native.py + RESULTS.md
├─ gui/
│  ├─ scripts/              # Godot-скрипты интерфейса (Main.gd и др.)
│  ├─ shaders/              # bg/ring/noise (цифровой шум)
│  ├─ assets/               # иконки, шрифты, музыка (lofi)
│  ├─ project.godot
│  ├─ main.tscn
│  └─ export_presets.cfg    # preset.0 = Windows Desktop, preset.1 = Linux/X11
├─ build_worker.ps1         # сборка wg_worker.exe (PyInstaller, Windows)
├─ build_worker_linux.sh    # сборка wg_worker (PyInstaller, Linux/WSL)
├─ do_export.ps1            # экспорт Godot + вшивка иконки (Windows)
└─ do_export_linux.ps1      # экспорт Godot (Linux/X11), без rcedit
```

---

## 🔒 Лицензия

MIT. См. [LICENSE](../LICENSE).
