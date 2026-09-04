# WG Vanity v3 — GUI: WireGuard + красивые .onion v3-адреса

Ищет **vanity-ключи WireGuard** И **красивые Tor .onion v3-адреса** в одном
интерфейсе. Поиск — быстрый Python/NaCl воркер на всех ядрах CPU, интерфейс —
Godot 3.6.3 (GLES2, работает на слабых видеокартах).

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

- Два режима поиска: WireGuard (ed25519) и **.onion v3** (адрес из ed25519-ключа).
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

### 2. Иконка (многоразмерный .ico)

```powershell
python core/make_icon.py  # соберёт gui/assets/icon.ico из icon.png (16–256 px)
```

### 3. Экспорт Godot (Windows)

- Установите **Godot 3.6.3** + export templates для Windows, положите
  `rcedit-x64.exe` рядом (в каталог v3/).
- Godot 3.6 НЕ вшивает иконку в exe сам — это делает `rcedit` в скрипте.

```powershell
./do_export.ps1           # соберёт WG_Vanity_v3.exe в v3/export/
```

Результат — портативный exe с вшитым воркером и своей иконкой.

---

## 📁 Структура

```
v3/
├─ core/                    # Python: wg_worker.py (поиск wg+onion),
│                           # gen_tracker_music.py, make_icon.py
├─ gui/
│  ├─ scripts/              # Godot-скрипты интерфейса (Main.gd и др.)
│  ├─ shaders/              # bg/ring/noise (цифровой шум)
│  ├─ assets/               # иконки, шрифты, музыка (lofi)
│  ├─ project.godot
│  ├─ main.tscn
│  └─ export_presets.cfg
├─ build_worker.ps1         # сборка wg_worker.exe (PyInstaller)
└─ do_export.ps1            # экспорт Godot + вшивка иконки
```

---

## 🔒 Лицензия

MIT. См. [LICENSE](../LICENSE).
