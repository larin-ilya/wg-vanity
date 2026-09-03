# WG Vanity v2 — красивая GUI-версия

Ищет **vanity-ключи WireGuard** (публичные ключи с нужным префиксом) в красивом
Godot-интерфейсе. Процессорный поиск — быстрый Python/NaCl воркер, интерфейс —
Godot 3.6.3 (GLES2, работает на слабых видеокартах).

Скриншот интерфейса — в корневом [README](../README.md).

---

## 🚀 Быстрый старт из готового билда

Скачайте **WG_Vanity_v2.exe** из [Releases](../../releases) — это портативный
`.exe`, внутри уже вшит воркер. Ничего не устанавливает.

Введите **слово** (например `bitcoin` или `vpn`), выберите число воркеров,
нажмите **«Найти»** — и смотрите на живую статистику поиска. При нахождении
ключа он сохраняется (`.conf`, `_keys.txt`, `_qr.png`) в папку рядом с exe.

---

## ✨ Возможности

- Один процессорный воркер на ядро — поиск использует весь CPU.
- Живые метрики: проверено ключей, скорость (k/s), примерное время до успеха.
- Статистика по каждому воркеру отдельно + суммарно.
- Генерация QR-кода и конфига клиента для найденного ключа.
- Сохранение результата в файл (`--save`).
- Лёгкий тумблер фоновой музыки (`Uctumi_Equanimity`, трекерный .it → MP3 64кбит).
- Работает на **GLES2** (проверено на NVIDIA GeForce GTX 550 Ti).

---

## 🛠 Сборка из исходников

### 1. Воркер (`wg_worker.exe`)

Нужен Python 3.8+ с `pynacl` и `pyinstaller`:

```powershell
pip install pynacl pyinstaller
./build_worker.ps1        # соберёт gui/bundled/wg_worker.exe
```

### 2. Экспорт Godot (Windows)

- Установите **Godot 3.6.3** и export templates для Windows.
- Откройте `gui/project.godot` в Godot (нажмите «Redeploy/Export»).
- Либо из командной строки:

```powershell
./do_export.ps1           # соберёт WG_Vanity_v2.exe в v2/export/
```

Результат — портативный exe с вшитым воркером.

---

## 📁 Структура

```
v2/
├─ core/                    # Python: wg_worker.py (поиск), gen_tracker_music.py
├─ gui/
│  ├─ scripts/              # Godot-скрипты интерфейса (Main.gd и др.)
│  ├─ shaders/              # фоновые шейдеры
│  ├─ assets/               # иконки, шрифты, музыка
│  ├─ project.godot
│  ├─ main.tscn
│  └─ export_presets.cfg
├─ build_worker.ps1         # сборка wg_worker.exe (PyInstaller)
└─ do_export.ps1            # экспорт Godot в WG_Vanity_v2.exe
```

---

## 🔒 Лицензия

MIT. См. [LICENSE](../LICENSE).
