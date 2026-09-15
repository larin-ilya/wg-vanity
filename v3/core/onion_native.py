# -*- coding: utf-8 -*-
"""
ctypes-обёртка над нативным движком поиска .onion v3 (onion_native/bin/wg_onion.dll).

DLL собирается из вендоренного кода mkp224o (batch-режим ed25519-donna), см.
onion_native/build.ps1 и onion_native/vendor/UPSTREAM.txt.  WireGuard-часть
поиска сюда не относится.

Особенности:
  * DLL линкуется БЕЗ libc, поэтому она не выделяет память и не пишет файлы —
    найденный ключ возвращается в аргументах вызова;
  * энтропия попадает внутрь ровно один раз: os.urandom(48) через
    wg_onion_init(), дальше работает внутренний ChaCha20-DRBG;
  * модуль НЕ потокобезопасен (у DLL одно глобальное состояние). Параллелизм в
    проекте — через multiprocessing, по одному движку на процесс; на всякий
    случай вызовы сериализованы threading.Lock'ом.

Если DLL недоступна (не собрана / другая платформа), is_available() вернёт
False, а configure()/search() — понятную ошибку; падения не будет.
"""
import ctypes
import os
import sys
import threading

DLL_NAME = "wg_onion.dll"

# Алфавит onion v3 (RFC 4648 base32, нижний регистр).
ONION_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
ONION_ALPHABET_SET = frozenset(ONION_ALPHABET)

# Нативный движок принимает префиксы 1..12 символов. Более длинные дают
# астрономически малую вероятность попадания (32**13 ~ 2**65), поэтому
# воркер для них откатывается на чистый Python-путь.
MAX_PREFIX_LEN = 12
MIN_PREFIX_LEN = 1
MAX_PREFIXES = 4096
ONION_ADDR_LEN = 56

# Коды возврата wg_onion_search().
SEARCH_FOUND = 1
SEARCH_BUDGET_EXHAUSTED = 0


class OnionNativeError(RuntimeError):
    """DLL недоступна или отказала."""


class OnionNativeUnavailable(OnionNativeError):
    """DLL не найдена / не загрузилась — нужен fallback на Python-движок."""


class OnionNativeBadPrefix(OnionNativeError):
    """Префиксы не подходят для нативного движка — нужен fallback."""


# --------------------------------------------------------------------------
# Поиск DLL
# --------------------------------------------------------------------------
def _candidate_paths():
    here = os.path.dirname(os.path.abspath(__file__))
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    meipass = getattr(sys, "_MEIPASS", None)
    names = [
        # 1) рядом с этим модулем: <core>/onion_native/bin/wg_onion.dll
        os.path.join(here, "onion_native", "bin", DLL_NAME),
        os.path.join(here, "onion_native", DLL_NAME),
        # 2) рядом с исполняемым файлом (--onedir, ручная раскладка)
        os.path.join(exe_dir, DLL_NAME),
        os.path.join(exe_dir, "onion_native", "bin", DLL_NAME),
    ]
    # 3) внутри PyInstaller-бандла (--onefile распаковывает в _MEIPASS)
    if meipass:
        names.insert(0, os.path.join(meipass, DLL_NAME))
        names.insert(1, os.path.join(meipass, "onion_native", "bin", DLL_NAME))
    out = []
    for p in names:
        p = os.path.normpath(p)
        if p not in out:
            out.append(p)
    return out


def find_dll():
    """Возвращает путь к wg_onion.dll или None."""
    for p in _candidate_paths():
        try:
            if os.path.isfile(p):
                return p
        except (OSError, ValueError):
            continue
    return None


# --------------------------------------------------------------------------
# Движок
# --------------------------------------------------------------------------
class OnionNativeEngine:
    """Один экземпляр на процесс. Не потокобезопасен (см. модульный docstring)."""

    def __init__(self):
        self._dll = None
        self._load_error = None
        self._lock = threading.Lock()
        self._prefixes = None
        self._inited = False

    # -- загрузка ---------------------------------------------------------
    def _ensure_loaded(self):
        if self._dll is not None:
            return
        if self._load_error is not None:
            raise OnionNativeUnavailable(self._load_error)
        path = find_dll()
        if path is None:
            self._load_error = (
                "wg_onion.dll не найдена (искали: %s); "
                "соберите её: powershell -File v3/core/onion_native/build.ps1"
                % "; ".join(_candidate_paths()))
            raise OnionNativeUnavailable(self._load_error)
        try:
            dll = ctypes.CDLL(path)
        except OSError as e:
            self._load_error = "не удалось загрузить %s: %s" % (path, e)
            raise OnionNativeUnavailable(self._load_error)

        try:
            dll.wg_onion_init.argtypes = [ctypes.c_char_p, ctypes.c_uint]
            dll.wg_onion_init.restype = ctypes.c_int

            dll.wg_onion_set_prefixes.argtypes = [
                ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
            dll.wg_onion_set_prefixes.restype = ctypes.c_int

            dll.wg_onion_search.argtypes = [
                ctypes.c_ulonglong,
                ctypes.POINTER(ctypes.c_ulonglong),
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_char_p,
            ]
            dll.wg_onion_search.restype = ctypes.c_int

            dll.wg_onion_addr_from_pub.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p]
            dll.wg_onion_addr_from_pub.restype = ctypes.c_int

            dll.wg_onion_filter_match.argtypes = [
                ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
            dll.wg_onion_filter_match.restype = ctypes.c_int

            dll.wg_onion_engine_info.argtypes = [
                ctypes.c_char_p, ctypes.c_uint]
            dll.wg_onion_engine_info.restype = ctypes.c_int
        except AttributeError as e:
            self._load_error = "%s: нет ожидаемых экспортов (%s)" % (path, e)
            raise OnionNativeUnavailable(self._load_error)

        self._dll = dll
        self._path = path

    @property
    def path(self):
        self._ensure_loaded()
        return self._path

    def engine_info(self):
        self._ensure_loaded()
        buf = ctypes.create_string_buffer(128)
        self._dll.wg_onion_engine_info(buf, len(buf))
        return buf.value.decode("ascii", "replace")

    # -- проверка префиксов ----------------------------------------------
    @staticmethod
    def normalize_prefixes(prefixes):
        """bytes/str -> список str в нижнем регистре.

        Бросает OnionNativeBadPrefix, если набор непригоден для нативного
        движка (пустой, слишком длинный, посторонние символы)."""
        if not prefixes:
            raise OnionNativeBadPrefix("пустой список префиксов")
        out = []
        seen = set()
        for p in prefixes:
            if isinstance(p, (bytes, bytearray)):
                try:
                    p = p.decode("ascii")
                except UnicodeDecodeError:
                    raise OnionNativeBadPrefix("префикс не ASCII: %r" % (p,))
            p = str(p)
            if len(p) < MIN_PREFIX_LEN:
                raise OnionNativeBadPrefix("пустой префикс")
            if len(p) > MAX_PREFIX_LEN:
                raise OnionNativeBadPrefix(
                    "префикс %r длиннее %d символов" % (p, MAX_PREFIX_LEN))
            bad = [c for c in p if c not in ONION_ALPHABET_SET]
            if bad:
                raise OnionNativeBadPrefix(
                    "недопустимые символы в префиксе %r: %s "
                    "(можно только a-z и 2-7)" % (p, " ".join(bad)))
            if p not in seen:
                seen.add(p)
                out.append(p)
        if len(out) > MAX_PREFIXES:
            raise OnionNativeBadPrefix(
                "слишком много префиксов: %d (максимум %d)"
                % (len(out), MAX_PREFIXES))
        return out

    def configure(self, prefixes, seed=None):
        """Инициализирует DRBG и ставит набор префиксов.

        Идемпотентна: повторный вызов с тем же набором ничего не делает.
        seed — 32..64 байта; по умолчанию os.urandom(48)."""
        self._ensure_loaded()
        plist = self.normalize_prefixes(prefixes)
        if self._inited and plist == self._prefixes:
            return
        seed = os.urandom(48) if seed is None else bytes(seed)
        if not 32 <= len(seed) <= 64:
            raise OnionNativeError("seed должен быть 32..64 байта, не %d"
                                   % len(seed))
        with self._lock:
            rc = self._dll.wg_onion_init(seed, len(seed))
            if rc != 0:
                raise OnionNativeError("wg_onion_init вернул %d" % rc)
            self._inited = True
            arr = (ctypes.c_char_p * len(plist))(
                *[p.encode("ascii") for p in plist])
            rc = self._dll.wg_onion_set_prefixes(arr, len(plist))
            if rc != 0:
                self._inited = False
                self._prefixes = None
                raise OnionNativeBadPrefix(
                    "wg_onion_set_prefixes вернул %d для %r" % (rc, plist))
            self._prefixes = plist

    # -- собственно поиск ------------------------------------------------
    def search(self, max_keys):
        """Ищет не более max_keys ключей.

        Возвращает (code, keys_checked, found|None):
          code == 1 и found — нашли (см. ключи ниже),
          code == 0 и found is None — бюджет исчерпан.
        found = {"onion": str, "pub": bytes[32], "secret": bytes[64],
                 "seed": bytes[32]}.

        secret — РАСШИРЕННЫЙ ed25519-секрет (sha512(seed) с клампом плюс
        счётчик), тот самый формат, который Tor ждёт в hs_ed25519_secret_key.
        seed — seed, с которого стартовал батч (для человекочитаемого .txt).
        """
        self._ensure_loaded()
        if not self._inited:
            raise OnionNativeError("configure() не вызывался")
        if max_keys <= 0:
            return SEARCH_BUDGET_EXHAUSTED, 0, None

        checked = ctypes.c_ulonglong(0)
        secret = ctypes.create_string_buffer(64)
        pub = ctypes.create_string_buffer(32)
        seed = ctypes.create_string_buffer(32)
        onion = ctypes.create_string_buffer(ONION_ADDR_LEN + 1)

        with self._lock:
            rc = self._dll.wg_onion_search(
                ctypes.c_ulonglong(int(max_keys)), ctypes.byref(checked),
                secret, pub, seed, onion)

        if rc < 0:
            raise OnionNativeError("wg_onion_search вернул %d" % rc)
        if rc == 0:
            return SEARCH_BUDGET_EXHAUSTED, checked.value, None
        return SEARCH_FOUND, checked.value, {
            "onion": onion.value.decode("ascii"),
            "pub": pub.raw,
            "secret": secret.raw,
            "seed": seed.raw,
        }

    # -- вспомогательное (для тестов/сверки) -----------------------------
    def addr_from_pub(self, pub):
        """56-символьный onion-адрес для 32-байтного pubkey."""
        self._ensure_loaded()
        if len(pub) != 32:
            raise OnionNativeError("pubkey должен быть 32 байта")
        out = ctypes.create_string_buffer(ONION_ADDR_LEN + 1)
        rc = self._dll.wg_onion_addr_from_pub(bytes(pub), out)
        if rc != 0:
            raise OnionNativeError("wg_onion_addr_from_pub вернул %d" % rc)
        return out.value.decode("ascii")

    def filter_match(self, pub):
        """Проверяет битовый фильтр по УЖЕ установленным префиксам.

        Возвращает индекс совпавшего префикса или -1. Используется в тестах
        для сверки нативного фильтра с addr.startswith(prefix) на Python."""
        self._ensure_loaded()
        if len(pub) != 32:
            raise OnionNativeError("pubkey должен быть 32 байта")
        idx = ctypes.c_int(-1)
        r = self._dll.wg_onion_filter_match(bytes(pub), ctypes.byref(idx))
        if r < 0:
            raise OnionNativeError("wg_onion_filter_match вернул %d" % r)
        if r == 0:
            return -1
        return idx.value


# --------------------------------------------------------------------------
# Процессный синглтон + удобные функции модуля
# --------------------------------------------------------------------------
_engine = None
_engine_lock = threading.Lock()


def get_engine():
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = OnionNativeEngine()
        return _engine


def is_available():
    """True, если DLL найдена и загружается."""
    try:
        get_engine()._ensure_loaded()
        return True
    except OnionNativeError:
        return False
    except Exception:
        return False


def unavailable_reason():
    """Строка с причиной недоступности или None."""
    try:
        get_engine()._ensure_loaded()
        return None
    except OnionNativeError as e:
        return str(e)
    except Exception as e:  # pragma: no cover
        return str(e)


def engine_mode():
    """Разбирает WG_ONION_ENGINE=python|native|auto (по умолчанию auto).

    Возвращает нормализованный выбор БЕЗ проверки доступности:
    "python" | "native" | "auto".  Решение о fallback принимает вызывающая
    сторона (wg_worker), чтобы явно запрошенный native не превращался молча
    в медленный Python-путь.
    """
    choice = (os.environ.get("WG_ONION_ENGINE") or "auto").strip().lower()
    if choice not in ("python", "native", "auto"):
        return "auto"
    return choice


def choose_engine():
    """python|native|auto -> фактически доступный движок: "native"/"python"."""
    mode = engine_mode()
    if mode == "python":
        return "python"
    return "native" if is_available() else "python"

