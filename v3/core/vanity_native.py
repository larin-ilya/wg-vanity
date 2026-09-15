# -*- coding: utf-8 -*-
"""
ctypes-обёртка над нативным движком двух видов vanity-поиска
(vanity_native/bin/vanity_core.dll):

  * kind="onion" — красивые Tor v3 .onion-адреса (ed25519, base32 a-z2-7);
  * kind="wg"    — красивые WireGuard-ключи (X25519, base64 A-Za-z0-9+/).

Один C-модуль обслуживает оба: batch-цикл mkp224o (ed25519-donna) с одной
обратной инверсией на батч из 2048 точек.  Для onion упаковка — ed25519-pubkey
(base32-адрес), для WireGuard — переход Эдвардс→Монтгомери
u = (z + y) / (z - y) и канонизация (`curve25519_contract`).  Всё это живёт в
vanity_native/vanity_bridge.c, см. также vanity_native/build.ps1 и
vanity_native/vendor/UPSTREAM.txt.

Особенности:
  * DLL линкуется БЕЗ libc, поэтому она не выделяет память и не пишет файлы —
    найденный ключ возвращается в аргументах вызова;
  * энтропия попадает внутрь ровно один раз: os.urandom(48) через
    vanity_init(), дальше работает внутренний ChaCha20-DRBG;
  * base64-строку для WireGuard формирует Python (в C только сырые 32 байта);
  * модуль НЕ потокобезопасен (у DLL одно глобальное состояние). Параллелизм в
    проекте — через multiprocessing, по одному движку на процесс; на всякий
    случай вызовы сериализованы threading.Lock'ом.

Выбор движка (переменные окружения, приоритет сверху вниз):

  1. WG_NATIVE_ENGINE=auto|native|python — общий переключатель для ОБОИХ видов
     поиска (по умолчанию auto: native, если DLL есть, иначе python);
  2. WG_ONION_ENGINE=auto|native|python — старый переключатель, продолжает
     работать и учитывается только для kind="onion" (обратная совместимость);
  3. иначе auto.

Если DLL недоступна (не собрана / другая платформа), is_available() вернёт
False, а configure()/search() — понятную ошибку; падения не будет.
"""
import base64
import ctypes
import os
import sys
import threading

DLL_NAME = "vanity_core.dll"
DLL_SUBDIR = "vanity_native"

# --------------------------------------------------------------------------
# Виды поиска
# --------------------------------------------------------------------------
KIND_ONION = 0
KIND_WG = 1
ONION = "onion"
WG = "wg"

_KIND_BY_NAME = {ONION: KIND_ONION, WG: KIND_WG}
_KIND_BY_CODE = {KIND_ONION: ONION, KIND_WG: WG}

# Алфавит onion v3 (RFC 4648 base32, нижний регистр).
ONION_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
# Алфавит WireGuard-ключей (RFC 4648 base64, стандартный, с '+' и '/').
WG_ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
               "0123456789+/")

# Нативный движок принимает onion-префиксы 1..12 символов. Более длинные дают
# астрономически малую вероятность попадания (32**13 ~ 2**65), поэтому
# воркер для них откатывается на чистый Python-путь.
MAX_PREFIX_LEN = 12
MIN_PREFIX_LEN = 1
# WireGuard: в приложении (GUI/wg_worker) слово ограничено 34 символами. C
# принимает до 42 (42*6 = 252 бита < 256, фильтр остаётся точным); всё, что
# длиннее 34, здесь считается непригодным для нативного пути.
MAX_WG_PREFIX_LEN = 34
C_MAX_WG_PREFIX_LEN = 42
MAX_PREFIXES = 4096
ONION_ADDR_LEN = 56

# Коды возврата vanity_search().
SEARCH_FOUND = 1
SEARCH_BUDGET_EXHAUSTED = 0


class VanityNativeError(RuntimeError):
    """DLL недоступна или отказала."""


class VanityNativeUnavailable(VanityNativeError):
    """DLL не найдена / не загрузилась — нужен fallback на Python-движок."""


class VanityNativeBadPrefix(VanityNativeError):
    """Префиксы не подходят для нативного движка — нужен fallback."""


def _norm_kind(kind):
    """'onion'/'wg'/0/1 -> 'onion'|'wg' (по умолчанию 'onion')."""
    if kind is None:
        return ONION
    if kind in _KIND_BY_NAME:
        return kind
    if kind in _KIND_BY_CODE:
        return _KIND_BY_CODE[kind]
    raise VanityNativeError("неизвестный kind: %r (нужно 'onion' или 'wg')"
                            % (kind,))


# --------------------------------------------------------------------------
# Поиск DLL
# --------------------------------------------------------------------------
def _candidate_paths():
    here = os.path.dirname(os.path.abspath(__file__))
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    meipass = getattr(sys, "_MEIPASS", None)
    names = [
        # 1) рядом с этим модулем: <core>/vanity_native/bin/vanity_core.dll
        os.path.join(here, DLL_SUBDIR, "bin", DLL_NAME),
        os.path.join(here, DLL_SUBDIR, DLL_NAME),
        # 2) рядом с исполняемым файлом (--onedir, ручная раскладка)
        os.path.join(exe_dir, DLL_NAME),
        os.path.join(exe_dir, DLL_SUBDIR, "bin", DLL_NAME),
    ]
    # 3) внутри PyInstaller-бандла (--onefile распаковывает в _MEIPASS)
    if meipass:
        names.insert(0, os.path.join(meipass, DLL_NAME))
        names.insert(1, os.path.join(meipass, DLL_SUBDIR, "bin", DLL_NAME))
    out = []
    for p in names:
        p = os.path.normpath(p)
        if p not in out:
            out.append(p)
    return out


def find_dll():
    """Возвращает путь к vanity_core.dll или None."""
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
class VanityNativeEngine:
    """Один экземпляр на процесс. Не потокобезопасен (см. модульный docstring)."""

    def __init__(self, kind=ONION):
        self._dll = None
        self._load_error = None
        self._path = None
        self._lock = threading.Lock()
        self._prefixes = {}        # kind -> список префиксов
        self._inited = False
        self.kind = _norm_kind(kind)

    # -- kind -------------------------------------------------------------
    @property
    def kind(self):
        return self._kind

    @kind.setter
    def kind(self, value):
        self._kind = _norm_kind(value)

    # -- загрузка ---------------------------------------------------------
    def _ensure_loaded(self):
        if self._dll is not None:
            return
        if self._load_error is not None:
            raise VanityNativeUnavailable(self._load_error)
        path = find_dll()
        if path is None:
            self._load_error = (
                "%s не найдена (искали: %s); "
                "соберите её: powershell -File v3/core/vanity_native/build.ps1"
                % (DLL_NAME, "; ".join(_candidate_paths())))
            raise VanityNativeUnavailable(self._load_error)
        try:
            dll = ctypes.CDLL(path)
        except OSError as e:
            self._load_error = "не удалось загрузить %s: %s" % (path, e)
            raise VanityNativeUnavailable(self._load_error)

        try:
            dll.vanity_init.argtypes = [ctypes.c_char_p, ctypes.c_uint]
            dll.vanity_init.restype = ctypes.c_int

            dll.vanity_set_prefixes.argtypes = [
                ctypes.c_int, ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
            dll.vanity_set_prefixes.restype = ctypes.c_int

            dll.vanity_search.argtypes = [
                ctypes.c_int,
                ctypes.c_ulonglong,
                ctypes.POINTER(ctypes.c_ulonglong),
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_char_p,
            ]
            dll.vanity_search.restype = ctypes.c_int

            dll.vanity_addr_from_pub.argtypes = [
                ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
            dll.vanity_addr_from_pub.restype = ctypes.c_int

            dll.vanity_pub_from_priv.argtypes = [
                ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
            dll.vanity_pub_from_priv.restype = ctypes.c_int

            dll.vanity_filter_match.argtypes = [
                ctypes.c_int, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
            dll.vanity_filter_match.restype = ctypes.c_int

            dll.vanity_engine_info.argtypes = [
                ctypes.c_char_p, ctypes.c_uint]
            dll.vanity_engine_info.restype = ctypes.c_int
        except AttributeError as e:
            self._load_error = "%s: нет ожидаемых экспортов (%s)" % (path, e)
            raise VanityNativeUnavailable(self._load_error)

        self._dll = dll
        self._path = path

    @property
    def path(self):
        self._ensure_loaded()
        return self._path

    def engine_info(self):
        self._ensure_loaded()
        buf = ctypes.create_string_buffer(160)
        self._dll.vanity_engine_info(buf, len(buf))
        return buf.value.decode("ascii", "replace")

    # -- проверка префиксов ----------------------------------------------
    @staticmethod
    def normalize_prefixes(prefixes, kind=ONION):
        """bytes/str -> список str (для onion — в нижнем регистре).

        Бросает VanityNativeBadPrefix, если набор непригоден для нативного
        движка (пустой, слишком длинный, посторонние символы)."""
        kind = _norm_kind(kind)
        if not prefixes:
            raise VanityNativeBadPrefix("пустой список префиксов")

        if kind == ONION:
            alphabet = set(ONION_ALPHABET)
            maxlen = MAX_PREFIX_LEN
            hint = "можно только a-z и 2-7"
        else:
            alphabet = set(WG_ALPHABET)
            maxlen = MAX_WG_PREFIX_LEN
            hint = "можно только A-Z a-z 0-9 + /"

        out = []
        seen = set()
        for p in prefixes:
            if isinstance(p, (bytes, bytearray)):
                try:
                    p = p.decode("ascii")
                except UnicodeDecodeError:
                    raise VanityNativeBadPrefix("префикс не ASCII: %r" % (p,))
            p = str(p)
            if kind == ONION:
                p = p.lower()
            if len(p) < MIN_PREFIX_LEN:
                raise VanityNativeBadPrefix("пустой префикс")
            if len(p) > maxlen:
                raise VanityNativeBadPrefix(
                    "префикс %r длиннее %d символов (kind=%s)"
                    % (p, maxlen, kind))
            bad = [c for c in p if c not in alphabet]
            if bad:
                raise VanityNativeBadPrefix(
                    "недопустимые символы в префиксе %r: %s (%s)"
                    % (p, " ".join(bad), hint))
            if p not in seen:
                seen.add(p)
                out.append(p)
        if len(out) > MAX_PREFIXES:
            raise VanityNativeBadPrefix(
                "слишком много префиксов: %d (максимум %d)"
                % (len(out), MAX_PREFIXES))
        return out

    def configure(self, prefixes, kind=None, seed=None):
        """Инициализирует DRBG и ставит набор префиксов для вида `kind`.

        kind=None — оставить текущий вид (по умолчанию "onion").
        Идемпотентна: повторный вызов с тем же (kind, набор) ничего не делает.
        seed — 32..64 байта; по умолчанию os.urandom(48)."""
        self._ensure_loaded()
        if kind is not None:
            kind = _norm_kind(kind)
        else:
            kind = self._kind
        self._kind = kind
        plist = self.normalize_prefixes(prefixes, kind)
        if self._inited and self._prefixes.get(kind) == plist:
            return
        seed = os.urandom(48) if seed is None else bytes(seed)
        if not 32 <= len(seed) <= 64:
            raise VanityNativeError("seed должен быть 32..64 байта, не %d"
                                   % len(seed))
        with self._lock:
            rc = self._dll.vanity_init(seed, len(seed))
            if rc != 0:
                raise VanityNativeError("vanity_init вернул %d" % rc)
            self._inited = True
            arr = (ctypes.c_char_p * len(plist))(
                *[p.encode("ascii") for p in plist])
            rc = self._dll.vanity_set_prefixes(
                _KIND_BY_NAME[kind], arr, len(plist))
            if rc != 0:
                self._inited = False
                self._prefixes.pop(kind, None)
                raise VanityNativeBadPrefix(
                    "vanity_set_prefixes(%s) вернул %d для %r"
                    % (kind, rc, plist))
            self._prefixes[kind] = plist

    # -- собственно поиск ------------------------------------------------
    def search(self, max_keys):
        """Ищет не более max_keys ключей вида self.kind.

        Возвращает (code, keys_checked, found|None):
          code == 1 и found — нашли (см. ключи ниже),
          code == 0 и found is None — бюджет исчерпан.

        kind="onion": found = {"onion": str, "pub": bytes[32],
                               "secret": bytes[64], "seed": bytes[32]}
          secret — РАСШИРЕННЫЙ ed25519-секрет (sha512(seed) с клампом плюс
          счётчик), тот самый формат, который Tor ждёт в hs_ed25519_secret_key.
        kind="wg":    found = {"private_key": bytes[32], "public_key": bytes[32],
                               "prefix": str, "checked": int, "seed": bytes[32]}
          private_key — клампнутый X25519-скаляр; public_key — сырая
          u-координата (base64-строку делает вызывающая сторона). prefix —
          самый длинный из установленных префиксов, которому соответствует
          ключ; checked — сколько ключей проверено в этом вызове (для onion это
          третий элемент кортежа, в dict его нет).

        seed в обоих случаях — seed, с которого стартовал батч (для
        человекочитаемого .txt)."""
        self._ensure_loaded()
        kind = self._kind
        if not self._inited or not self._prefixes.get(kind):
            raise VanityNativeError("configure() для kind=%r не вызывался"
                                    % kind)
        if max_keys <= 0:
            return SEARCH_BUDGET_EXHAUSTED, 0, None

        checked = ctypes.c_ulonglong(0)
        priv = ctypes.create_string_buffer(64)
        pub = ctypes.create_string_buffer(32)
        seed = ctypes.create_string_buffer(32)
        onion = ctypes.create_string_buffer(ONION_ADDR_LEN + 1)

        with self._lock:
            rc = self._dll.vanity_search(
                _KIND_BY_NAME[kind], ctypes.c_ulonglong(int(max_keys)),
                ctypes.byref(checked), priv, pub, seed, onion)

        if rc < 0:
            raise VanityNativeError("vanity_search(%s) вернул %d" % (kind, rc))
        if rc == 0:
            return SEARCH_BUDGET_EXHAUSTED, checked.value, None

        if kind == ONION:
            return SEARCH_FOUND, checked.value, {
                "onion": onion.value.decode("ascii"),
                "pub": pub.raw,
                "secret": priv.raw,
                "seed": seed.raw,
            }
        public_key = pub.raw
        return SEARCH_FOUND, checked.value, {
            "private_key": priv.raw[:32],
            "public_key": public_key,
            "prefix": self.match_prefix(public_key),
            "checked": checked.value,
            "seed": seed.raw,
        }

    # -- вспомогательное (для воркера и тестов) ---------------------------
    def match_prefix(self, pub):
        """Самый длинный из установленных префиксов, которому соответствует
        публичный ключ (для wg — по base64, для onion — по адресу)."""
        if self._kind == ONION:
            addr = self.addr_from_pub(pub)
            best = None
            for p in self._prefixes.get(ONION, ()):
                if addr.startswith(p) and (best is None or len(p) > len(best)):
                    best = p
            return best
        b64 = base64.b64encode(pub).decode("ascii")
        best = None
        for p in self._prefixes.get(WG, ()):
            if b64.startswith(p) and (best is None or len(p) > len(best)):
                best = p
        return best

    def addr_from_pub(self, pub):
        """Строковая форма публичного ключа.

        onion: 56-символьный адрес (считает нативный C);
        wg:    base64 32 байт — по ТЗ энкодер остаётся на стороне Python,
               поэтому здесь обычный base64.b64encode()."""
        self._ensure_loaded()
        if len(pub) != 32:
            raise VanityNativeError("pubkey должен быть 32 байта")
        if self._kind == WG:
            return base64.b64encode(bytes(pub)).decode("ascii")
        out = ctypes.create_string_buffer(ONION_ADDR_LEN + 1)
        rc = self._dll.vanity_addr_from_pub(KIND_ONION, bytes(pub), out)
        if rc != 0:
            raise VanityNativeError("vanity_addr_from_pub вернул %d" % rc)
        return out.value.decode("ascii")

    def pub_from_priv(self, priv):
        """Публичный ключ из приватного — C-реализация того же перехода, что
        делает batch-цикл (для тестов: сверка с libsodium/PyNaCl).

        onion: priv = 32-байтный seed  -> ed25519 pubkey (32);
        wg:    priv = 32-байтный скаляр -> X25519 u-координата (32), скаляр
               предварительно клампится, как в crypto_scalarmult_base()."""
        self._ensure_loaded()
        if len(priv) != 32:
            raise VanityNativeError("приватный ключ должен быть 32 байта")
        out = ctypes.create_string_buffer(32)
        rc = self._dll.vanity_pub_from_priv(
            _KIND_BY_NAME[self._kind], bytes(priv), out)
        if rc != 0:
            raise VanityNativeError("vanity_pub_from_priv вернул %d" % rc)
        return out.raw

    def filter_match(self, pub):
        """Проверяет битовый фильтр своего вида по УЖЕ установленным префиксам.

        Возвращает индекс совпавшего префикса или -1. Используется в тестах
        для сверки нативного фильтра со строковым сравнением на Python
        (addr.startswith / base64(pub).startswith)."""
        self._ensure_loaded()
        if len(pub) != 32:
            raise VanityNativeError("pubkey должен быть 32 байта")
        idx = ctypes.c_int(-1)
        r = self._dll.vanity_filter_match(
            _KIND_BY_NAME[self._kind], bytes(pub), ctypes.byref(idx))
        if r < 0:
            raise VanityNativeError("vanity_filter_match вернул %d" % r)
        if r == 0:
            return -1
        return idx.value


# --------------------------------------------------------------------------
# Процессные синглтоны + удобные функции модуля
# --------------------------------------------------------------------------
_engines = {}
_engine_lock = threading.Lock()


def get_engine(kind=ONION):
    """Движок для вида kind ('onion'|'wg'). По одному экземпляру на вид:
    у DLL отдельный набор фильтров для каждого вида, так что состояние не
    пересекается."""
    kind = _norm_kind(kind)
    with _engine_lock:
        eng = _engines.get(kind)
        if eng is None:
            eng = VanityNativeEngine(kind)
            _engines[kind] = eng
        return eng


def is_available():
    """True, если DLL найдена и загружается."""
    try:
        get_engine()._ensure_loaded()
        return True
    except VanityNativeError:
        return False
    except Exception:
        return False


def unavailable_reason():
    """Строка с причиной недоступности или None."""
    try:
        get_engine()._ensure_loaded()
        return None
    except VanityNativeError as e:
        return str(e)
    except Exception as e:  # pragma: no cover
        return str(e)


def engine_mode(kind=None):
    """Разбирает WG_NATIVE_ENGINE / WG_ONION_ENGINE в python|native|auto.

    Приоритет: WG_NATIVE_ENGINE (общий), затем — только для kind="onion" —
    старый WG_ONION_ENGINE, иначе auto.  Возвращает нормализованный выбор БЕЗ
    проверки доступности: решение о fallback принимает вызывающая сторона
    (wg_worker), чтобы явно запрошенный native не превращался молча в медленный
    Python-путь."""
    kind = _norm_kind(kind)
    choice = (os.environ.get("WG_NATIVE_ENGINE") or "").strip().lower()
    if choice not in ("python", "native", "auto"):
        choice = ""
    if not choice and kind == ONION:
        legacy = (os.environ.get("WG_ONION_ENGINE") or "").strip().lower()
        if legacy in ("python", "native", "auto"):
            choice = legacy
    return choice or "auto"


def choose_engine(kind=None):
    """python|native|auto -> фактически доступный движок: "native"/"python"."""
    mode = engine_mode(kind)
    if mode == "python":
        return "python"
    return "native" if is_available() else "python"
