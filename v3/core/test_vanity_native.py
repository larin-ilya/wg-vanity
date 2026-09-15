# -*- coding: utf-8 -*-
"""Тесты нативного движка обоих видов поиска (vanity_native/bin/vanity_core.dll).

Запуск:  cd v3/core && python test_vanity_native.py
Выход:   0 если все проверки PASS, 1 иначе.

.onion v3 (kind="onion"):
  1) addr_from_pub нативного модуля == onion_address_from_pub на Python
     (>=1000 случайных pubkey);
  2) битовый фильтр нативного движка == addr.startswith(prefix) на Python
     (>=2000 случайных pubkey, префиксы разной длины);
  3) end-to-end: поиск 3-символьного префикса нативным движком; адрес
     начинается с префикса, из 64-байтного секрета восстанавливается тот же
     pubkey, и адрес из pubkey совпадает с найденным;
  4) fallback: WG_ONION_ENGINE=python — прежний Python-путь даёт валидный
     адрес;
  5) формат файлов: save_onion_results пишет правильные магические
     префиксы и длины (проверяем байты).

WireGuard (kind="wg"):
  6) ГЛАВНЫЙ ТЕСТ: >=2000 случайных клампнутых скаляров -> публичный ключ,
     который выдаёт движок, побитово совпадает с
     nacl.bindings.crypto_scalarmult_base(sk) (X25519 из libsodium). Это
     подтверждает и переход Эдвардс->Монтгомери u=(z+y)/(z-y), и то, что
     редукция скаляра по L внутри ed25519-donna не портит результат;
  7) битовый фильтр по 6-битным группам base64 ==
     base64.b64encode(pub).startswith(prefix) на Python (>=2000 ключей,
     префиксы длиной 1..8 и набор из нескольких префиксов, как даёт leet);
  8) end-to-end: поиск 3-символьного WG-префикса нативным движком;
     crypto_scalarmult_base(private_key) даёт ровно найденный public_key,
     base64 которого начинается с префикса, а приватник — в кламп-форме;
  9) fallback: WG_NATIVE_ENGINE=python — прежний Python-путь, ключ валиден;
 10) валидация WG-префиксов: алфавит A-Za-z0-9+/ и длина 1..34 на уровне
     Python, 42 в C; всё остальное отвергается с понятной ошибкой.
"""
import base64
import ctypes
import hashlib
import multiprocessing as mp
import os
import shutil
import sys
import tempfile
import time

try:
    import nacl.bindings
    import nacl.signing
except Exception:
    nacl = None

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import vanity_native                                   # noqa: E402
import wg_worker                                       # noqa: E402

N_ADDR = 1000
N_FILTER = 2000
N_X25519 = 2000
N_X25519_STEP = 200

# порядок базовой точки ed25519 (X25519-скаляр никогда не редуцируется явно,
# ed25519-donna редуцирует — см. тест 6)
L = 2 ** 252 + 27742317777372353535851937790883648493

_failures = []
_checks = 0


def check(name, ok, detail=""):
    global _checks
    _checks += 1
    if ok:
        print("  PASS  %s" % name)
    else:
        print("  FAIL  %s%s" % (name, (" -- " + detail) if detail else ""))
        _failures.append(name)
    return ok


def section(title):
    print("\n== %s ==" % title)


def require_native():
    if not vanity_native.is_available():
        print("нативный движок недоступен: %s"
              % vanity_native.unavailable_reason())
        print("соберите DLL: powershell -File v3/core/vanity_native/build.ps1")
        sys.exit(1)


# --------------------------------------------------------------------------
def test_1_address():
    section("1. addr_from_pub: нативный vs Python (%d ключей)" % N_ADDR)
    eng = vanity_native.get_engine(vanity_native.ONION)
    mism = []
    for i in range(N_ADDR):
        pub = os.urandom(32)
        native = eng.addr_from_pub(pub)
        pypath = wg_worker.onion_address_from_pub(pub)
        if native != pypath:
            mism.append((pub.hex(), native, pypath))
    check("адреса совпадают", not mism,
          "%d расхождений, например %r" % (len(mism), mism[:2]))

    # дополнительно: адрес из найденной пары должен быть воспроизводим
    eng2 = vanity_native.get_engine(vanity_native.ONION)
    good = eng2.addr_from_pub(b"\x00" * 32)
    check("длина адреса 56 и алфавит a-z2-7",
          len(good) == 56 and all(c in wg_worker.ONION_CHARSET for c in good),
          repr(good))


# --------------------------------------------------------------------------
def _load_private_copy():
    """Загружает отдельную КОПИЮ DLL, чтобы её глобальное состояние (набор
    префиксов) не пересекалось с тем, что использует vanity_native.py.
    Windows кэширует модуль по полному пути, так что копия в temp — это
    действительно отдельный экземпляр со своими глобальными переменными."""
    import ctypes
    src = vanity_native.find_dll()
    if src is None:
        return None, None
    tmpdir = tempfile.mkdtemp(prefix="wgv_dll_copy_")
    dst = os.path.join(tmpdir, vanity_native.DLL_NAME)
    shutil.copy2(src, dst)
    dll = ctypes.CDLL(dst)
    dll.vanity_init.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    dll.vanity_init.restype = ctypes.c_int
    dll.vanity_set_prefixes.argtypes = [
        ctypes.c_int, ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
    dll.vanity_set_prefixes.restype = ctypes.c_int
    dll.vanity_filter_match.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    dll.vanity_filter_match.restype = ctypes.c_int
    dll.vanity_addr_from_pub.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
    dll.vanity_addr_from_pub.restype = ctypes.c_int
    dll.vanity_pub_from_priv.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
    dll.vanity_pub_from_priv.restype = ctypes.c_int
    return dll, tmpdir


def ctypes_array_of_c_char_p(items):
    vals = [s if isinstance(s, bytes) else s.encode("ascii") for s in items]
    return (ctypes.c_char_p * len(vals))(*vals)


_B64VAL = {c: i for i, c in enumerate(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}


def key_with_b64_prefix(p):
    """32-байтный ключ, base64 которого ГАРАНТИРОВАННО начинается с p.

    base64 — это нарезка потока бит на 6-битные группы по старшинству, значит
    достаточно положить в начало ключа биты символов p, а остальное залить
    нулями. Нужно, чтобы проверять фильтр не только на «нет ложных
    срабатываний» (случайные ключи), но и на «нет пропусков» — в том числе на
    границе, где 6*len(p) не кратно 8."""
    bits = "".join(format(_B64VAL[c], "06b") for c in p)
    return int(bits + "0" * (256 - len(bits)), 2).to_bytes(32, "big")


def test_2_filter():
    section("2. onion-фильтр vs addr.startswith (%d ключей)" % N_FILTER)
    eng = vanity_native.get_engine(vanity_native.ONION)

    # --- 2a. через Python-обёртку: префиксы разной длины в её пределах -----
    # (обёртка по ТЗ принимает 1..12 символов)
    prefixes = ["a", "b4", "cook", "tor7", "zz2", "abcde", "m", "s3", "xx",
                "abcdefghijkl"]
    eng.configure(prefixes)
    bad_expected, bad_index, n_match = [], [], 0
    for i in range(N_FILTER):
        pub = os.urandom(32)
        addr = wg_worker.onion_address_from_pub(pub)
        want = any(addr.startswith(p) for p in prefixes)
        idx = eng.filter_match(pub)
        got = idx >= 0
        if got:
            n_match += 1
        if got != want:
            bad_expected.append((addr, idx, want))
        elif got and not addr.startswith(prefixes[idx]):
            bad_index.append((addr, idx, prefixes[idx]))
    check("2a: фильтр == startswith", not bad_expected,
          "%d расхождений, например %r" % (len(bad_expected),
                                           bad_expected[:3]))
    check("2a: индекс совпавшего префикса корректен", not bad_index,
          "%d расхождений, например %r" % (len(bad_index), bad_index[:3]))
    print("        (совпадений фильтра: %d из %d — ожидаемо мало)"
          % (n_match, N_FILTER))

    # --- 2b. C-уровень: границы 51/55 символов ---------------------------
    # 51 символ = 255 бит — максимум, который помещается в упакованный ключ,
    # не задевая sign-bit, который batchpack_destructive_1 не записывает.
    # Проверяем на отдельной копии DLL, чтобы не сбить состояние обёртки.
    dll, tmpdir = _load_private_copy()
    if dll is None:
        check("2b: копия DLL для C-теста", False, "DLL не найдена")
        return
    try:
        check("2b: vanity_init", dll.vanity_init(os.urandom(48), 48) == 0)

        long_prefixes = [
            "a" * 13,                                            # 13
            "zzzzzzzzzzzz2",                                     # 13
            "abcdefghijklmnopqrstuvwxyz23456",                   # 31
            "a" * 48,                                            # 48
            "abcdefghij" * 4 + "a" * 11,                         # 51
            "a" * 55,                                            # 55 (>51)
        ]
        arr = (ctypes_array_of_c_char_p(long_prefixes))
        rc = dll.vanity_set_prefixes(vanity_native.KIND_ONION, arr,
                                     len(long_prefixes))
        check("2b: set_prefixes принимает 1..55 символов", rc == 0,
              "rc=%d" % rc)

        bad = []
        for i in range(N_FILTER):
            pub = os.urandom(32)
            out = ctypes.create_string_buffer(57)
            dll.vanity_addr_from_pub(vanity_native.KIND_ONION, pub, out)
            addr = out.value.decode("ascii")
            want = any(addr.startswith(p) for p in long_prefixes)
            idx = ctypes.c_int(-1)
            got = dll.vanity_filter_match(vanity_native.KIND_ONION, pub,
                                          ctypes.byref(idx)) == 1
            if got != want:
                bad.append((addr, idx.value, want))
        check("2b: фильтр == startswith на 13..55 символах", not bad,
              "%d расхождений, например %r" % (len(bad), bad[:3]))

        # невалидные входы должны отвергаться, а не падать
        for name, plist in (
                ("пустая строка", [""]),
                ("заглавные", ["TOR"]),
                ("цифра 0/1/8/9", ["c0ol"]),
                ("56 символов (длиннее PUBLIC_LEN*8/5)", ["a" * 56]),
                ("не латиница", [b"\xd0\xba\xd0\xb8"])):
            rc = dll.vanity_set_prefixes(vanity_native.KIND_ONION,
                                         ctypes_array_of_c_char_p(plist), 1)
            check("2b: отвергает '%s'" % name, rc < 0, "rc=%d" % rc)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# --------------------------------------------------------------------------
def test_3_end_to_end():
    section("3. end-to-end: поиск 3-символьного onion-префикса")
    eng = vanity_native.get_engine(vanity_native.ONION)
    prefix = "tor"
    eng.configure([prefix])

    total = 0
    found = None
    t0 = time.time()
    while time.time() - t0 < 120:
        code, checked, res = eng.search(1 << 20)
        total += checked
        if res is not None:
            found = res
            break
    check("адрес найден", found is not None,
          "не нашли %r за %d ключей" % (prefix, total))
    if found is None:
        return
    onion = found["onion"]
    print("        найден %s.onion, проверено %d ключей" % (onion, total))

    check("адрес начинается с префикса", onion.startswith(prefix),
          "адрес %s, префикс %s" % (onion, prefix))
    check("длина адреса 56", len(onion) == 56, str(len(onion)))
    check("длина секрета 64", len(found["secret"]) == 64,
          str(len(found["secret"])))
    check("длина pubkey 32", len(found["pub"]) == 32, str(len(found["pub"])))
    check("длина seed 32", len(found["seed"]) == 32, str(len(found["seed"])))

    # адрес, пересчитанный из pubkey, должен совпасть
    recomputed = eng.addr_from_pub(found["pub"])
    check("addr_from_pub(pub) == найденный адрес", recomputed == onion,
          "%s != %s" % (recomputed, onion))

    # из РАСШИРЕННОГО 64-байтного секрета должен восстанавливаться тот же pubkey
    if nacl is not None:
        scalar = found["secret"][:32]
        try:
            pub2 = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(scalar)
            check("pubkey из 64-байтного секрета совпадает", pub2 == found["pub"],
                  "%s != %s" % (pub2.hex(), found["pub"].hex()))
        except Exception as e:                     # pragma: no cover
            check("pubkey из 64-байтного секрета совпадает", False,
                  "PyNaCl: %s" % e)
        # кламп-инварианты расширенного секрета
        s = found["secret"]
        check("секрет в кламп-форме (биты 0..2 и 31)",
              (s[0] & 7) == 0 and (s[31] & 128) == 0 and (s[31] & 64) != 0,
              "s[0]=%02x s[31]=%02x" % (s[0], s[31]))
    else:
        check("PyNaCl доступен", False, "nacl не импортируется")

    # секрет должен быть выводим и без DLL (тот же формат у python-пути)
    exp = wg_worker.onion_expanded_secret(found["seed"])
    # seed может быть не тем, что дал бы expand(seed), когда счётчик != 0,
    # поэтому сверяем только когда счётчик нулевой — иначе просто отмечаем
    if exp == found["secret"]:
        print("        (счётчик батча был 0: secret == expand(seed))")
    else:
        print("        (счётчик батча != 0: secret = expand(seed) + counter)")


# --------------------------------------------------------------------------
def test_4_python_fallback():
    section("4. fallback: WG_ONION_ENGINE=python (onion)")
    old = os.environ.get("WG_ONION_ENGINE")
    os.environ["WG_ONION_ENGINE"] = "python"
    try:
        check("engine_mode('onion') == python",
              vanity_native.engine_mode("onion") == "python")
        groups = wg_worker.build_groups({b"z"})
        check("onion_engine_for() == python",
              wg_worker.onion_engine_for(groups) == "python")

        # сам python-путь: запускаем в текущем процессе с mp-примитивами
        stop_event = mp.Event()
        found_event = mp.Event()
        counter = mp.Value("Q", 0)
        queue = mp.Queue()
        t0 = time.time()
        wg_worker._search_worker_onion_python(
            1, groups, [b"z"], stop_event, found_event, counter, queue)
        el = time.time() - t0
        res = queue.get(timeout=5)
        check("python-путь вернул результат", "error" not in res, repr(res))
        if "error" in res:
            return
        addr = res["onion"]
        check("адрес валиден и начинается с префикса",
              len(addr) == 56 and addr.startswith("z")
              and all(c in wg_worker.ONION_CHARSET for c in addr), repr(addr))
        check("engine == python", res.get("engine") == "python",
              repr(res.get("engine")))
        # seed -> pubkey должно сходиться без участия нативного модуля
        seed = base64.b64decode(res["seed_b64"])
        pub = base64.b64decode(res["public_key_b64"])
        if nacl is not None:
            check("pubkey соответствует seed",
                  nacl.signing.SigningKey(seed).verify_key.encode() == pub)
        check("адрес соответствует pubkey",
              wg_worker.onion_address_from_pub(pub) == addr)
        print("        (python-путь нашёл %s.onion за %.1f с)" % (addr, el))
    finally:
        if old is None:
            os.environ.pop("WG_ONION_ENGINE", None)
        else:
            os.environ["WG_ONION_ENGINE"] = old


# --------------------------------------------------------------------------
def test_5_file_format():
    section("5. формат файлов save_onion_results")
    pub = os.urandom(32)
    seed = os.urandom(32)
    onion = wg_worker.onion_address_from_pub(pub)
    secret = wg_worker.onion_expanded_secret(seed)

    out = tempfile.mkdtemp(prefix="wgv_onion_fmt_")
    try:
        for label, extra in (("без secret_b64 (python-путь)", {}),
                             ("с secret_b64 (нативный путь)",
                              {"secret_b64": base64.b64encode(
                                  secret).decode()})):
            res = {
                "onion": onion,
                "prefix": onion[:3],
                "seed_b64": base64.b64encode(seed).decode(),
                "public_key_b64": base64.b64encode(pub).decode(),
                "worker_id": 1,
                "keys_checked": 12345,
                "engine": "native" if extra else "python",
            }
            res.update(extra)
            files = wg_worker.save_onion_results(res, "test", True, out)
            svc = os.path.join(out, onion + ".onion")

            host = open(os.path.join(svc, "hostname"), "rb").read()
            check("%s: hostname == <addr>.onion\\n" % label,
                  host == (onion + ".onion\n").encode())

            pk = open(os.path.join(svc, "hs_ed25519_public_key"), "rb").read()
            check("%s: public_key = магия(32)+pub(32), итого 64" % label,
                  len(pk) == 64 and pk[:32] == wg_worker.ONION_PUBLIC_MAGIC
                  and pk[32:] == pub,
                  "len=%d magic=%r" % (len(pk), pk[:32]))

            sk = open(os.path.join(svc, "hs_ed25519_secret_key"), "rb").read()
            check("%s: secret_key = магия(32)+секрет(64), итого 96" % label,
                  len(sk) == 96 and sk[:32] == wg_worker.ONION_SECRET_MAGIC
                  and sk[32:] == secret,
                  "len=%d magic=%r" % (len(sk), sk[:32]))
            check("%s: секрет == sha512(seed) с клампом" % label,
                  sk[32:] == wg_worker.onion_expanded_secret(seed))
            check("%s: магия ровно как у mkp224o/Tor" % label,
                  wg_worker.ONION_SECRET_MAGIC
                  == b"== ed25519v1-secret: type0 ==\x00\x00\x00"
                  and wg_worker.ONION_PUBLIC_MAGIC
                  == b"== ed25519v1-public: type0 ==\x00\x00\x00")

            shutil.rmtree(svc, ignore_errors=True)
            for f in files:
                try:
                    os.remove(os.path.join(out, f))
                except OSError:
                    pass
    finally:
        shutil.rmtree(out, ignore_errors=True)


# --------------------------------------------------------------------------
def _clamped(sk):
    sk = bytearray(sk)
    sk[0] &= 248
    sk[31] &= 127
    sk[31] |= 64
    return bytes(sk)


def test_6_wg_matches_x25519():
    section("6. ГЛАВНЫЙ ТЕСТ: wg pubkey == X25519/PyNaCl (%d+%d скаляров)"
            % (N_X25519, N_X25519_STEP))
    if nacl is None:
        check("PyNaCl доступен", False, "nacl не импортируется")
        return
    eng = vanity_native.get_engine(vanity_native.WG)

    # 6a. клампнутые скаляры. Замечание про редукцию: любой клампнутый скаляр
    # >= 2**254 > L, т.е. ed25519-donna ВСЕГДА редуцирует его по L, а
    # libsodium в crypto_scalarmult_base — нет (он считает по модулю порядка
    # базовой точки). Совпадение всех 2000 результатов и есть проверка того,
    # что (sk mod L)*B == sk*B.
    mism = []
    t0 = time.time()
    for i in range(N_X25519):
        sk = _clamped(os.urandom(32))
        native = eng.pub_from_priv(sk)
        ref = nacl.bindings.crypto_scalarmult_base(sk)
        if native != ref:
            mism.append((sk.hex(), native.hex(), ref.hex()))
    check("6a: pubkey == crypto_scalarmult_base (клампнутые скаляры)",
          not mism, "%d расхождений, например %r" % (len(mism), mism[:2]))

    # 6b. скаляры с нередуцированным видом: sk + L (проверка редукции по L)
    mism2 = []
    for i in range(N_X25519_STEP):
        sk = _clamped(os.urandom(32))
        big = (int.from_bytes(sk, "little") + L).to_bytes(32, "little")
        native = eng.pub_from_priv(big)
        ref = nacl.bindings.crypto_scalarmult_base(big)
        if native != ref:
            mism2.append((big.hex(), native.hex(), ref.hex()))
    check("6b: pubkey == crypto_scalarmult_base (скаляр + L)",
          not mism2, "%d расхождений, например %r" % (len(mism2), mism2[:2]))

    # 6c. скаляры вида sk + 8b — те самые, что порождает batch-цикл шагом 8B
    mism3 = []
    for i in range(N_X25519_STEP):
        sk = _clamped(os.urandom(32))
        b = 1 + int.from_bytes(os.urandom(2), "little")      # 1..65536
        cand = (int.from_bytes(sk, "little") + 8 * b).to_bytes(32, "little")
        native = eng.pub_from_priv(cand)
        ref = nacl.bindings.crypto_scalarmult_base(cand)
        if native != ref:
            mism3.append((cand.hex(), native.hex(), ref.hex()))
    check("6c: pubkey == crypto_scalarmult_base (скаляр sk+8b)",
          not mism3, "%d расхождений, например %r" % (len(mism3), mism3[:2]))

    # 6d. инкремент скаляра в C: candidate(b) == sk + 8b
    base = _clamped(os.urandom(32))
    ok_step = True
    for b in (0, 1, 2, 7, 2047, 2048, 65535):
        want = (int.from_bytes(base, "little") + 8 * b).to_bytes(32, "little")
        got = bytearray(base)
        v = 8 * b
        carry = 0
        for i in range(32):
            carry += got[i] + (v & 0xFF)
            got[i] = carry & 0xFF
            carry >>= 8
            v >>= 8
        if bytes(got) != want:
            ok_step = False
    check("6d: арифметика счётчика 8b совпадает с Python", ok_step)

    # 6e. pub_from_priv умеет и onion (seed -> ed25519 pubkey)
    seed = os.urandom(32)
    onion_pub = vanity_native.get_engine(
        vanity_native.ONION).pub_from_priv(seed)
    check("6e: pub_from_priv(onion, seed) == SigningKey(seed).pubkey",
          onion_pub == nacl.signing.SigningKey(seed).verify_key.encode())
    print("        (6a+6b+6c: %d сравнений с PyNaCl за %.1f с)"
          % (N_X25519 + 2 * N_X25519_STEP, time.time() - t0))


# --------------------------------------------------------------------------
def test_7_wg_filter():
    section("7. wg-фильтр (6-битные группы base64) vs startswith (%d ключей)"
            % N_FILTER)
    eng = vanity_native.get_engine(vanity_native.WG)

    # 7a. префиксы длиной 1..8 через Python-обёртку
    prefixes = ["A", "b", "7", "Zx9", "cook", "AAAA", "zz/9", "0123",
                "abcdEFGH", "+/ab"]
    eng.configure(prefixes, kind=vanity_native.WG)
    bad_expected, bad_index, n_match = [], [], 0
    for i in range(N_FILTER):
        pub = os.urandom(32)
        b64 = base64.b64encode(pub).decode("ascii")
        want = any(b64.startswith(p) for p in prefixes)
        idx = eng.filter_match(pub)
        got = idx >= 0
        if got:
            n_match += 1
        if got != want:
            bad_expected.append((b64, idx, want))
        elif got and not b64.startswith(prefixes[idx]):
            bad_index.append((b64, idx, prefixes[idx]))
    check("7a: фильтр == base64(pub).startswith", not bad_expected,
          "%d расхождений, например %r" % (len(bad_expected),
                                           bad_expected[:3]))
    check("7a: индекс совпавшего префикса корректен", not bad_index,
          "%d расхождений, например %r" % (len(bad_index), bad_index[:3]))
    print("        (совпадений фильтра: %d из %d)" % (n_match, N_FILTER))

    # 7b. набор «как даёт leet» — много префиксов, в т.ч. с '/' и '+'
    leet = sorted(w.decode("ascii") for w in wg_worker.generate_prefixes(
        "cool", False)[0])
    eng.configure(leet, kind=vanity_native.WG)
    bad = []
    for i in range(N_FILTER):
        pub = os.urandom(32)
        b64 = base64.b64encode(pub).decode("ascii")
        want = any(b64.startswith(p) for p in leet)
        got = eng.filter_match(pub) >= 0
        if got != want:
            bad.append(b64)
    check("7b: фильтр == startswith на leet-наборе (%d префиксов)"
          % len(leet), not bad, "%d расхождений, например %r"
          % (len(bad), bad[:2]))

    # 7c. положительные срабатывания на СКОНСТРУИРОВАННЫХ ключах: так
    # проверяется, что фильтр ничего не пропускает (в т.ч. на длинах, где
    # 6*len не кратно 8, и на верхней границе обёртки — 34 символа)
    pos = ["A", "b", "Zx9", "abcdEFG", "0123456789", "abcdefghijkl",
           "Ab3+/Zx9" * 4, "a" * 34]
    eng.configure(pos, kind=vanity_native.WG)
    miss, wrong_idx = [], []
    for p in pos:
        key = key_with_b64_prefix(p)
        b64 = base64.b64encode(key).decode("ascii")
        idx = eng.filter_match(key)
        if idx < 0:
            miss.append((p, b64))
        elif not b64.startswith(pos[idx]):
            wrong_idx.append((p, idx, pos[idx], b64))
        if not b64.startswith(p):
            miss.append(("python-side", p, b64))
    check("7c: фильтр находит сконструированные ключи (длины 1..34)",
          not miss, "%d пропусков, например %r" % (len(miss), miss[:2]))
    check("7c: индекс указывает на реально совпавший префикс",
          not wrong_idx, repr(wrong_idx[:2]))

    # 7d. C-уровень: точная граница 42 символа
    dll, tmpdir = _load_private_copy()
    if dll is None:
        check("7d: копия DLL для C-теста", False, "DLL не найдена")
        return
    try:
        check("7d: vanity_init", dll.vanity_init(os.urandom(48), 48) == 0)
        for n, want_ok in ((1, True), (8, True), (42, True), (43, False),
                           (55, False)):
            p = ("Ab3+/Zx9" * 8)[:n]
            rc = dll.vanity_set_prefixes(
                vanity_native.KIND_WG, ctypes_array_of_c_char_p([p]), 1)
            check("7d: wg-префикс длиной %d -> rc%s 0" % (n, "==" if want_ok
                                                         else "!="),
                  (rc == 0) == want_ok, "rc=%d" % rc)

        long_wg = ["Ab3+/Zx9" * 5, "a" * 42, "Zz09+/" * 7]
        rc = dll.vanity_set_prefixes(vanity_native.KIND_WG,
                                     ctypes_array_of_c_char_p(long_wg),
                                     len(long_wg))
        check("7d: set_prefixes принимает длинные (<=42) wg-префиксы",
              rc == 0, "rc=%d" % rc)
        bad2 = []
        for i in range(N_FILTER):
            pub = os.urandom(32)
            b64 = base64.b64encode(pub).decode("ascii")
            want = any(b64.startswith(p) for p in long_wg)
            idx = ctypes.c_int(-1)
            got = dll.vanity_filter_match(vanity_native.KIND_WG, pub,
                                          ctypes.byref(idx)) == 1
            if got != want:
                bad2.append((b64, idx.value, want))
        check("7d: фильтр == startswith на 40..42 символах", not bad2,
              "%d расхождений, например %r" % (len(bad2), bad2[:3]))
        # ...и на границе ничего не пропускает
        miss2 = []
        for p in long_wg:
            key = key_with_b64_prefix(p)
            idx = ctypes.c_int(-1)
            r = dll.vanity_filter_match(vanity_native.KIND_WG, key,
                                        ctypes.byref(idx))
            if r != 1 or idx.value != long_wg.index(p):
                miss2.append((p, r, idx.value))
        check("7d: граница 42 символа ловится C-фильтром", not miss2,
              repr(miss2))

        # onion- и wg-фильтры не должны мешать друг другу
        arr_on = ctypes_array_of_c_char_p(["tor"])
        rc_o = dll.vanity_set_prefixes(vanity_native.KIND_ONION, arr_on, 1)
        arr_wg = ctypes_array_of_c_char_p(["Zx9"])
        rc_w = dll.vanity_set_prefixes(vanity_native.KIND_WG, arr_wg, 1)
        check("7d: наборы префиксов onion и wg независимы",
              rc_o == 0 and rc_w == 0)
        n_on = n_wg = 0
        for i in range(500):
            pub = os.urandom(32)
            addr = wg_worker.onion_address_from_pub(pub)
            b64 = base64.b64encode(pub).decode("ascii")
            i_on = ctypes.c_int(-1)
            i_wg = ctypes.c_int(-1)
            dll.vanity_filter_match(vanity_native.KIND_ONION, pub,
                                    ctypes.byref(i_on))
            dll.vanity_filter_match(vanity_native.KIND_WG, pub,
                                    ctypes.byref(i_wg))
            if (i_on.value >= 0) != addr.startswith("tor"):
                n_on += 1
            if (i_wg.value >= 0) != b64.startswith("Zx9"):
                n_wg += 1
        check("7d: оба фильтра верны при одновременной установке",
              n_on == 0 and n_wg == 0, "onion=%d wg=%d" % (n_on, n_wg))

        # невалидные входы должны отвергаться, а не падать
        for name, plist, kind in (
                ("пустая строка", [""], vanity_native.KIND_WG),
                ("пробел", ["ab cd"], vanity_native.KIND_WG),
                ("дефис", ["ab-c"], vanity_native.KIND_WG),
                ("'=' (padding)", ["abc="], vanity_native.KIND_WG),
                ("подчёркивание", ["ab_c"], vanity_native.KIND_WG),
                ("не латиница", [b"\xd0\xba\xd0\xb8"], vanity_native.KIND_WG),
                ("цифра 8 в onion", ["a8b"], vanity_native.KIND_ONION),
                ("kind=2", ["abc"], 2)):
            rc = dll.vanity_set_prefixes(kind, ctypes_array_of_c_char_p(plist),
                                         1)
            check("7d: отвергает '%s'" % name, rc < 0, "rc=%d" % rc)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# --------------------------------------------------------------------------
def test_8_wg_end_to_end():
    section("8. end-to-end: поиск 3-символьного WG-префикса нативным движком")
    if nacl is None:
        check("PyNaCl доступен", False, "nacl не импортируется")
        return
    eng = vanity_native.get_engine(vanity_native.WG)
    prefix = "Zx9"
    eng.configure([prefix], kind=vanity_native.WG)

    total = 0
    found = None
    t0 = time.time()
    while time.time() - t0 < 120:
        code, checked, res = eng.search(1 << 20)
        total += checked
        if res is not None:
            found = res
            break
    check("ключ найден", found is not None,
          "не нашли %r за %d ключей" % (prefix, total))
    if found is None:
        return

    priv = found["private_key"]
    pub = found["public_key"]
    b64 = base64.b64encode(pub).decode("ascii")
    print("        найден %s… проверено %d ключей" % (b64[:12], total))

    check("длина приватного ключа 32", len(priv) == 32, str(len(priv)))
    check("длина публичного ключа 32", len(pub) == 32, str(len(pub)))
    check("base64(pub) начинается с префикса", b64.startswith(prefix),
          "%s / %s" % (b64, prefix))
    check("prefix в результате == установленный", found["prefix"] == prefix,
          repr(found.get("prefix")))
    check("checked в результате > 0", found.get("checked", 0) > 0,
          repr(found.get("checked")))
    check("seed 32 байта", len(found["seed"]) == 32, str(len(found["seed"])))

    # САМОЕ ГЛАВНОЕ: приватник и публичник — согласованная пара по X25519
    ref = nacl.bindings.crypto_scalarmult_base(priv)
    check("crypto_scalarmult_base(private_key) == public_key", ref == pub,
          "%s != %s" % (ref.hex(), pub.hex()))

    # кламп-инварианты приватника (X25519: sk[0]&248, sk[31]&127|64)
    check("приватник в кламп-форме (биты 0..2 нули, бит 7 нуль, бит 6 единица)",
          (priv[0] & 7) == 0 and (priv[31] & 128) == 0
          and (priv[31] & 64) != 0,
          "p[0]=%02x p[31]=%02x" % (priv[0], priv[31]))

    # повторный кламп не меняет приватник (значит X25519 его не «подправит»)
    check("повторный кламп приватника — тождество",
          _clamped(priv) == priv)

    # native pub_from_priv даёт то же самое (сверка двух путей внутри движка)
    check("pub_from_priv(private_key) == public_key",
          eng.pub_from_priv(priv) == pub)

    # фильтр по этому ключу должен срабатывать
    check("filter_match(public_key) находит префикс",
          eng.filter_match(pub) >= 0)

    # и «до»-путь: python-движок на том же префиксе даёт валидный ключ
    res2 = wg_worker._match_prefix([prefix.encode()], b64)
    check("_match_prefix выбирает префикс", res2 == prefix, repr(res2))


# --------------------------------------------------------------------------
def test_9_wg_python_fallback():
    section("9. fallback: WG_NATIVE_ENGINE=python (wg)")
    old = os.environ.get("WG_NATIVE_ENGINE")
    os.environ["WG_NATIVE_ENGINE"] = "python"
    try:
        check("engine_mode('wg') == python",
              vanity_native.engine_mode("wg") == "python")
        check("engine_mode('onion') == python (общий переключатель)",
              vanity_native.engine_mode("onion") == "python")
        groups = wg_worker.build_groups({b"Z"})
        check("wg_engine_for() == python",
              wg_worker.wg_engine_for(groups) == "python")

        stop_event = mp.Event()
        found_event = mp.Event()
        counter = mp.Value("Q", 0)
        queue = mp.Queue()
        t0 = time.time()
        wg_worker._search_worker_wg_python(
            1, groups, [b"Z"], stop_event, found_event, counter, queue)
        el = time.time() - t0
        res = queue.get(timeout=60)
        check("python-путь вернул результат", "error" not in res, repr(res))
        if "error" in res:
            return
        check("engine == python", res.get("engine") == "python",
              repr(res.get("engine")))
        check("ключ начинается с префикса", res["public_key"].startswith("Z"),
              repr(res["public_key"]))
        priv = base64.b64decode(res["private_key"])
        pub = base64.b64decode(res["public_key"])
        check("длины ключей 32/32", len(priv) == 32 and len(pub) == 32,
              "%d/%d" % (len(priv), len(pub)))
        if nacl is not None:
            check("crypto_scalarmult_base(private_key) == public_key",
                  nacl.bindings.crypto_scalarmult_base(priv) == pub)
        print("        (python-путь нашёл %s… за %.1f с)"
              % (res["public_key"][:12], el))

        # старый WG_ONION_ENGINE продолжает работать, когда новый не задан
        os.environ.pop("WG_NATIVE_ENGINE", None)
        os.environ["WG_ONION_ENGINE"] = "python"
        check("WG_ONION_ENGINE=python всё ещё понимается (onion)",
              vanity_native.engine_mode("onion") == "python")
        check("WG_ONION_ENGINE не влияет на wg",
              vanity_native.engine_mode("wg") == "auto")
        os.environ["WG_ONION_ENGINE"] = "native"
        check("WG_ONION_ENGINE=native работает для onion",
              vanity_native.engine_mode("onion") == "native")
        os.environ["WG_NATIVE_ENGINE"] = "python"
        check("WG_NATIVE_ENGINE имеет приоритет над WG_ONION_ENGINE",
              vanity_native.engine_mode("onion") == "python",
              repr(vanity_native.engine_mode("onion")))
    finally:
        os.environ.pop("WG_ONION_ENGINE", None)
        if old is None:
            os.environ.pop("WG_NATIVE_ENGINE", None)
        else:
            os.environ["WG_NATIVE_ENGINE"] = old


# --------------------------------------------------------------------------
def test_10_wg_prefix_validation():
    section("10. валидация WG-префиксов на уровне Python-обёртки")
    ok = vanity_native.VanityNativeEngine.normalize_prefixes(
        ["A", "Zx9", "abcdEFGH", "+/ab", "a" * 34], kind="wg")
    check("принимает A-Za-z0-9+/ длиной 1..34",
          ok == ["A", "Zx9", "abcdEFGH", "+/ab", "a" * 34], repr(ok))

    bad_cases = [
        ("пустой список", []),
        ("пустая строка", [""]),
        ("36 символов", ["a" * 36]),
        ("'=' (base64 padding)", ["abc="]),
        ("'-' (url-safe base64)", ["ab-c"]),
        ("'_' (url-safe base64)", ["ab_c"]),
        ("пробел", ["ab cd"]),
        ("кириллица", ["\u043a\u0438"]),
    ]
    for name, plist in bad_cases:
        try:
            vanity_native.VanityNativeEngine.normalize_prefixes(
                plist, kind="wg")
            got = None
        except vanity_native.VanityNativeError as e:
            got = str(e)
        check("отвергает %s" % name, got is not None,
              "исключения не было (got=%r)" % (got,))
        if got:
            print("        (%s → %s)" % (name, got))

    # wg_engine_for: непригодный набор префиксов -> тихий python в auto и
    # громкая ошибка при явном native
    long_groups = wg_worker.build_groups({b"a" * 40})
    old = os.environ.get("WG_NATIVE_ENGINE")
    try:
        os.environ.pop("WG_NATIVE_ENGINE", None)
        check("auto: слишком длинный префикс -> python",
              wg_worker.wg_engine_for(long_groups) == "python")
        os.environ["WG_NATIVE_ENGINE"] = "native"
        err = None
        try:
            wg_worker.wg_engine_for(long_groups)
        except Exception as e:
            err = str(e)
        check("native: слишком длинный префикс -> громкая ошибка",
              err is not None, "исключения не было")
        if err:
            print("        (%s)" % err.split(":")[0])
    finally:
        if old is None:
            os.environ.pop("WG_NATIVE_ENGINE", None)
        else:
            os.environ["WG_NATIVE_ENGINE"] = old


# --------------------------------------------------------------------------
def main():
    print("Python %s, %s" % (sys.version.split()[0], sys.platform))
    require_native()
    eng = vanity_native.get_engine(vanity_native.ONION)
    print("DLL   : %s" % eng.path)
    print("engine: %s" % eng.engine_info())

    test_1_address()
    test_2_filter()
    test_3_end_to_end()
    test_4_python_fallback()
    test_5_file_format()
    test_6_wg_matches_x25519()
    test_7_wg_filter()
    test_8_wg_end_to_end()
    test_9_wg_python_fallback()
    test_10_wg_prefix_validation()

    print("\n" + "=" * 60)
    if _failures:
        print("ИТОГ: FAIL (%d из %d проверок не прошли)" % (len(_failures),
                                                          _checks))
        for f in _failures:
            print("  - %s" % f)
        return 1
    print("ИТОГ: PASS (все %d проверок)" % _checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
