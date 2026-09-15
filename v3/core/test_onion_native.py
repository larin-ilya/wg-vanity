# -*- coding: utf-8 -*-
"""Тесты нативного onion-движка (onion_native/bin/wg_onion.dll).

Запуск:  cd v3/core && python test_onion_native.py
Выход:   0 если все проверки PASS, 1 иначе.

Проверяем:
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

import onion_native                                     # noqa: E402
import wg_worker                                        # noqa: E402

N_ADDR = 1000
N_FILTER = 2000

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
    if not onion_native.is_available():
        print("нативный движок недоступен: %s"
              % onion_native.unavailable_reason())
        print("соберите DLL: powershell -File v3/core/onion_native/build.ps1")
        sys.exit(1)


# --------------------------------------------------------------------------
def test_1_address():
    section("1. addr_from_pub: нативный vs Python (%d ключей)" % N_ADDR)
    eng = onion_native.get_engine()
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
    eng2 = onion_native.get_engine()
    good = eng2.addr_from_pub(b"\x00" * 32)
    check("длина адреса 56 и алфавит a-z2-7",
          len(good) == 56 and all(c in wg_worker.ONION_CHARSET for c in good),
          repr(good))


# --------------------------------------------------------------------------
def _load_private_copy():
    """Загружает отдельную КОПИЮ DLL, чтобы её глобальное состояние (набор
    префиксов) не пересекалось с тем, что использует onion_native.py.
    Windows кэширует модуль по полному пути, так что копия в temp — это
    действительно отдельный экземпляр со своими глобальными переменными."""
    import ctypes
    src = onion_native.find_dll()
    if src is None:
        return None, None
    tmpdir = tempfile.mkdtemp(prefix="wgv_dll_copy_")
    dst = os.path.join(tmpdir, onion_native.DLL_NAME)
    shutil.copy2(src, dst)
    dll = ctypes.CDLL(dst)
    dll.wg_onion_init.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    dll.wg_onion_init.restype = ctypes.c_int
    dll.wg_onion_set_prefixes.argtypes = [
        ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
    dll.wg_onion_set_prefixes.restype = ctypes.c_int
    dll.wg_onion_filter_match.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    dll.wg_onion_filter_match.restype = ctypes.c_int
    dll.wg_onion_addr_from_pub.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    dll.wg_onion_addr_from_pub.restype = ctypes.c_int
    return dll, tmpdir


def test_2_filter():
    section("2. битовый фильтр vs addr.startswith (%d ключей)" % N_FILTER)
    eng = onion_native.get_engine()

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
        check("2b: wg_onion_init", dll.wg_onion_init(os.urandom(48), 48) == 0)

        long_prefixes = [
            "a" * 13,                                            # 13
            "zzzzzzzzzzzz2",                                     # 13
            "abcdefghijklmnopqrstuvwxyz23456",                   # 31
            "a" * 48,                                            # 48
            "abcdefghij" * 4 + "a" * 11,                         # 51
            "a" * 55,                                            # 55 (>51)
        ]
        arr = (ctypes_array_of_c_char_p(long_prefixes))
        rc = dll.wg_onion_set_prefixes(arr, len(long_prefixes))
        check("2b: set_prefixes принимает 1..55 символов", rc == 0,
              "rc=%d" % rc)

        bad = []
        for i in range(N_FILTER):
            pub = os.urandom(32)
            out = ctypes.create_string_buffer(57)
            dll.wg_onion_addr_from_pub(pub, out)
            addr = out.value.decode("ascii")
            want = any(addr.startswith(p) for p in long_prefixes)
            idx = ctypes.c_int(-1)
            got = dll.wg_onion_filter_match(pub, ctypes.byref(idx)) == 1
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
            rc = dll.wg_onion_set_prefixes(ctypes_array_of_c_char_p(plist), 1)
            check("2b: отвергает '%s'" % name, rc < 0, "rc=%d" % rc)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def ctypes_array_of_c_char_p(items):
    vals = [s if isinstance(s, bytes) else s.encode("ascii") for s in items]
    return (ctypes.c_char_p * len(vals))(*vals)


# --------------------------------------------------------------------------
def test_3_end_to_end():
    section("3. end-to-end: поиск 3-символьного префикса нативным движком")
    eng = onion_native.get_engine()
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
    section("4. fallback: WG_ONION_ENGINE=python")
    old = os.environ.get("WG_ONION_ENGINE")
    os.environ["WG_ONION_ENGINE"] = "python"
    try:
        check("engine_mode() == python",
              onion_native.engine_mode() == "python")
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
def main():
    print("Python %s, %s" % (sys.version.split()[0], sys.platform))
    require_native()
    eng = onion_native.get_engine()
    print("DLL   : %s" % eng.path)
    print("engine: %s" % eng.engine_info())

    test_1_address()
    test_2_filter()
    test_3_end_to_end()
    test_4_python_fallback()
    test_5_file_format()

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
