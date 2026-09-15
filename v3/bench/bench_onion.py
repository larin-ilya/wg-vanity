# -*- coding: utf-8 -*-
"""Бенчмарк скорости поиска .onion v3: python-движок против нативного.

Запуск:
    cd v3/core && python ../bench/bench_onion.py --engine native --seconds 10 --cores 12
    cd v3/core && python ../bench/bench_onion.py --engine python --seconds 10 --cores 12
    cd v3 && python bench/bench_onion.py --engine native --seconds 5 --cores 1 --json

Мерит ровно одно и то же у обоих движков: тот же набор префиксов, то же число
процессов, тот же код (реальные функции воркера search_worker_onion*), тот же
способ подсчёта (общий mp.Value-счётчик).  Дополнительно прогреваем процессы
до старта замера, чтобы время импорта/DLL не попадало в цифры.

Числа в v3/bench/RESULTS.md получены этой же командой.
"""
import argparse
import json
import multiprocessing as mp
import os
import platform
import sys
import time
from functools import partial

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.normpath(os.path.join(HERE, "..", "core"))
if CORE not in sys.path:
    sys.path.insert(0, CORE)

import wg_worker                                        # noqa: E402

# Набор префиксов для замера. 8 символов = 32**8 ~ 1.1e12 комбинаций, поэтому
# ни один движок не найдёт совпадение за секунды — меряем чистую скорость.
# Алфавит — только a-z2-7, как требует Tor.
BENCH_PREFIXES = ["tor7zzzq", "7orzzzzz"]


def cpu_name():
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            val = winreg.QueryValueEx(key, "ProcessorNameString")[0]
            winreg.CloseKey(key)
            return " ".join(str(val).split())
        except Exception:
            pass
    return platform.processor() or platform.machine()


def run_once(engine, seconds, cores, warmup=0.75):
    """Гоняет cores процессов выбранного движка и возвращает (keys, seconds)."""
    groups = wg_worker.build_groups({p.encode("ascii")
                                     for p in BENCH_PREFIXES})
    first_bytes = list(groups.keys())

    stop_event = mp.Event()
    found_event = mp.Event()
    counter = mp.Value("Q", 0)
    queue = mp.Queue()

    if engine == "native":
        target = wg_worker._search_worker_onion_native
        args = lambda i: (i, groups, stop_event, found_event, counter,
                          queue)                                  # noqa: E731
    else:
        target = wg_worker._search_worker_onion_python
        args = lambda i: (i, groups, first_bytes, stop_event, found_event,
                          counter, queue)                         # noqa: E731

    procs = []
    for i in range(cores):
        p = mp.Process(target=target, args=args(i + 1), daemon=True)
        p.start()
        procs.append(p)

    time.sleep(warmup)
    with counter.get_lock():
        base = counter.value

    t0 = time.perf_counter()
    time.sleep(seconds)
    stop_event.set()
    for p in procs:
        p.join(timeout=60)
    t1 = time.perf_counter()

    with counter.get_lock():
        total = counter.value - base

    for p in procs:
        if p.is_alive():
            p.terminate()

    # ошибки воркеров не глотаем
    errs = []
    try:
        while True:
            m = queue.get_nowait()
            if "error" in m:
                errs.append(m["error"])
    except Exception:
        pass
    if errs:
        print("  !! worker errors: %r" % errs[:3], file=sys.stderr)
    if found_event.is_set():
        print("  !! неожиданно найден префикс — замер некорректен",
              file=sys.stderr)

    return total, (t1 - t0)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engine", choices=["python", "native"], required=True)
    ap.add_argument("--seconds", type=float, default=10.0,
                    help="длительность замера (по умолчанию 10)")
    ap.add_argument("--cores", type=int, default=os.cpu_count() or 1,
                    help="число процессов (по умолчанию все ядра)")
    ap.add_argument("--repeat", type=int, default=1,
                    help="повторить замер N раз и взять лучший результат")
    ap.add_argument("--json", action="store_true",
                    help="напечатать результат в JSON")
    args = ap.parse_args()

    info = {
        "engine": args.engine,
        "cores": args.cores,
        "seconds": args.seconds,
        "cpu": cpu_name(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "prefixes": BENCH_PREFIXES,
    }
    if args.engine == "native":
        info["dll"] = None
        info["engine_info"] = None
        if wg_worker.onion_native is None:
            print("нативный движок недоступен: %s"
                  % wg_worker.ONION_NATIVE_IMPORT_ERROR, file=sys.stderr)
            return 2
        info["dll"] = wg_worker.onion_native.find_dll()
        if not wg_worker.onion_native.is_available():
            print("нативный движок недоступен: %s"
                  % wg_worker.onion_native.unavailable_reason(), file=sys.stderr)
            return 2
        info["engine_info"] = wg_worker.onion_native.get_engine().engine_info()
    else:
        if not wg_worker.HAVE_NACL:
            print("python-движок требует PyNaCl", file=sys.stderr)
            return 2

    best = None
    for run in range(args.repeat):
        keys, el = run_once(args.engine, args.seconds, args.cores)
        kps = keys / el if el > 0 else 0.0
        if best is None or kps > best[2]:
            best = (keys, el, kps)
        if args.repeat > 1:
            print("  прогон %d: %s ключей за %.3f с -> %.0f keys/s"
                  % (run + 1, f"{keys:,}", el, kps))

    keys, el, kps = best
    info["keys"] = keys
    info["elapsed"] = el
    info["keys_per_sec"] = kps
    info["keys_per_sec_per_core"] = kps / args.cores

    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
    else:
        print("machine  : %s" % info["cpu"])
        print("cores    : %d logical, %s" % (info["cpu_count"], info["platform"]))
        print("python   : %s" % info["python"])
        print("engine   : %s" % info["engine"]
              + ("  (%s)" % info["engine_info"] if info.get("engine_info") else ""))
        if info.get("dll"):
            print("dll      : %s" % info["dll"])
        print("prefixes : %s (8 символов — за секунды не находится)"
              % ", ".join(BENCH_PREFIXES))
        print("workers  : %d, длительность %s с" % (args.cores, args.seconds))
        print("-" * 66)
        print("checked  : %s ключей за %.3f с" % (f"{keys:,}", el))
        print("RESULT   : %s keys/s суммарно, %s keys/s на ядро"
              % (f"{kps:,.0f}", f"{kps / args.cores:,.0f}"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
