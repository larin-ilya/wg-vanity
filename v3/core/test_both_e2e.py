# -*- coding: utf-8 -*-
"""Быстрый end-to-end тест воркера: wg и onion через TCP."""
import json, os, socket, subprocess, tempfile, time

PY = r"C:\Users\ilja\AppData\Local\Programs\Python\Python38\python.exe"
CORE = r"D:\AI-PROjects\TEST\wg-vanity\core"
WORKER = os.path.join(CORE, "wg_worker.py")

def run_search(cfg):
    portfile = os.path.join(tempfile.gettempdir(), "wgv_test_%d.txt" % int(time.time()*100))
    if os.path.exists(portfile):
        os.remove(portfile)
    env = dict(os.environ)
    env["PYTHONPATH"] = r"D:\AI-PROjects\TEST\wg-vanity\pylibs"
    proc = subprocess.Popen([PY, WORKER, "--portfile", portfile, "--secret", "t"],
                            env=env, cwd=CORE)
    try:
        port = None
        for _ in range(300):
            if os.path.exists(portfile):
                try:
                    port = int(open(portfile).read().strip())
                    if port > 0:
                        break
                except Exception:
                    pass
            if proc.poll() is not None:
                raise RuntimeError("worker exited: %s" % proc.poll())
            time.sleep(0.05)
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        f = s.makefile("rwb")
        buf = b""
        def send(o):
            f.write((json.dumps(o) + "\n").encode()); f.flush()
        def recv(t=10):
            nonlocal buf
            s.settimeout(t)
            while b"\n" not in buf:
                d = f.read(1)
                if not d:
                    raise RuntimeError("eof")
                buf += d
            line, buf = buf.split(b"\n", 1)
            return json.loads(line.decode())
        print("  ready:", recv(5).get("type"))
        send(cfg)
        while True:
            m = recv(20)
            t = m.get("type")
            if t in ("started",):
                print("  started prefix_count=%s" % m.get("prefix_count"))
                continue
            if t == "stats":
                continue
            if t == "found":
                return m
            if t == "error":
                raise RuntimeError("worker error: %s" % m)
        send({"type": "quit"})
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

out = tempfile.gettempdir()

print("== wg test ==")
m = run_search({"type": "start", "search_id": 1, "kind": "wg", "word": "aa",
                "strict": True, "workers": 2, "save": False, "out_dir": out,
                "server": {}})
assert m["kind"] == "wg"
assert m["public_key"].startswith("aa")
print("WG_OK", m["public_key"][:12])

print("== onion test ==")
m = run_search({"type": "start", "search_id": 2, "kind": "onion", "word": "xx",
                "strict": True, "workers": 2, "save": False, "out_dir": out,
                "server": {}})
assert m["kind"] == "onion"
o = m["onion"]
assert len(o) == 56 and o.startswith("xx") and set(o) <= set("abcdefghijklmnopqrstuvwxyz234567")
assert m.get("seed_b64")
print("ONION_OK", o[:14])
print("ALL_OK")
