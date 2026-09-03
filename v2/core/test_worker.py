# -*- coding: utf-8 -*-
"""Интеграционный тест wg_worker: поднимает worker, ищет короткий префикс,
проверяет found + сохранённые файлы. Выход 0 = успех."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

PY = sys.executable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKER = os.path.join(ROOT, "core", "wg_worker.py")
PYLIBS = os.path.join(ROOT, "pylibs")

def wait_portfile(path, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return int(f.read().strip())
            except Exception:
                pass
        time.sleep(0.1)
    raise RuntimeError("portfile not created")

def recv_json(sock):
    buf = b""
    sock.settimeout(15)
    while b"\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("closed")
        buf += chunk
    line, _ = buf.split(b"\n", 1)
    return json.loads(line)

def main():
    tmp = tempfile.mkdtemp(prefix="wgtest_")
    portfile = os.path.join(tmp, "port.txt")
    env = dict(os.environ)
    env["PYTHONPATH"] = PYLIBS
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.Popen(
        [PY, WORKER, "--portfile", portfile, "--secret", "test"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        port = wait_portfile(portfile)
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        sock.settimeout(15)
        ready = recv_json(sock)
        print("ready:", ready)
        assert ready["type"] == "ready"

        msg = {
            "type": "start",
            "search_id": 1,
            "word": "ab",
            "strict": False,
            "workers": 4,
            "save": True,
            "out_dir": tmp,
            "server": {
                "public_key": "SERVERPUBLICKEYTESTTESTTESTTESTTESTTESTTESTTE=",
                "endpoint": "vpn.example.com:51820",
                "allowed_ips": "0.0.0.0/0",
                "dns": "1.1.1.1, 8.8.8.8",
                "client_address": "10.0.0.200/32",
            },
        }
        sock.sendall((json.dumps(msg) + "\n").encode())

        got_started = False
        got_found = None
        stats_seen = 0
        t0 = time.time()
        while time.time() - t0 < 60:
            m = recv_json(sock)
            if m["type"] == "started":
                got_started = True
                print("started:", {k: m[k] for k in ("prefix_count", "workers", "substitutions")})
            elif m["type"] == "stats":
                stats_seen += 1
            elif m["type"] == "found":
                got_found = m
                print("FOUND prefix=%s checked=%s files=%s" % (m["prefix"], m["checked"], m["files"]))
                print("has qr b64:", bool(m.get("qr_png_b64")))
                break
            elif m["type"] == "error":
                raise RuntimeError("worker error: " + m["message"])
        assert got_started, "never started"
        assert got_found, "not found in time"
        files = got_found["files"]
        for fn in files:
            p = os.path.join(tmp, fn)
            assert os.path.exists(p), "missing " + fn
            print("  file ok:", fn, os.path.getsize(p))
        assert any(fn.endswith(".conf") for fn in files)
        assert any(fn.endswith("_qr.png") for fn in files)
        print("stats events:", stats_seen)
        print("TEST PASS")
        return 0
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

if __name__ == "__main__":
    sys.exit(main())
