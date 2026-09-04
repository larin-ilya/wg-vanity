# -*- coding: utf-8 -*-
"""
wg-vanity v3 — вычислительное ядро (worker).

Отдельный процесс, который ищет vanity-ключи WireGuard или красивые
.onion v3 адреса на всех ядрах CPU и общается с GUI (Godot) через
локальный TCP-сервер по простому JSON-lines протоколу.

Запуск (dev):   python wg_worker.py --portfile <путь> --secret <строка>
Запуск (exe):   wg_worker.exe --portfile <путь> --secret <строка>

Worker сам выбирает свободный порт (bind 127.0.0.1:0), пишет номер порта
в файл --portfile, после чего GUI подключается.

Протокол (одна JSON-строка на сообщение, разделитель \n):
  GUI -> worker:
    {"type":"start", "search_id":1, "kind":"wg"|"onion", "word":"cook",
     "strict":false, "workers":8, "save":true, "out_dir":"C:/...",
     "server":{"public_key":"...","endpoint":"vpn.example.com:51820",
               "allowed_ips":"0.0.0.0/0","dns":"1.1.1.1, 8.8.8.8",
               "client_address":"10.0.0.200/32"}}
    {"type":"stop"}
    {"type":"quit"}
  worker -> GUI:
    {"type":"ready"}                     (сразу после подключения)
    {"type":"started","search_id":1,"kind":"wg"|"onion","word":...,
     "strict":...,"workers":N,"prefix_count":K,"base64_len":L,
     "substitutions":n}
    {"type":"stats","search_id":1,"elapsed":s,"checked":N,"speed":n/s,
     "avg":n/s,"peak":n/s,"eta":s|null}
    Для kind="wg":
    {"type":"found","search_id":1,"kind":"wg",
     "prefix":"...","public_key":"...","private_key":"...",
     "checked":N,"elapsed":s,"worker_id":i,
     "files":["имя","имя"...],"qr_png_b64":"..."|null}
    Для kind="onion":
    {"type":"found","search_id":1,"kind":"onion","prefix":"...",
     "onion":"56-символов без .onion","seed_b64":"...",
     "public_key_b64":"...","checked":N,"elapsed":s,"worker_id":i,
     "files":["..."...]}
    {"type":"stopped","search_id":1,"checked":N,"elapsed":s}   (остановлено пользователем)
    {"type":"error","search_id":1|null,"message":"..."}
    {"type":"bye"}
"""
import base64
import hashlib
import json
import multiprocessing as mp
import os
import random
import re
import socket
import sys
import threading
import time
import traceback
from datetime import datetime

try:
    import nacl.bindings
    import nacl.signing
    import nacl.utils
    HAVE_NACL = True
except Exception:  # pragma: no cover
    HAVE_NACL = False

# --------------------------------------------------------------------------
# ДОПУСТИМЫЕ ЗАМЕНЫ СИМВОЛОВ (leet-режим) — как в v1
# --------------------------------------------------------------------------
CHAR_SUBS = {
    "a": ["a", "A", "4"], "b": ["b", "B", "8"], "c": ["c", "C"],
    "d": ["d", "D", "9"], "e": ["e", "E", "3"], "f": ["f", "F"],
    "g": ["g", "G", "9", "6"], "h": ["h", "H"], "i": ["i", "I", "1", "l"],
    "j": ["j", "J"], "k": ["k", "K"], "l": ["l", "L", "1", "I"],
    "m": ["m", "M"], "n": ["n", "N"], "o": ["o", "O", "0"],
    "p": ["p", "P"], "q": ["q", "Q"], "r": ["r", "R"],
    "s": ["s", "S", "5"], "t": ["t", "T", "7", "+"], "u": ["u", "U"],
    "v": ["v", "V"], "w": ["w", "W"], "x": ["x", "X"],
    "y": ["y", "Y"], "z": ["z", "Z", "2"],
    "0": ["0", "O", "o"], "1": ["1", "l", "I", "i"], "2": ["2", "z", "Z"],
    "3": ["3", "e", "E"], "4": ["4", "a", "A"], "5": ["5", "s", "S"],
    "6": ["6", "b", "B", "g", "G"], "7": ["7", "T"], "8": ["8", "B"],
    "9": ["9", "g"],
}
BASE64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

# Tor onion v3: адрес = base32(pubkey[32] + checksum[2] + 0x03)[:56], в нижнем
# регистре, алфавит RFC4648 base32: a-z + 2-7.  Проверка префикса идёт по
# адресу (без ".onion").  ВНИМАНИЕ: алфавит base32 НЕ содержит 0,1,8,9,+/
# и заглавных — только a-z и 2-7, поэтому префикс приводится к нижнему
# регистру, а leet-подстановки ограничены доступными символами.
ONION_CHARS = "abcdefghijklmnopqrstuvwxyz234567"
ONION_CHARSET = set(ONION_CHARS)
ONION_CHECKSUM_PREFIX = b".onion checksum"
ONION_VERSION_BYTE = b"\x03"

# Подстановки для onion (только в рамках алфавита base32).
# "0"->"o", "1"->"l"/"i", "8"->"b", "9"->"g" НЕЛЬЗЯ: таких символов в
# алфавите нет, поэтому заменяем «похожие» на доступные буквы.
ONION_SUBS = {
    "a": ["a", "4"], "b": ["b"], "c": ["c"], "d": ["d"], "e": ["e", "3"],
    "f": ["f"], "g": ["g", "6"], "h": ["h"], "i": ["i", "l"], "j": ["j"],
    "k": ["k"], "l": ["l", "i"], "m": ["m"], "n": ["n"], "o": ["o"],
    "p": ["p"], "q": ["q"], "r": ["r"], "s": ["s", "5"], "t": ["t", "7"],
    "u": ["u"], "v": ["v"], "w": ["w"], "x": ["x"], "y": ["y"], "z": ["z", "2"],
    "2": ["2", "z"], "3": ["3", "e"], "4": ["4", "a"], "5": ["5", "s"],
    "6": ["6", "g"], "7": ["7", "t"],
}


def onion_address_from_pub(pub: bytes) -> str:
    """Возвращает 56-символьный onion v3 адрес (без суффикса .onion)."""
    checksum = hashlib.sha3_256(
        ONION_CHECKSUM_PREFIX + pub + ONION_VERSION_BYTE).digest()[:2]
    raw = pub + checksum + ONION_VERSION_BYTE          # 35 байт
    b32 = base64.b32encode(raw).decode("ascii")        # 56 символов A-Z2-7
    return b32.lower()


def generate_onion_prefixes(word: str, strict: bool):
    """Возвращает (set префиксов onion как bytes, число подстановок)."""
    w = word.strip().lower()
    variants = [""]
    subs = 0
    for ch in w:
        repls = [ch] if strict else ONION_SUBS.get(ch, [ch])
        if len(repls) > 1:
            subs += 1
        variants = [v + r for v in variants for r in repls]
    return {v.encode("ascii") for v in variants}, subs


def onion_first_byte(prefix_bytes: bytes) -> bytes:
    """Для onion-префикса первый байт в UTF-8 = первая буква адреса."""
    return prefix_bytes[:1]


def generate_prefixes(word: str, strict: bool):
    """Возвращает (set префиксов как bytes, число подстановок)."""
    variants = [""]
    subs = 0
    for ch in word:
        repls = [ch] if strict else CHAR_SUBS.get(ch, [ch])
        if len(repls) > 1:
            subs += 1
        variants = [v + r for v in variants for r in repls]
    return {v.encode("utf-8") for v in variants}, subs


def build_groups(prefixes):
    """Группировка префиксов по первому байту: ускоряет проверку."""
    groups = {}
    for p in prefixes:
        groups.setdefault(p[:1], []).append(p)
    return groups


# --------------------------------------------------------------------------
# Дочерний процесс-поисковик (только криптография + счётчик)
# --------------------------------------------------------------------------
def search_worker(worker_id, groups, first_bytes, stop_event, found_event,
                  counter, result_queue):
    """Крутит пары ключей, пока не найдёт совпадение или не остановят."""
    keys_checked = 0
    try:
        firsts = set(first_bytes)
        while not stop_event.is_set() and not found_event.is_set():
            priv = nacl.utils.random(32)
            pub = nacl.bindings.crypto_scalarmult_base(priv)
            pub_b64 = base64.b64encode(pub)
            keys_checked += 1
            if keys_checked % 1000 == 0:
                with counter.get_lock():
                    counter.value += 1000
            if pub_b64[:1] in firsts:
                for prefix in groups.get(pub_b64[:1], ()):
                    if pub_b64.startswith(prefix):
                        if not found_event.is_set():
                            found_event.set()
                            result_queue.put({
                                "private_key": base64.b64encode(priv).decode(),
                                "public_key": pub_b64.decode(),
                                "prefix": prefix.decode(),
                                "worker_id": worker_id,
                                "keys_checked": keys_checked,
                                "timestamp": datetime.now().isoformat(
                                    timespec="seconds"),
                            })
                        return
    except Exception as e:  # pragma: no cover
        try:
            result_queue.put({"error": "search_worker: %s" % e})
        except Exception:
            pass
    finally:
        with counter.get_lock():
            counter.value += keys_checked % 1000


def search_worker_onion(worker_id, groups, first_bytes, stop_event,
                        found_event, counter, result_queue):
    """Ищет onion v3: крутит ed25519-пары, считает 56-символьный адрес
    и проверяет префикс по алфавиту a-z2-7 (как mkp224o)."""
    keys_checked = 0
    try:
        firsts = set(first_bytes)
        while not stop_event.is_set() and not found_event.is_set():
            seed = nacl.utils.random(32)
            sk = nacl.signing.SigningKey(seed)
            pub = sk.verify_key.encode()          # 32 байта ed25519
            addr = onion_address_from_pub(pub)    # 56 символов a-z2-7
            keys_checked += 1
            if keys_checked % 1000 == 0:
                with counter.get_lock():
                    counter.value += 1000
            # ищем по первому символу адреса (байт ASCII = латиница)
            first_ch = addr[:1].encode("ascii")
            if first_ch in firsts:
                for prefix in groups.get(first_ch, ()):
                    if addr.startswith(prefix.decode("ascii")):
                        if not found_event.is_set():
                            found_event.set()
                            result_queue.put({
                                "seed_b64": base64.b64encode(seed).decode(),
                                "public_key_b64": base64.b64encode(pub).decode(),
                                "onion": addr,
                                "prefix": prefix.decode("ascii"),
                                "worker_id": worker_id,
                                "keys_checked": keys_checked,
                                "timestamp": datetime.now().isoformat(
                                    timespec="seconds"),
                            })
                        return
    except Exception as e:  # pragma: no cover
        try:
            result_queue.put({"error": "search_worker_onion: %s" % e})
        except Exception:
            pass
    finally:
        with counter.get_lock():
            counter.value += keys_checked % 1000


# --------------------------------------------------------------------------
# Служебные функции сохранения результатов (выполняются в родительском
# процессе worker'а, не в поисковых детях)
# --------------------------------------------------------------------------
def sanitize(name):
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', name) or "key"


def build_conf_text(result, server):
    c = [
        "[Interface]",
        "PrivateKey = %s" % result["private_key"],
        "Address = %s" % server.get("client_address", "10.0.0.2/32"),
        "DNS = %s" % server.get("dns", "1.1.1.1, 8.8.8.8"),
        "",
        "[Peer]",
        "PublicKey = %s" % server.get("public_key", ""),
        "Endpoint = %s" % server.get("endpoint", ""),
        "AllowedIPs = %s" % server.get("allowed_ips", "0.0.0.0/0"),
        "PersistentKeepalive = 25",
    ]
    return "\n".join(c)


def build_qr_data(result, server):
    return "\n".join([
        "[Interface]",
        "PrivateKey = %s" % result["private_key"],
        "Address = %s" % server.get("client_address", "10.0.0.2/32"),
        "DNS = %s" % server.get("dns", "1.1.1.1, 8.8.8.8"),
        "",
        "[Peer]",
        "PublicKey = %s" % server.get("public_key", ""),
        "Endpoint = %s" % server.get("endpoint", ""),
        "AllowedIPs = %s" % server.get("allowed_ips", "0.0.0.0/0"),
        "PersistentKeepalive = 25",
    ])


def save_results(result, word, strict, server, out_dir):
    """Сохраняет .conf / _keys.txt / _qr.png / лог. Возвращает имена файлов."""
    created = []
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix_s = sanitize(result["prefix"])
    word_s = sanitize(word)
    base = "wg_%s_%s_%s" % (word_s, prefix_s, ts)

    os.makedirs(out_dir, exist_ok=True)

    # 1) .conf
    conf_name = base + ".conf"
    try:
        with open(os.path.join(out_dir, conf_name), "w", encoding="utf-8") as f:
            f.write(build_conf_text(result, server) + "\n")
        created.append(conf_name)
    except Exception:
        pass

    # 2) _keys.txt
    keys_name = base + "_keys.txt"
    try:
        with open(os.path.join(out_dir, keys_name), "w", encoding="utf-8") as f:
            f.write("WireGuard ключи — %s\n" % word)
            f.write("Префикс: %s\n" % result["prefix"])
            f.write("Дата: %s\n" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            f.write("Режим: %s\n" % ("СТРОГИЙ" if strict else "ОБЫЧНЫЙ"))
            f.write("=" * 60 + "\n")
            f.write("Публичный ключ клиента:\n%s\n\n" % result["public_key"])
            f.write("Приватный ключ клиента:\n%s\n\n" % result["private_key"])
            f.write("Публичный ключ сервера:\n%s\n" % server.get("public_key", ""))
            f.write("=" * 60 + "\n")
            f.write("Endpoint: %s\n" % server.get("endpoint", ""))
            f.write("Адрес клиента: %s\n" % server.get("client_address", ""))
            f.write("AllowedIPs: %s\n" % server.get("allowed_ips", ""))
            f.write("DNS: %s\n" % server.get("dns", ""))
        created.append(keys_name)
    except Exception:
        pass

    # 3) QR-код (PIL) — цветной, с подписью wg:<prefix>
    qr_b64 = None
    try:
        import qrcode
        from PIL import Image, ImageDraw, ImageFont
        import colorsys

        qr_data = build_qr_data(result, server)
        qr = qrcode.QRCode(version=None,
                           error_correction=qrcode.constants.ERROR_CORRECT_M,
                           box_size=10, border=4)
        qr.add_data(qr_data)
        qr.make(fit=True)

        h = random.random()
        s = random.uniform(0.7, 1.0)
        v = random.uniform(0.25, 0.55)
        r, g, b = colorsys.hsv_to_rgb(h, s, v)
        fill_color = (int(r * 255), int(g * 255), int(b * 255))

        img = qr.make_image(fill_color=fill_color, back_color="white").convert("RGB")
        draw = ImageDraw.Draw(img)

        font = None
        for fn in ("arial.ttf", "arialbd.ttf", "segoeuib.ttf", "segoeui.ttf"):
            try:
                font = ImageFont.truetype(fn, 28)
                break
            except Exception:
                continue
        text = "wg:%s" % result["prefix"]
        if font is None:
            font = ImageFont.load_default()
        try:
            bbox = draw.textbbox((0, 0), text, font=font)
            tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        except Exception:
            tw, th = len(text) * 16, 24
        w, hh = img.size
        pad = 8
        tx = (w - tw) // 2
        ty = hh - th - 20
        draw.rectangle([tx - pad, ty - pad, tx + tw + pad, ty + th + pad],
                       fill=(255, 255, 255))
        draw.text((tx, ty), text, font=font, fill=fill_color)

        qr_name = base + "_qr.png"
        img.save(os.path.join(out_dir, qr_name))
        created.append(qr_name)

        import io
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
    except Exception:
        qr_b64 = None

    # 4) Общий лог
    log_name = "wg_keys_log.txt"
    try:
        exists = os.path.exists(os.path.join(out_dir, log_name))
        with open(os.path.join(out_dir, log_name), "a", encoding="utf-8") as f:
            if not exists:
                f.write("=" * 80 + "\n")
                f.write("ЛОГ НАЙДЕННЫХ КЛЮЧЕЙ WIREGUARD\n")
                f.write("Создан: %s\n" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                f.write("=" * 80 + "\n\n")
            f.write("[%s]\n" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            f.write("Слово: %s\n" % word)
            f.write("Режим: %s\n" % ("СТРОГИЙ" if strict else "ОБЫЧНЫЙ"))
            f.write("Префикс: %s\n" % result["prefix"])
            f.write("Публичный ключ:  %s\n" % result["public_key"])
            f.write("Приватный ключ:  %s\n" % result["private_key"])
            f.write("Процесс: %s | Проверено: %s\n"
                    % (result.get("worker_id"), result.get("keys_checked")))
            f.write("-" * 80 + "\n\n")
        created.append(log_name)
    except Exception:
        pass

    return created, qr_b64


def save_onion_results(result, word, strict, out_dir):
    """Сохраняет результат onion v3 в формате, который примет Tor:
    подпапка <onion>.onion/ с hostname, hs_ed25519_public_key,
    hs_ed25519_secret_key + читаемый .txt и общий лог.
    Возвращает список созданных файлов (относительно out_dir)."""
    created = []
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    word_s = sanitize(word)
    prefix_s = sanitize(result["prefix"])
    onion = result["onion"]                 # 56 символов без ".onion"
    onion_domain = onion + ".onion"
    svc_dir = os.path.join(out_dir, onion_domain)
    os.makedirs(svc_dir, exist_ok=True)

    # 1) hostname
    try:
        with open(os.path.join(svc_dir, "hostname"), "wb") as f:
            f.write((onion_domain + "\n").encode("utf-8"))
        created.append(os.path.join(onion_domain, "hostname"))
    except Exception:
        pass

    # 2) hs_ed25519_public_key (raw 32 байта)
    pub = base64.b64decode(result["public_key_b64"])
    try:
        with open(os.path.join(svc_dir, "hs_ed25519_public_key"), "wb") as f:
            f.write(pub)
        created.append(os.path.join(onion_domain, "hs_ed25519_public_key"))
    except Exception:
        pass

    # 3) hs_ed25519_secret_key — seed[32] || pub[32] (64 байта)
    seed = base64.b64decode(result["seed_b64"])
    try:
        with open(os.path.join(svc_dir, "hs_ed25519_secret_key"), "wb") as f:
            f.write(seed + pub)
        created.append(os.path.join(onion_domain, "hs_ed25519_secret_key"))
    except Exception:
        pass

    # 4) читаемый .txt
    txt_name = "onion_%s_%s_%s.txt" % (word_s, prefix_s, ts)
    try:
        with open(os.path.join(out_dir, txt_name), "w", encoding="utf-8") as f:
            f.write("Tor onion v3 адрес (vanity) — %s\n" % word)
            f.write("=" * 70 + "\n")
            f.write("Адрес: %s\n" % onion_domain)
            f.write("Префикс: %s\n" % result["prefix"])
            f.write("Дата: %s\n" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            f.write("Режим: %s\n" % ("СТРОГИЙ" if strict else "ОБЫЧНЫЙ"))
            f.write("=" * 70 + "\n")
            f.write("seed (base64, 32 байта):\n%s\n\n" % result["seed_b64"])
            f.write("публичный ключ (base64, 32 байта):\n%s\n\n"
                    % result["public_key_b64"])
            f.write("Как использовать:\n")
            f.write("1) Установите Tor (>=0.4) и настройте onion-сервис.\n")
            f.write("2) В файле torrc укажите HiddenServiceDir на папку:\n")
            f.write("   %s\n" % os.path.abspath(svc_dir))
            f.write("3) Перезапустите Tor — он подхватит ключи из папки.\n")
        created.append(txt_name)
    except Exception:
        pass

    # 5) общий лог
    log_name = "onion_keys_log.txt"
    try:
        exists = os.path.exists(os.path.join(out_dir, log_name))
        with open(os.path.join(out_dir, log_name), "a", encoding="utf-8") as f:
            if not exists:
                f.write("=" * 80 + "\n")
                f.write("ЛОГ НАЙДЕННЫХ ONION V3 АДРЕСОВ\n")
                f.write("Создан: %s\n" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                f.write("=" * 80 + "\n\n")
            f.write("[%s]\n" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            f.write("Слово: %s\n" % word)
            f.write("Режим: %s\n" % ("СТРОГИЙ" if strict else "ОБЫЧНЫЙ"))
            f.write("Адрес: %s\n" % onion_domain)
            f.write("Папка ключей: %s\n" % os.path.abspath(svc_dir))
            f.write("Процесс: %s | Проверено: %s\n"
                    % (result.get("worker_id"), result.get("keys_checked")))
            f.write("-" * 80 + "\n\n")
        created.append(log_name)
    except Exception:
        pass

    return created


# --------------------------------------------------------------------------
# TCP-сервер
# --------------------------------------------------------------------------
class SearchSession:
    def __init__(self, msg, search_id):
        self.search_id = search_id
        self.kind = str(msg.get("kind", "wg"))          # "wg" | "onion"
        self.word = msg.get("word", "")
        self.strict = bool(msg.get("strict", False))
        self.save = bool(msg.get("save", False))
        self.out_dir = msg.get("out_dir") or os.getcwd()
        self.server = msg.get("server") or {}
        self.workers = max(1, min(int(msg.get("workers", 1)),
                                  os.cpu_count() or 1))
        self.stop_event = mp.Event()
        self.found_event = mp.Event()
        self.counter = mp.Value("Q", 0)
        self.result_queue = mp.Queue()
        self.processes = []
        self.groups = {}
        self.first_bytes = []
        self.substitutions = 0
        self.prefix_count = 0

    def start(self):
        if self.kind == "onion":
            prefixes, self.substitutions = generate_onion_prefixes(
                self.word, self.strict)
            target = search_worker_onion
        else:
            prefixes, self.substitutions = generate_prefixes(
                self.word, self.strict)
            target = search_worker
        self.prefix_count = len(prefixes)
        self.groups = build_groups(prefixes)
        self.first_bytes = list(self.groups.keys())
        for i in range(self.workers):
            p = mp.Process(target=target,
                           args=(i + 1, self.groups, self.first_bytes,
                                 self.stop_event, self.found_event,
                                 self.counter, self.result_queue),
                           daemon=True)
            p.start()
            self.processes.append(p)
        return {
            "kind": self.kind,
            "prefix_count": self.prefix_count,
            "substitutions": self.substitutions,
            "workers": self.workers,
        }

    def stop(self):
        self.stop_event.set()
        for p in self.processes:
            if p.is_alive():
                p.terminate()
        for p in self.processes:
            p.join(timeout=2)

    def cleanup(self):
        self.stop()


class WorkerServer:
    def __init__(self, secret):
        self.secret = secret
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.conn = None
        self.session = None
        self.session_start = None
        self.last_stats_send = 0.0
        self.stats_lock = threading.Lock()
        self._stats_thread = None
        self._checked_snapshot = 0
        self.peak_speed = 0

    # -- helpers ---------------------------------------------------------
    def send(self, obj):
        if self.conn is None:
            return False
        try:
            self.conn.sendall((json.dumps(obj, ensure_ascii=False) + "\n")
                              .encode("utf-8"))
            return True
        except Exception:
            return False

    def read_line(self):
        """Блокирующее чтение одной строки с таймаутом на сокете."""
        try:
            data = self.conn.recv(1 << 20)
        except socket.timeout:
            return None
        except Exception:
            return b""
        if not data:
            return b""
        # накапливаем до перевода строки (сообщения worker'а малы)
        self._buf += data
        if b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            return line
        return None

    # -- stats thread ----------------------------------------------------
    def _stats_loop(self):
        while True:
            with self.stats_lock:
                if self.session is None:
                    return
                if self.conn is None:
                    return
                sess = self.session
            try:
                with sess.counter.get_lock():
                    checked = sess.counter.value
            except Exception:
                return
            elapsed = time.time() - self.session_start
            delta = checked - self._checked_snapshot
            dt = max(0.001, elapsed - self.last_stats_send)
            speed = delta / dt
            if speed > self.peak_speed:
                self.peak_speed = speed
            self._checked_snapshot = checked
            avg = checked / elapsed if elapsed > 0 else 0
            self.last_stats_send = elapsed
            # мягкая ETA: ожидаемое число ключей = N^len / кол-во префиксов
            # где N — размер алфавита: 64 для base64 wg, 32 для onion.
            eta = None
            if avg > 0 and sess.prefix_count:
                L = len(sess.word)
                alphabet = 32 if sess.kind == "onion" else 64
                expected = (alphabet ** L) / sess.prefix_count
                remain = max(0.0, expected - checked)
                eta = remain / avg
            if not self.send({
                "type": "stats", "search_id": sess.search_id,
                "elapsed": round(elapsed, 2), "checked": checked,
                "speed": round(speed), "avg": round(avg), "peak": round(self.peak_speed),
                "eta": round(eta) if eta else None,
            }):
                return
            time.sleep(0.5)

    # -- dispatch ---------------------------------------------------------
    def handle_start(self, msg):
        if self.session is not None:
            self.send({"type": "error", "message": "Поиск уже запущен"})
            return
        sid = msg.get("search_id", 1)
        kind = str(msg.get("kind", "wg"))
        if kind not in ("wg", "onion"):
            self.send({"type": "error", "search_id": sid,
                       "message": "Неизвестный режим: %s" % kind})
            return
        word = str(msg.get("word", "")).strip()
        if not word:
            self.send({"type": "error", "search_id": sid,
                       "message": "Слово не может быть пустым"})
            return
        if kind == "onion":
            word = word.lower()
            bad = [c for c in word if c not in ONION_CHARSET]
            if bad:
                self.send({"type": "error", "search_id": sid,
                           "message": "Для .onion можно только a-z и 2-7: %s"
                                      % " ".join(bad)})
                return
            if len(word) > 55:
                self.send({"type": "error", "search_id": sid,
                           "message": "Слишком длинный префикс (максимум 55)"})
                return
        else:
            bad = [c for c in word if c not in BASE64_CHARS]
            if bad:
                self.send({"type": "error", "search_id": sid,
                           "message": "Недопустимые символы: %s (можно только A-Z a-z 0-9 + /)"
                                      % " ".join(bad)})
                return
            if len(word) > 34:
                self.send({"type": "error", "search_id": sid,
                           "message": "Слово слишком длинное (максимум 34 символа)"})
                return
        sess = SearchSession(msg, sid)
        try:
            meta = sess.start()
        except Exception as e:
            self.send({"type": "error", "search_id": sid,
                       "message": "Ошибка запуска: %s" % e})
            return
        self.session = sess
        self.session_start = time.time()
        self.last_stats_send = 0.0
        self._checked_snapshot = 0
        self.peak_speed = 0
        self.send({"type": "started", "search_id": sid, "word": word,
                   "kind": sess.kind, "strict": sess.strict,
                   "workers": sess.workers,
                   "prefix_count": meta["prefix_count"],
                   "substitutions": meta["substitutions"]})
        self._stats_thread = threading.Thread(target=self._stats_loop,
                                              daemon=True)
        self._stats_thread.start()

    def handle_stop(self):
        sid = self.session.search_id if self.session else None
        if self.session is not None:
            checked = self._finalize()
            self.send({"type": "stopped", "search_id": sid, "checked": checked,
                       "elapsed": round(time.time() - self.session_start, 2)})
        else:
            self.send({"type": "stopped", "search_id": sid, "checked": 0,
                       "elapsed": 0})

    def _finalize(self):
        sess = self.session
        if sess is None:
            return 0
        sess.stop()
        try:
            with sess.counter.get_lock():
                checked = sess.counter.value
        except Exception:
            checked = 0
        self.session = None
        return checked

    def handle_found(self):
        sess = self.session
        if sess is None:
            return
        try:
            res = sess.result_queue.get_nowait()
        except Exception:
            return
        if "error" in res:
            self.send({"type": "error", "search_id": sess.search_id,
                       "message": res["error"]})
            return
        checked = self._finalize()
        elapsed = time.time() - self.session_start
        files, qr_b64 = [], None
        if sess.save:
            try:
                if sess.kind == "onion":
                    files = save_onion_results(res, sess.word, sess.strict,
                                               sess.out_dir)
                else:
                    files, qr_b64 = save_results(res, sess.word, sess.strict,
                                                 sess.server, sess.out_dir)
            except Exception as e:
                traceback.print_exc()
        if sess.kind == "onion":
            self.send({
                "type": "found", "search_id": sess.search_id, "kind": "onion",
                "prefix": res["prefix"], "onion": res["onion"],
                "seed_b64": res["seed_b64"],
                "public_key_b64": res["public_key_b64"],
                "checked": checked, "elapsed": round(elapsed, 2),
                "worker_id": res["worker_id"], "files": files,
                "qr_png_b64": None,
            })
        else:
            self.send({
                "type": "found", "search_id": sess.search_id, "kind": "wg",
                "prefix": res["prefix"], "public_key": res["public_key"],
                "private_key": res["private_key"], "checked": checked,
                "elapsed": round(elapsed, 2), "worker_id": res["worker_id"],
                "files": files, "qr_png_b64": qr_b64,
            })

    # -- main loop --------------------------------------------------------
    def serve(self):
        self.sock.listen(1)
        self._buf = b""
        while True:
            try:
                conn, _ = self.sock.accept()
            except Exception:
                break
            conn.settimeout(0.15)
            self.conn = conn
            self.send({"type": "ready"})
            try:
                while True:
                    line = self.read_line()
                    if line is None:
                        # по таймауту — проверяем результат/стоп
                        if self.session is not None:
                            if self.session.found_event.is_set():
                                self.handle_found()
                        continue
                    if line == b"":
                        break  # клиент отключился
                    try:
                        msg = json.loads(line.decode("utf-8"))
                    except Exception:
                        continue
                    mtype = msg.get("type")
                    if mtype == "start":
                        self.handle_start(msg)
                    elif mtype == "stop":
                        self.handle_stop()
                    elif mtype == "quit":
                        if self.session is not None:
                            self._finalize()
                        self.send({"type": "bye"})
                        try:
                            conn.close()
                        except Exception:
                            pass
                        self.conn = None
                        return
            except Exception:
                traceback.print_exc()
            finally:
                if self.session is not None:
                    self._finalize()
                try:
                    conn.close()
                except Exception:
                    pass
                self.conn = None
            # цикл продолжается — ждём нового клиента


def main():
    mp.freeze_support()
    args = [a for a in sys.argv[1:]]
    portfile = None
    pidfile = None
    secret = ""
    if "--portfile" in args:
        portfile = args[args.index("--portfile") + 1]
    if "--pidfile" in args:
        pidfile = args[args.index("--pidfile") + 1]
    if "--secret" in args:
        secret = args[args.index("--secret") + 1]

    if not HAVE_NACL:
        # простое сообщение в консоль (при --noconsole не видно)
        try:
            sys.stderr.write("wg-vanity: PyNaCl недоступен\n")
        except Exception:
            pass

    if pidfile:
        try:
            with open(pidfile, "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))
        except Exception:
            pass

    srv = WorkerServer(secret)
    if portfile:
        try:
            with open(portfile, "w", encoding="utf-8") as f:
                f.write(str(srv.port))
        except Exception:
            pass
    srv.serve()


if __name__ == "__main__":
    main()
