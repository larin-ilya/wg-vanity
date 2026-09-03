# -*- coding: utf-8 -*-
"""Генератор чиптюн-лупа в стиле старых демо (MOD/tracker).
Синтез на чистом Python со wavetables. Выход: 16-bit моно WAV ~22 кГц."""
import math
import wave
import os
import struct
import sys

SR = 22050

# --- волны ---------------------------------------------------------------
def make_square(freq):
    period = SR / freq
    table = [1.0 if i < period / 2 else -1.0 for i in range(int(period))]
    return table

def make_tri(freq, depth=0.8):
    period = SR / freq
    n = int(period)
    table = []
    for i in range(n):
        ph = (i / period) * 2 - 1  # -1..1
        table.append(depth * (1.0 - abs(ph) * 2))
    return table

# --- композиция ----------------------------------------------------------
# Тонкая сетка 16-х нот; bpm ~ 144 => одна 16-я = 60/144/4 сек
NOTE = 60.0 / 144.0 / 4.0

# Ноты: (частота, длительность_в_16х, accent)
# Басы (квадрат, октава низкая)
bass = [
    (110.0, 4), (110.0, 4), (130.81, 4), (146.83, 4),
    (110.0, 4), (110.0, 4), (98.0, 4), (87.31, 4),
    (110.0, 4), (110.0, 4), (130.81, 4), (146.83, 4),
    (123.47, 6), (98.0, 2), (87.31, 8),
]

# Лед-мелодия (треугольник)
lead = [
    (0, 1), (440.0, 1), (0, 1), (523.25, 1),
    (587.33, 2), (523.25, 1), (440.0, 1), (0, 1),
    (349.23, 2), (392.0, 1), (440.0, 1), (0, 1),
    (523.25, 2), (587.33, 1), (659.25, 2),
    (0, 2), (587.33, 2), (523.25, 2),
    (440.0, 2), (392.0, 2), (330.0, 2),
]
# арп-контр (квадрат, высоко, быстрый) на 16-х
arp = [
    (220.0,1),(277.18,1),(329.63,1),(277.18,1),
    (220.0,1),(277.18,1),(329.63,1),(277.18,1),
    (196.0,1),(246.94,1),(293.66,1),(246.94,1),
    (174.61,1),(220.0,1),(261.63,1),(220.0,1),
    (220.0,1),(277.18,1),(329.63,1),(277.18,1),
    (196.0,1),(246.94,1),(293.66,1),(246.94,1),
    (246.94,1),(311.13,1),(369.99,1),(311.13,1),
    (220.0,1),(277.18,1),(329.63,1),(277.18,1),
]
# Ударные: (наступ. ли = 1, открытый хэт), длительность в 16-х
drums = [  # [bassdrum], [snare], [hat], длительность 16-х saming layout
]

def build_bass():
    out = []
    for f, d in bass:
        t = make_square(f)
        out.append((t, d))
    return out

def build_lead():
    out = []
    for f, d in lead:
        t = make_tri(f) if f else None
        out.append((t, d))
    return out

def build_arp():
    out = []
    for f, d in arp:
        t = make_square(f) if f else None
        out.append((t, d))
    return out

def build_drums(total_steps):
    fill = []
    for step in range(total_steps):
        bd = 1 if step % 16 == 0 else 0
        sn = 1 if step % 8 == 4 or step % 8 == 6 else 0
        ht = 1 if step % 2 == 0 else 0
        fill.append((bd, sn, ht, 1))
    return fill

def synth():
    total_steps = 0
    for _, d in bass:
        total_steps += d
    n = int(total_steps * NOTE * SR)
    buf = [0.0] * n

    def mix(seq, gain, filter_dc=True):
        pos = 0
        for item in seq:
            t, d = item[0], item[1]
            if pos >= n:
                break
            ln = int(min(d * NOTE * SR, n - pos))
            if t:
                tl = len(t)
                for i in range(ln):
                    buf[pos + i] += t[(pos + i) % tl] * gain
            pos += ln

    def mix_drums():
        # хэты — шум с быстрым затуханием
        import random
        rnd = random.Random(7)
        pos = 0
        beat_n = int(NOTE * SR)
        for (bd, sn, ht, d) in build_drums(total_steps):
            if pos >= n:
                break
            ln = int(d * NOTE * SR)
            if bd:
                # бас-барабан
                dur = int(0.09 * SR)
                for i in range(min(dur, ln)):
                    f = 120.0 * math.exp(-i * 13.0 / SR)
                    ph = (i / (SR / f)) % 1.0
                    buf[pos + i] += math.sin(2 * math.pi * ph) * 0.9 * math.exp(-i * 6.0 / SR)
            if sn:
                dur = int(0.11 * SR)
                for i in range(min(dur, ln)):
                    b = rnd.random() * 2 - 1
                    env = math.exp(-i * 22.0 / SR)
                    buf[pos + i] += b * 0.45 * env
                    if i < dur * 0.5:
                        buf[pos + i] += make_square(220)[(pos + i) % len(make_square(220))] * 0.18 * env
            if ht:
                dur = int(0.04 * SR)
                for i in range(min(dur, ln)):
                    b = rnd.random() * 2 - 1
                    buf[pos + i] += b * 0.30 * math.exp(-i * 55.0 / SR)
            pos += ln

    mix(build_bass(), 0.42)
    mix(build_lead(), 0.30)
    mix(build_arp(), 0.16)
    mix_drums()

    # нормализация + мягкий limiter
    peak = max(max(x, -x) for x in buf)
    g = 0.9 / peak if peak > 0.9 else 1.0
    pcm = bytearray()
    for x in buf:
        v = int(max(-1.0, min(1.0, x * g)) * 32767)
        pcm += struct.pack("<h", v)
    return bytes(pcm), n

def main():
    # путь можно передать аргументом, иначе — рядом со скриптом
    here = os.path.dirname(os.path.abspath(__file__))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "tracker_loop.wav")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    pcm, n = synth()
    with wave.open(out, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(pcm)
    print("OK wrote", out, "dur=%.1fs" % (n / SR), "samples=", n)

if __name__ == "__main__":
    main()
