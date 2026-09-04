# -*- coding: utf-8 -*-
"""Собирает многоразмерный icon.ico из icon.png (16..256 px)."""
from PIL import Image
import os

png = r"D:\AI-PROjects\TEST\wg-vanity\gui\assets\icon.png"
ico = r"D:\AI-PROjects\TEST\wg-vanity\gui\assets\icon.ico"

img = Image.open(png).convert("RGBA")
print("source", img.size)
# квадрат
w, h = img.size
side = min(w, h)
img = img.crop(((w - side) // 2, (h - side) // 2,
                (w + side) // 2, (h + side) // 2))
sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
img.save(ico, format="ICO", sizes=sizes)
print("wrote", ico, os.path.getsize(ico), "bytes")
