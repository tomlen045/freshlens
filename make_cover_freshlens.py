#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""freshlens 公众号封面 900x383（PIL 渲染，无 drawtext 转义坑）"""
from PIL import Image, ImageDraw, ImageFont
import os

OUT = os.path.expanduser("~/Desktop/freshlens_cover.png")
W, H = 900, 383
CJK = "/System/Library/Fonts/STHeiti Medium.ttc"

# 渐变底 #0b0e1a → #1a0f2e（135deg 近似：水平+垂直插值）
img = Image.new("RGB", (W, H))
px = img.load()
c0 = (11, 14, 26); c1 = (26, 15, 46)
for y in range(H):
    for x in range(W):
        t = (x / W * 0.5 + y / H * 0.5)
        px[x, y] = tuple(int(c0[i] + (c1[i] - c0[i]) * t) for i in range(3))
d = ImageDraw.Draw(img)

_fc = {}
def F(sz):
    if sz not in _fc:
        _fc[sz] = ImageFont.truetype(CJK, sz)
    return _fc[sz]

GOLD = (240, 180, 41); WHITE = (235, 240, 245); GREY = (139, 148, 158)
RED = (248, 81, 73); DIM = (92, 99, 112)

# 左金竖条（锚住主标题）
d.rectangle([34, 88, 39, 218], fill=GOLD)

# 栏目标签
d.text((48, 36), "小薅薅 · 自研安全工具", font=F(24), fill=GOLD)
d.text((48, 76), "Sentinel Suite · 05", font=F(16), fill=DIM)

# 主钩子（对话形态：白句 + 金句反驳）——第二行 ≤11 字，避让右侧数据区
d.text((52, 108), "告警响了，机器没基线？", font=F(50), fill=WHITE)
d.text((52, 176), "一次扫描，点名坏文件", font=F(50), fill=GOLD)

# 右侧数据区
d.text((636, 96), "12", font=F(64), fill=GOLD)
d.text((700, 118), "类判决", font=F(26), fill=WHITE)
d.text((636, 178), "FJ-01~12", font=F(24), fill=GREY)
d.text((636, 214), "21/21", font=F(40), fill=GOLD)
d.text((724, 226), "自测全绿", font=F(22), fill=WHITE)

# 底部重点行（黑衬底）
d.rectangle([40, 276, 620, 312], fill=(0, 0, 0, 255))
d.text((52, 282), "零依赖 · 单文件 · 只读 · 接 cron 即用", font=F(24), fill=RED)

# 底部信息行
d.text((48, 330), "freshlens · 哨兵套件第五件 · 落地面补齐", font=F(20), fill=GREY)
d.text((48, 356), "gitee.com/tomlen/freshlens", font=F(17), fill=DIM)

img.save(OUT)
print("OK", OUT, os.path.getsize(OUT))
