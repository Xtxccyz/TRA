#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""加密字符串自动定位器 —— 扫描 PE 自动找 CR-013 加密字符串并解密。

纯标准库。解决「seed 和密文散落在 .text，需 IDA 手工定位」的痛点。

用法：
    from scan import scan_cr013_strings
    hits = scan_cr013_strings(open('sample.exe', 'rb').read())
    for h in hits:
        print(hex(h['seed']), repr(h['plaintext']))

原理（10_108.exe 实测，DiBa 内嵌驱动）：
  - 密文：栈数组逐字初始化 `mov eax, imm16`(B8) + `mov [ebp+disp], ax`(89 45)，
    imm16 为负数（bit15=1，加密时 `| 0x8000` 造成）。同一字符串的密文 word
    物理上连续（相邻 B8 间隔 ≤ max_gap 字节）。
  - seed：`push imm32`(68) 传给解密函数，紧随密文序列之后（同函数内）。
  - 解密：word ^= (seed>>16)|0x8000，seed = 0x19660D*seed + 0x3C6EF35F
    （即 crypto.cr013_nr_decrypt 宽字符变体）。
"""

from __future__ import annotations

import struct

from constants import CR013_NR_MULT, CR013_NR_ADD
from crypto import cr013_nr_decrypt


# ============================================================================
# 提取：负 word 密文序列 + seed 候选
# ============================================================================

def _neg_word_runs(data: bytes, min_len: int = 4, max_gap: int = 8):
    """提取 .text 中「负 16-bit word 连续 run」。

    模式：B8 ?? ??（mov eax, imm16，imm16 负数）。相邻 B8 间隔 ≤ max_gap 字节
    视为同一字符串的密文。返回 [(start_offset, [word, ...]), ...]，offset 相对 data。
    """
    runs = []
    cur = []
    cur_start = None
    prev_end = None
    i = 0
    n = len(data)
    while i < n - 2:
        if data[i] == 0xB8:
            w = data[i + 1] | (data[i + 2] << 8)
            if w & 0x8000:  # 负数 word（bit15 置位）
                if prev_end is not None and cur_start is not None and i - prev_end <= max_gap:
                    cur.append(w)
                else:
                    if len(cur) >= min_len:
                        runs.append((cur_start, cur))
                    cur = [w]
                    cur_start = i
                prev_end = i + 3
                i += 3
                continue
        i += 1
    if len(cur) >= min_len:
        runs.append((cur_start, cur))
    return runs


def _seed_candidates(data: bytes) -> list[int]:
    """提取 push imm32（68 ?? ?? ?? ??）立即数作为 seed 候选（去重）。"""
    seeds = []
    i = 0
    n = len(data)
    while i < n - 4:
        if data[i] == 0x68:
            seeds.append(struct.unpack_from('<I', data, i + 1)[0])
        i += 1
    return sorted(set(seeds))


# ============================================================================
# 可读性判断
# ============================================================================

def _readable_utf16(plain: bytes) -> str | None:
    """判断解密结果是否为可读 UTF-16 字符串，返回 str 或 None。"""
    if not plain or len(plain) < 8:
        return None
    try:
        txt = plain.decode('utf-16le')
    except UnicodeDecodeError:
        return None
    txt = txt.rstrip('\x00')
    if len(txt) < 4:
        return None
    # DiBa 字符串均为 ASCII（注册表路径 / API 名 / 服务名），要求全部字符
    # 落在可打印 ASCII（0x20-0x7E），过滤解密出的非 ASCII 假阳性。
    if not all(0x20 <= ord(c) <= 0x7E for c in txt):
        return None
    alnum = sum(1 for c in txt if c.isalnum() or c in '\\/.:_- ')
    if alnum / len(txt) < 0.5:
        return None
    return txt


# ============================================================================
# 主入口
# ============================================================================

def scan_cr013_strings(pe_bytes: bytes, min_len: int = 4) -> list[dict]:
    """扫描 PE 找 CR-013 加密字符串并自动解密。

    返回 [{seed, plaintext, words, offset}, ...]，offset 为密文序列的文件偏移。
    配对策略：密文 run × seed 候选 全配对，用 UTF-16 可读性过滤假阳性。
    """
    from pe_tools import _sections  # 局部 import，避免模块循环

    text_roff = None
    text_size = None
    for name, va, vsize, roff, rsize in _sections(pe_bytes):
        if name == '.text':
            text_roff = roff
            text_size = rsize
            break
    if text_roff is None:
        return []
    text = pe_bytes[text_roff:text_roff + text_size]

    runs = _neg_word_runs(text, min_len)
    seeds = _seed_candidates(text)

    hits = []
    for start_off, words in runs:
        cipher = b''.join(struct.pack('<H', w) for w in words)
        for seed in seeds:
            plain = cr013_nr_decrypt(cipher, seed, wide=True)
            txt = _readable_utf16(plain)
            if txt:
                hits.append({
                    'seed': seed,
                    'plaintext': txt,
                    'words': len(words),
                    'offset': text_roff + start_off,
                })
                break  # 一个密文序列只保留首个命中 seed
    return hits


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('用法: python scan.py <file>')
        sys.exit(1)
    data = open(sys.argv[1], 'rb').read()
    hits = scan_cr013_strings(data)
    print(f'== scan_cr013_strings({sys.argv[1]}) ==')
    for h in hits:
        print(f"  seed=0x{h['seed']:08X} words={h['words']:2d} off=0x{h['offset']:X} -> {h['plaintext']!r}")
    if not hits:
        print('  (无命中)')
