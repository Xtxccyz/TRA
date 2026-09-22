#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELF 解析工具 —— 纯标准库，基础版。

用法：
    from elf_tools import elf_header, elf_sections, elf_symbols
    d = open('sample.so', 'rb').read()
    hdr = elf_header(d)

支持 32/64 位、大小端。后续按需扩展（动态导入、重定位等）。
"""

from __future__ import annotations

import struct


# ELF header 各字段的格式（key: (偏移, 格式)）
# 32 位与 64 位共用前 52 字节，差异在 e_phoff 之后的字段
_ELF_HDR = {
    'ident': (0, '16s'),
    'type': (16, 'H'),
    'machine': (18, 'H'),
    'version': (20, 'I'),
    'entry': (24, None),   # 32 位 'I' / 64 位 'Q'
    'phoff': (28, None),
    'shoff': (32, None),
    'flags': (36, 'I'),
    'ehsize': (40, 'H'),
    'phentsize': (42, 'H'),
    'phnum': (44, 'H'),
    'shentsize': (46, 'H'),
    'shnum': (48, 'H'),
    'shstrndx': (50, 'H'),
}

# 常见 machine 值（部分）
ELF_MACHINE = {
    3: 'EM_386 (x86)',
    62: 'EM_X86_64 (x64)',
    40: 'EM_ARM',
    183: 'EM_AARCH64 (arm64)',
    8: 'EM_MIPS',
}


def _fmt(d: bytes, field: str):
    """返回字段的 struct 格式，处理 32/64 位差异。"""
    is64 = d[4] == 2  # ELFCLASS64
    if field in ('entry', 'phoff', 'shoff'):
        return 'Q' if is64 else 'I'
    return None


def elf_header(d: bytes) -> dict:
    """解析 ELF header，返回 dict（字段名 → 值）。"""
    if len(d) < 52 or d[:4] != b'\x7fELF':
        raise ValueError('非 ELF 文件（缺 \\x7fELF magic）')
    is64 = d[4] == 2
    endian = '<' if d[5] == 1 else '>'
    hdr = {'class': 'ELF64' if is64 else 'ELF32', 'endian': 'LE' if endian == '<' else 'BE'}
    for name, (off, fmt) in _ELF_HDR.items():
        if fmt is None:
            fmt = 'Q' if is64 else 'I'
        hdr[name] = struct.unpack_from(endian + fmt, d, off)[0]
    hdr['machine_name'] = ELF_MACHINE.get(hdr['machine'], f'unknown({hdr["machine"]})')
    return hdr


def elf_sections(d: bytes) -> list[dict]:
    """返回节表 list，元素含 name/type/addr/offset/size。"""
    hdr = elf_header(d)
    is64 = d[4] == 2
    endian = '<' if d[5] == 1 else '>'
    word = 'Q' if is64 else 'I'
    shoff, shentsize, shnum, shstrndx = hdr['shoff'], hdr['shentsize'], hdr['shnum'], hdr['shstrndx']
    if shoff == 0 or shnum == 0:
        return []
    # 先读 shstrtab 节头，得到节名字符串表
    strhdr_off = shoff + shstrndx * shentsize
    str_off = struct.unpack_from(endian + word, d, strhdr_off + 24)[0]
    str_size = struct.unpack_from(endian + word, d, strhdr_off + 32)[0]

    def cstr(off, base, size):
        end = base + size
        if off >= end:
            return ''
        s = d[base + off:end].split(b'\x00')[0]
        return s.decode('latin1', errors='replace')

    sections = []
    for i in range(shnum):
        so = shoff + i * shentsize
        name_off = struct.unpack_from(endian + 'I', d, so)[0]
        sec = {
            'name': cstr(name_off, str_off, str_size),
            'type': struct.unpack_from(endian + 'I', d, so + 4)[0],
            'addr': struct.unpack_from(endian + word, d, so + 16)[0],
            'offset': struct.unpack_from(endian + word, d, so + 24)[0],
            'size': struct.unpack_from(endian + word, d, so + 32)[0],
        }
        sections.append(sec)
    return sections


def elf_symbols(d: bytes, symtab='.symtab') -> list[dict]:
    """提取符号表（默认 .symtab）。返回 [{'name', 'value', 'size'}, ...]。"""
    sections = elf_sections(d)
    is64 = d[4] == 2
    endian = '<' if d[5] == 1 else '>'
    word = 'Q' if is64 else 'I'
    # 找 symtab 和 strtab
    target = next((s for s in sections if s['name'] == symtab), None)
    if target is None:
        return []
    strtab = next((s for s in sections if s['name'] == '.strtab'), None)
    if strtab is None:
        return []
    entsize = 24 if is64 else 16
    syms = []
    for off in range(target['offset'], target['offset'] + target['size'], entsize):
        name_off = struct.unpack_from(endian + 'I', d, off)[0]
        value = struct.unpack_from(endian + word, d, off + 8)[0]
        size = struct.unpack_from(endian + word, d, off + 16)[0]
        name = d[strtab['offset'] + name_off:strtab['offset'] + strtab['size']].split(b'\x00')[0]
        name = name.decode('latin1', errors='replace')
        if name:
            syms.append({'name': name, 'value': value, 'size': size})
    return syms


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('用法: python elf_tools.py <file>')
        sys.exit(1)
    d = open(sys.argv[1], 'rb').read()
    print(elf_header(d))
