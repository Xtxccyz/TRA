#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PE 解析工具 —— 纯标准库，无 pefile 依赖。

用法：
    from pe_tools import get_pdb, get_imports, get_exports, get_sections
    d = open('sample.dll', 'rb').read()
    pdb = get_pdb(d)
    imports = get_imports(d)

所有函数输入完整 PE 文件 bytes。
"""

from __future__ import annotations

import struct


# ============================================================================
# 基础结构解析
# ============================================================================

def _pe_header(d: bytes) -> int:
    """返回 PE header（COFF header 起点 = e_lfanew 指向的 'PE\\0\\0'）。"""
    if len(d) < 0x40 or d[:2] != b'MZ':
        raise ValueError('非 PE 文件（缺 MZ 头）')
    return struct.unpack_from('<I', d, 0x3C)[0]


def _sections(d: bytes):
    """返回 [(name, virtual_addr, virtual_size, raw_offset, raw_size), ...] 节表。"""
    pe = _pe_header(d)
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    sec = pe + 24 + optsz
    out = []
    for i in range(nsec):
        s = sec + i * 40
        name = d[s:s + 8].split(b'\x00')[0].decode('latin1', errors='replace')
        vsize = struct.unpack_from('<I', d, s + 8)[0]
        va = struct.unpack_from('<I', d, s + 12)[0]
        rsize = struct.unpack_from('<I', d, s + 16)[0]
        roff = struct.unpack_from('<I', d, s + 20)[0]
        out.append((name, va, vsize, roff, rsize))
    return out


def rva_to_offset(d: bytes, rva: int) -> int | None:
    """RVA → 文件偏移。找不到返回 None。"""
    for _, va, vsize, roff, rsize in _sections(d):
        if va <= rva < va + max(vsize, rsize):
            return roff + (rva - va)
    return None


# ============================================================================
# 头部字段
# ============================================================================

def get_machine(d: bytes) -> int:
    """Machine 字段（0x14C=i386，0x8664=x64，0=被清零/去特征化）。"""
    pe = _pe_header(d)
    return struct.unpack_from('<H', d, pe + 4)[0]


def get_timestamp(d: bytes) -> int:
    """TimeDateStamp（编译时间，Unix 时间戳）。"""
    pe = _pe_header(d)
    return struct.unpack_from('<I', d, pe + 8)[0]


def get_sections(d: bytes) -> list:
    """返回节表 list，元素为 (name, virtual_addr, virtual_size, raw_offset, raw_size)。"""
    return _sections(d)


# ============================================================================
# 调试目录 / PDB
# ============================================================================

def get_pdb(d: bytes) -> dict | None:
    """提取 PDB 调试信息（RSDS CodeView）。

    返回 dict：{'guid': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', 'age': int, 'name': str}
    无调试目录或非 RSDS 返回 None。

    用途：PDB GUID 是驱动身份指纹（如 fvepxy.pdb / drmkflt.pdb / hidsvc.pdb）。
    """
    try:
        pe = _pe_header(d)
        opt = pe + 24
        magic = struct.unpack_from('<H', d, opt)[0]
        # 数据目录偏移：Export[0]=+0x60/+0x70，Import[1]=+0x68/+0x78，
        # Resource[2]=+0x70/+0x80，Debug[6]=+0x90/+0xA0（PE32/PE32+）
        dd_off = opt + (0x90 if magic == 0x10B else 0xA0)
        dd_rva, dd_size = struct.unpack_from('<II', d, dd_off)
        if not dd_size:
            return None
        off = rva_to_offset(d, dd_rva)
        if off is None:
            return None
        # 取第一个调试目录项
        typ = struct.unpack_from('<I', d, off + 12)[0]
        if typ != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            return None
        # CodeView 数据位置：PointerToRawData(偏移24)=文件偏移；回退 AddressOfRawData(偏移20)=RVA
        ptr_raw = struct.unpack_from('<I', d, off + 24)[0]
        addr_rva = struct.unpack_from('<I', d, off + 20)[0]
        cv_off = ptr_raw if ptr_raw else rva_to_offset(d, addr_rva)
        if cv_off is None or d[cv_off:cv_off + 4] != b'RSDS':
            return None
        guid = d[cv_off + 4:cv_off + 20]
        age = struct.unpack_from('<I', d, cv_off + 20)[0]
        name = d[cv_off + 24:].split(b'\x00')[0].decode('latin1')
        # GUID 标准格式：Data1(4B)/Data2(2B)/Data3(2B) 小端反转，Data4(8B) 原样
        data1 = guid[0:4][::-1]
        data2 = guid[4:6][::-1]
        data3 = guid[6:8][::-1]
        data4 = guid[8:16]
        g = ''.join('%02x' % b for b in data1 + data2 + data3 + data4)
        return {
            'guid': f'{g[0:8]}-{g[8:12]}-{g[12:16]}-{g[16:20]}-{g[20:32]}',
            'age': age,
            'name': name,
        }
    except (ValueError, struct.error):
        return None


# ============================================================================
# 导入表 / 导出表
# ============================================================================

def get_imports(d: bytes) -> list[str]:
    """返回导入模块名 list（如 ['ntoskrnl', 'HAL', 'msvcrt.dll']）。"""
    try:
        pe = _pe_header(d)
        opt = pe + 24
        magic = struct.unpack_from('<H', d, opt)[0]
        imp_off = opt + (0x68 if magic == 0x10B else 0x78)
        imp_rva = struct.unpack_from('<I', d, imp_off)[0]
        if not imp_rva:
            return []
        off = rva_to_offset(d, imp_rva)
        mods = []
        while off:
            name_rva = struct.unpack_from('<I', d, off + 12)[0]
            if not name_rva:
                break
            no = rva_to_offset(d, name_rva)
            if not no:
                break
            mods.append(d[no:].split(b'\x00')[0].decode('latin1'))
            off += 20  # IMAGE_IMPORT_DESCRIPTOR 大小
        return mods
    except (ValueError, struct.error):
        return []


def get_exports(d: bytes) -> list[str]:
    """返回导出函数名 list（ordinal-only 导出不会出现在 list 里）。"""
    try:
        pe = _pe_header(d)
        opt = pe + 24
        magic = struct.unpack_from('<H', d, opt)[0]
        # Export[0] 数据目录：PE32 +0x60，PE32+ +0x70
        exp_off = opt + (0x60 if magic == 0x10B else 0x70)
        exp_rva = struct.unpack_from('<I', d, exp_off)[0]
        if not exp_rva:
            return []
        off = rva_to_offset(d, exp_rva)
        if off is None:
            return []
        num_names = struct.unpack_from('<I', d, off + 24)[0]
        names_rva = struct.unpack_from('<I', d, off + 32)[0]
        names_off = rva_to_offset(d, names_rva)
        if names_off is None:
            return []
        names = []
        for i in range(num_names):
            n_rva = struct.unpack_from('<I', d, names_off + i * 4)[0]
            n_off = rva_to_offset(d, n_rva)
            if n_off:
                names.append(d[n_off:].split(b'\x00')[0].decode('latin1'))
        return names
    except (ValueError, struct.error):
        return []


# ============================================================================
# 资源目录
# ============================================================================

def get_resources(d: bytes, rsrc_type: int | None = None) -> list[dict]:
    """提取资源目录条目。

    返回 [{'type': int, 'id': int, 'rva': int, 'size': int, 'data': bytes}, ...]
    rsrc_type 指定时只返回该类型（如 10 = RT_RCDATA），None 返回全部。
    """
    try:
        pe = _pe_header(d)
        opt = pe + 24
        magic = struct.unpack_from('<H', d, opt)[0]
        rsrc_off = opt + (0x70 if magic == 0x10B else 0x80)
        rsrc_rva = struct.unpack_from('<I', d, rsrc_off)[0]
        if not rsrc_rva:
            return []
        root = rva_to_offset(d, rsrc_rva)
        if root is None:
            return []

        def walk(off, depth, rtype, rid):
            """递归遍历三层资源目录树。"""
            num_named = struct.unpack_from('<H', d, off + 12)[0]
            num_id = struct.unpack_from('<H', d, off + 14)[0]
            count = num_named + num_id
            out = []
            for i in range(count):
                e = off + 16 + i * 8
                name = struct.unpack_from('<I', d, e)[0]
                sub = struct.unpack_from('<I', d, e + 4)[0]
                is_dir = bool(sub & 0x80000000)
                sub_off = rva_to_offset(d, sub & 0x7FFFFFFF)
                if sub_off is None:
                    continue
                if depth == 0:
                    out += walk(sub_off, 1, name, rid)
                elif depth == 1:
                    out += walk(sub_off, 2, rtype, name)
                else:
                    # 叶子：data entry
                    do = rva_to_offset(d, sub)
                    if do is None:
                        continue
                    data_rva = struct.unpack_from('<I', d, do + 0)[0]
                    data_size = struct.unpack_from('<I', d, do + 4)[0]
                    doff = rva_to_offset(d, data_rva)
                    if doff is None:
                        continue
                    out.append({
                        'type': rtype,
                        'id': rid,
                        'rva': data_rva,
                        'size': data_size,
                        'data': d[doff:doff + data_size],
                    })
            return out

        all_res = walk(root, 0, 0, 0)
        if rsrc_type is None:
            return all_res
        return [r for r in all_res if r['type'] == rsrc_type]
    except (ValueError, struct.error):
        return []


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('用法: python pe_tools.py <file>')
        sys.exit(1)
    d = open(sys.argv[1], 'rb').read()
    print('Machine:', hex(get_machine(d)))
    print('PDB:', get_pdb(d))
    print('Imports:', get_imports(d))
    print('Exports:', get_exports(d))
