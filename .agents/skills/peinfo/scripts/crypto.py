#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""加密原语库 —— 通用算法 + NSA Equation Group / DiBa 家族特有算法。

纯标准库，无第三方依赖。所有函数输入 bytes、输出 bytes。

用法：
    from crypto import rc4_decrypt, xor_decrypt, cr007_decrypt
    plain = cr007_decrypt(cipher_bytes)
"""

from __future__ import annotations

import base64
import zlib

from constants import (
    CR001_LGC_MULT, CR001_LGC_ADD,
    CR007_SUBSTITUTION_TABLE,
    CR011_GLIBC_MULT, CR011_GLIBC_ADD,
    CR013_NR_MULT, CR013_NR_ADD,
)


# ============================================================================
# 一、通用算法
# ============================================================================

def xor_decrypt(data: bytes, key) -> bytes:
    """单字节 / 多字节重复 XOR 解密（与加密对称，同一函数）。

    key 为 int（单字节，0-255）时按单字节 XOR；
    key 为 bytes 时按重复 key 流 XOR。
    """
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError('key 必须是 int 或 bytes')
    klen = len(key)
    if klen == 0:
        return bytes(data)
    return bytes(data[i] ^ key[i % klen] for i in range(len(data)))


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 流密码（加解密对称，同一函数）。

    KSA 用 key 初始化 256 字节 S 盒，PRGA 生成密钥流与 data 异或。
    典型场景：C2 通信（前 16 字节 = session key，后续 = 密文）。
    """
    s = list(range(256))
    j = 0
    klen = len(key)
    # KSA（密钥调度）
    for i in range(256):
        j = (j + s[i] + key[i % klen]) & 0xFF
        s[i], s[j] = s[j], s[i]
    # PRGA（伪随机生成 + 异或）
    out = bytearray(len(data))
    i = j = 0
    for n in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = data[n] ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


# 别名（语义化）
rc4_decrypt = rc4_crypt
rc4_encrypt = rc4_crypt


def lcg_stream(seed: int, mult: int, add: int, length: int, xor_shift: int = 8) -> bytes:
    """通用 LCG 密钥流生成。

    递推：seed = (mult * seed + add) mod 2^32；输出 byte = (seed >> xor_shift) & 0xFF。

    xor_shift 决定取 seed 的哪个字节：
      8  → 取第 1 字节（BYTE1，如 CR-001）
      16 → 取第 2 字节（BYTE2，如 CR-011）
    """
    s = seed & 0xFFFFFFFF
    out = bytearray(length)
    for i in range(length):
        s = (mult * s + add) & 0xFFFFFFFF
        out[i] = (s >> xor_shift) & 0xFF
    return bytes(out)


def b64_decode(data) -> bytes:
    """base64 解码（自动补 padding），带异常兜底。"""
    if isinstance(data, str):
        data = data.encode()
    pad = b'=' * (-len(data) % 4)
    return base64.b64decode(data + pad)


# ============================================================================
# 二、NSA Equation Group / DiBa 家族特有
# ============================================================================

def cr001_lcg_decrypt(data: bytes, seed: int) -> bytes:
    """CR-001 LCG 流密码解密（DiBa 资源封装 / 数据解密）。

    递推：seed = (0xDD483B8F - 0x6033A96D * seed) mod 2^32
    输出：byte ^= (seed >> 8) & 0xFF

    典型格式：[4 字节 seed LE] + LCG 加密的 [4 字节解压后大小 + zlib 流]
    见 constants.RESOURCE_FORMAT_DIBA。
    """
    s = seed & 0xFFFFFFFF
    out = bytearray(len(data))
    for i in range(len(data)):
        s = (CR001_LGC_ADD - CR001_LGC_MULT * s) & 0xFFFFFFFF
        out[i] = data[i] ^ ((s >> 8) & 0xFF)
    return bytes(out)


def cr007_decrypt(cipher: str | bytes) -> str:
    """CR-007 单字节替换表解密（DiBa 本体字符串混淆）。

    解密方向（实测修正，勿用早期 fact 的 table.index()+32 反方向）：
        plain = table[ord(cipher_char) - 0x20]

    加密（反向）：cipher = chr(table.index(plain_char) + 0x20)
    """
    if isinstance(cipher, bytes):
        cipher = cipher.decode('latin1')
    table = CR007_SUBSTITUTION_TABLE
    out = []
    for c in cipher:
        o = ord(c)
        if 0x20 <= o < 0x7F:
            out.append(table[o - 0x20])
        else:
            out.append(c)  # 非可打印字符原样保留
    return ''.join(out)


def cr007_encrypt(plain: str | bytes) -> str:
    """CR-007 替换表加密（与 cr007_decrypt 互逆）。"""
    if isinstance(plain, bytes):
        plain = plain.decode('latin1')
    table = CR007_SUBSTITUTION_TABLE
    return ''.join(chr(table.index(c) + 0x20) for c in plain)


def cr011_glibc_decrypt(data: bytes, seed: int) -> bytes:
    """CR-011 glibc rand LCG 解密（DiBa 内嵌驱动字符串解密）。

    递推：seed = (0x41C64E6D * seed + 0x3039) mod 2^32
    输出：byte ^= (seed >> 16) & 0xFF

    实测用例：10_104.sys 用此解密 'ExAllocatePoolWithTag' /
    'ZwAllocateVirtualMemory' / 'ZwFreeVirtualMemory'。
    """
    s = seed & 0xFFFFFFFF
    out = bytearray(len(data))
    for i in range(len(data)):
        s = (CR011_GLIBC_MULT * s + CR011_GLIBC_ADD) & 0xFFFFFFFF
        out[i] = data[i] ^ ((s >> 16) & 0xFF)
    return bytes(out)


def cr013_nr_decrypt(data: bytes, seed: int, wide: bool = False) -> bytes:
    """CR-013 Numerical Recipes LCG 解密（DiBa 内嵌驱动 10_102.sys = fvepxy.sys）。

    递推：seed = (0x19660D * seed + 0x3C6EF35F) mod 2^32

    两变体（wide=False 单字节 / wide=True 宽字符 UTF-16LE）：
        单字节：byte ^= (seed >> 16) & 0xFF | 0x80
        宽字符：word ^= (seed >> 16) & 0xFFFF | 0x8000

    每个被混淆字符串有独立 seed（存于调用点数组）。用于 SSDT hook 服务名
    （ZwCreateThread/ZwWriteVirtualMemory/NtClose 等）与 ntdll.dll 模块名。
    """
    s = seed & 0xFFFFFFFF
    out = bytearray(len(data))
    if wide:
        for i in range(0, len(data) - 1, 2):
            s = (CR013_NR_MULT * s + CR013_NR_ADD) & 0xFFFFFFFF
            w = data[i] | (data[i + 1] << 8)
            w ^= ((s >> 16) & 0xFFFF) | 0x8000
            out[i] = w & 0xFF
            out[i + 1] = (w >> 8) & 0xFF
    else:
        for i in range(len(data)):
            s = (CR013_NR_MULT * s + CR013_NR_ADD) & 0xFFFFFFFF
            out[i] = data[i] ^ (((s >> 16) & 0xFF) | 0x80)
    return bytes(out)


def decrypt_diba_resource(encrypted_resource: bytes) -> bytes:
    """解密 DiBa 内嵌 RT_RCDATA 资源（CR-001 LCG + zlib）。

    输入：完整资源原始字节（含前 4 字节 seed）
    输出：解压后的 payload（PE 或数据）
    """
    import struct
    if len(encrypted_resource) < 8:
        raise ValueError('资源太短')
    seed = struct.unpack_from('<I', encrypted_resource, 0)[0]
    dec = cr001_lcg_decrypt(encrypted_resource[4:], seed)
    # 格式：[4B seed][LCG: 4B decompressed_size + zlib stream]
    return zlib.decompress(dec[4:])


if __name__ == '__main__':
    # 自测：CR-007 加解密互逆 + 已知用例
    assert cr007_decrypt('yF^T]2@D]izIWc2]') == 'ZwQuerySemaphore', 'CR-007 用例失败'
    assert cr007_encrypt('ZwQuerySemaphore') == 'yF^T]2@D]izIWc2]', 'CR-007 加密失败'
    assert rc4_decrypt(rc4_encrypt(b'hello world', b'key'), b'key') == b'hello world', 'RC4 失败'
    # CR-013 用例：10_102.sys SSDT hook 服务名（seed 见 sub_22071 v2 数组）
    assert cr013_nr_decrypt(bytes.fromhex('c6 c8 98 d3 89 91 bc b6 9b b2 a0 eb 91 f1'), 0x705180) == b'ZwCreateThread'
    assert cr013_nr_decrypt(bytes.fromhex('88 e5 e8 fe ca c6 81'), 0x8F5800) == b'NtClose'
    print('crypto.py 自测通过')
