#!/usr/bin/env python3
"""
SimHash 代码相似度计算工具

算法: Charikar SimHash (64-bit)
特征: x86-64 指令助记符 4-gram (仅操作码，忽略操作数)
哈希: MD5 → 64-bit integer
权重: uniform (每 4-gram 权重=1)

后续用同样的算法对新样本的函数体计算 SimHash → 与已有库中的
SimHash 做汉明距离比较 → 距离 < 阈值 = 代码高度相似

用法:
  python simhash.py --hex "4885c9..."                    # 单次计算
  python simhash.py --file <binary_file> --start <offset> --size <N>  # 从文件读取
  python simhash.py --compare <hash1> <hash2>            # 比较两个 hash

参考:
  Charikar, Moses S. "Similarity estimation techniques from rounding algorithms."
  Proceedings of the thirty-fourth annual ACM symposium on Theory of computing. 2002.
"""

import sys
import hashlib
import struct
import argparse
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import os as _os

# 初始化 capstone x86-64 反汇编器
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = False  # 不需要详细信息，只需要助记符

# Path to known functions YAML database (shared with fuzzy_hash.py)
_KNOWN_YAML = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'known-functions.yaml')


def disassemble_mnemonics(code: bytes) -> list[str]:
    """反汇编字节序列，返回助记符列表（仅操作码，忽略操作数）。"""
    mnemonics = []
    for insn in MD.disasm(code, 0):
        mnemonics.append(insn.mnemonic)
    return mnemonics


def generate_ngrams(mnemonics: list[str], n: int = 4) -> list[str]:
    """从助记符序列生成 n-gram 特征。"""
    if len(mnemonics) < n:
        return [' '.join(mnemonics)]  # 不足 n 个的取全部
    return [' '.join(mnemonics[i:i+n]) for i in range(len(mnemonics) - n + 1)]


def hash64(s: str) -> int:
    """将字符串哈希为 64-bit 整数 (MD5 前 8 字节)。"""
    digest = hashlib.md5(s.encode('utf-8')).digest()
    return struct.unpack('<Q', digest[:8])[0]


def simhash(features: list[str], weights: list[int] | None = None) -> int:
    """
    计算 Charikar SimHash。

    算法:
      1. 初始化 64 维向量 v，全部为 0
      2. 对每个特征 f:
         a. hash64(f) → 64-bit hash h
         b. 对每个 bit i (0..63):
            - 若 h 的 bit i 为 1 → v[i] += weight(f)
            - 若 h 的 bit i 为 0 → v[i] -= weight(f)
      3. 最终指纹: bit i = 1 if v[i] > 0 else 0

    Args:
      features: 特征列表 (如 4-gram 字符串)
      weights:  每个特征的权重 (None=uniform weight=1)

    Returns:
      64-bit SimHash fingerprint
    """
    v = [0] * 64

    if weights is None:
        weights = [1] * len(features)

    for f, w in zip(features, weights):
        h = hash64(f)
        for i in range(64):
            if (h >> i) & 1:
                v[i] += w
            else:
                v[i] -= w

    # 构建最终指纹
    fingerprint = 0
    for i in range(64):
        if v[i] > 0:
            fingerprint |= (1 << i)

    return fingerprint


def hamming_distance(a: int, b: int) -> int:
    """计算两个 64-bit hash 的汉明距离 (不同 bit 数)。"""
    x = a ^ b
    return x.bit_count()


def simhash_from_bytes(code: bytes) -> int:
    """对二进制代码字节计算 SimHash。（一步完成反汇编→4-gram→SimHash）"""
    mnemonics = disassemble_mnemonics(code)
    features = generate_ngrams(mnemonics, n=4)
    return simhash(features)


def simhash_from_file(filepath: str, offset: int, size: int) -> int:
    """从二进制文件中指定位置读取代码并计算 SimHash。"""
    with open(filepath, 'rb') as f:
        f.seek(offset)
        code = f.read(size)
    return simhash_from_bytes(code)


# ============================================================
# 已知函数 SimHash 库 (从 YAML 加载, 与 fuzzy_hash.py 共享)
# ============================================================

KNOWN_SIMHASHES = {}  # lazy-loaded by _load_known_simhashes()

def _load_known_simhashes():
    """Load known function simhashes from known-functions.yaml."""
    global KNOWN_SIMHASHES
    if KNOWN_SIMHASHES:
        return KNOWN_SIMHASHES
    import yaml
    with open(_KNOWN_YAML, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    for e in data.get('entries', []):
        KNOWN_SIMHASHES[e['name']] = {
            'simhash': e['simhash'],
            'file': e['file'],
            'offset': e['func'],  # keep key name for backward compat
            'size': e['size'],
            'mnemonic_count': e.get('mnemonics', 0),
            'description': e['desc'],
        }
    return KNOWN_SIMHASHES


def register_known(name, code_bytes, filepath, offset, size, description=''):
    """注册已知函数的 SimHash 到库中（运行时注册，不写回 YAML）。"""
    _load_known_simhashes()
    sh = simhash_from_bytes(code_bytes)
    KNOWN_SIMHASHES[name] = {
        'simhash': f'0x{sh:016x}',
        'file': filepath,
        'offset': f'0x{offset:x}',
        'size': size,
        'mnemonic_count': len(disassemble_mnemonics(code_bytes)),
        'description': description,
    }
    return sh


def print_library():
    """打印已知函数 SimHash 库（结构化输出）。"""
    _load_known_simhashes()
    print('=' * 70)
    print('已知加密函数 SimHash 库 (Charikar SimHash 64-bit)')
    print('参数: n-gram=4, hash=MD5, 特征=助记符(仅操作码), 权重=uniform')
    print('')
    for name, info in KNOWN_SIMHASHES.items():
        print(f'  {name}')
        print(f'    simhash:    {info["simhash"]}')
        print(f'    file:       {info["file"]}')
        print(f'    offset:     {info["offset"]}')
        print(f'    size:       {info["size"]} bytes')
        print(f'    mnemonics:  {info["mnemonic_count"]}')
        print(f'    desc:       {info["description"]}')
        print()


def search_similar(target_hash: int, threshold: int = 10):
    """在已知库中搜索与 target_hash 汉明距离 <= threshold 的函数。"""
    _load_known_simhashes()
    results = []
    for name, info in KNOWN_SIMHASHES.items():
        known = int(info['simhash'], 16)
        dist = hamming_distance(target_hash, known)
        if dist <= threshold:
            results.append((name, dist, info))
    return sorted(results, key=lambda x: x[1])  # 按距离升序


# ============================================================
# 主入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description='SimHash 代码相似度计算 (Charikar 64-bit, mnemonic 4-gram)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python simhash.py --hex "4885c974254885db..."
  python simhash.py --file foo.dll --offset 0x1FC --size 713
  python simhash.py --compare 0x3a2f... 0x7b1c...
  python simhash.py --print-library
        """,
    )
    parser.add_argument('--hex', help='十六进制字节 (空格分隔或连写)')
    parser.add_argument('--file', help='二进制文件路径')
    parser.add_argument('--offset', help='文件中的字节偏移 (hex 或 decimal)')
    parser.add_argument('--size', type=int, help='要读取的字节数', default=0)
    parser.add_argument(
        '--compare', nargs=2,
        help='比较两个 64-bit SimHash (hex格式) 的汉明距离'
    )
    parser.add_argument(
        '--search', help='在已知库中搜索相似的 SimHash',
        metavar='HASH'
    )
    parser.add_argument(
        '--threshold', type=int, default=10,
        help='汉明距离阈值 (默认: 10)'
    )
    parser.add_argument('--print-library', action='store_true', help='打印已知函数库')
    parser.add_argument('--json', action='store_true', help='JSON 格式输出')

    args = parser.parse_args()

    if args.print_library:
        print_library()
        return

    if args.compare:
        a = int(args.compare[0], 16)
        b = int(args.compare[1], 16)
        dist = hamming_distance(a, b)
        print(f'Hamming distance({args.compare[0]}, {args.compare[1]}): {dist}')
        print(f'Result: {"SIMILAR" if dist <= 10 else "DIFFERENT"} (threshold=10)')
        return

    if args.search:
        target = int(args.search, 16)
        results = search_similar(target, args.threshold)
        if results:
            print(f'Found {len(results)} match(es) within threshold {args.threshold}:')
            for name, dist, info in results:
                print(f'  {name}: distance={dist}, desc={info["description"]}')
        else:
            print(f'No matches within threshold {args.threshold}')
        return

    # 计算 SimHash
    if args.hex:
        hex_str = args.hex.replace(' ', '').replace('\n', '')
        code = bytes.fromhex(hex_str)
    elif args.file:
        if not args.offset:
            print('Error: --offset required with --file', file=sys.stderr)
            sys.exit(1)
        offset = int(args.offset, 16) if args.offset.startswith('0x') else int(args.offset)
        with open(args.file, 'rb') as f:
            f.seek(offset)
            code = f.read(args.size)
    else:
        parser.print_help()
        return

    # 显示反汇编
    mnemonics = disassemble_mnemonics(code)
    features = generate_ngrams(mnemonics, n=4)
    sh = simhash(features)

    if args.json:
        import json
        print(json.dumps({
            'simhash': f'0x{sh:016x}',
            'mnemonic_count': len(mnemonics),
            'feature_count': len(features),
            'bytes': len(code),
        }))
    else:
        print(f'Bytes:     {len(code)}')
        print(f'Mnemonics: {len(mnemonics)}')
        print(f'Features:  {len(features)} (4-grams)')
        print(f'SimHash:   0x{sh:016x}')
        print(f'Binary:    {sh:064b}')


if __name__ == '__main__':
    main()
