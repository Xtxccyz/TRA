#!/usr/bin/env python3
"""
fuzzy_hash.py — ssdeep + SimHash 双引擎模糊哈希工具

  计算: python fuzzy_hash.py --hex "4885c90f..."             从IDA导出的十六进制计算
        python fuzzy_hash.py --file foo.dll --start 0x1FC --size 713  从文件读取计算

  对比: python fuzzy_hash.py --cmp 0xb4a0f9... 0xe568de...   传两个hash, 自动识别类型
        python fuzzy_hash.py --cmp-file hashes.txt            从文件读两行hash对比

  搜索: python fuzzy_hash.py --search simhash 0xb4a0f9...     在已知库搜索(SimHash)
        python fuzzy_hash.py --search ssdeep "12:kkHmW..."    在已知库搜索(ssdeep)

  查看: python fuzzy_hash.py --print-library

  自动识别规则:
    hash 包含 ':' → ssdeep compare
    hash 以 '0x' 开头 → SimHash compare

  依赖: pip install ppdeep capstone
"""

import sys
import struct
import hashlib
import argparse

import ppdeep
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

MD_X64 = Cs(CS_ARCH_X86, CS_MODE_64)
MD_X64.detail = False
MD_X86 = Cs(CS_ARCH_X86, CS_MODE_32)
MD_X86.detail = False

# Path to known functions YAML database (relative to this script)
import os as _os
_KNOWN_YAML = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'known-functions.yaml')


def _get_md(arch: str = 'x64'):
    """Get capstone disassembler for given architecture."""
    return MD_X86 if arch == 'x86' else MD_X64


# ============================================================
# ssdeep (ppdeep)
# ============================================================

def ssdeep_hash(data: bytes) -> str:
    return ppdeep.hash(data)


def ssdeep_compare(h1: str, h2: str) -> int:
    try:
        return ppdeep.compare(h1, h2)
    except ValueError:
        return -1


# ============================================================
# SimHash (mnemonic 4-gram)
# ============================================================

def simhash_mnemonics(code: bytes, arch: str = 'x64') -> list[str]:
    return [i.mnemonic for i in _get_md(arch).disasm(code, 0)]


def simhash_ngrams(mnemonics: list[str], n: int = 4) -> list[str]:
    if len(mnemonics) < n:
        return [' '.join(mnemonics)]
    return [' '.join(mnemonics[i:i+n]) for i in range(len(mnemonics) - n + 1)]


def simhash_hash64(s: str) -> int:
    return struct.unpack('<Q', hashlib.md5(s.encode()).digest()[:8])[0]


def simhash_compute(features: list[str]) -> int:
    v = [0] * 64
    for f in features:
        h = simhash_hash64(f)
        for i in range(64):
            v[i] += 1 if (h >> i) & 1 else -1
    fp = 0
    for i in range(64):
        if v[i] > 0:
            fp |= (1 << i)
    return fp


def simhash_from_bytes(code: bytes, arch: str = 'x64') -> int:
    return simhash_compute(simhash_ngrams(simhash_mnemonics(code, arch), 4))


def simhash_text(text: bytes, n: int = 4) -> int:
    """Compute SimHash over raw bytes using byte n-grams (no disassembly)."""
    features = [text[i:i+n].hex() for i in range(len(text) - n + 1)]
    if not features:
        features = [text.hex()]
    return simhash_compute(features)


def fuzzy_compare_str(s1: str, s2: str, case_sensitive: bool = False):
    """Compare two arbitrary strings with both ssdeep and SimHash (text mode).

    Default: case-insensitive (both strings lowercased before hashing).
    """
    if not case_sensitive:
        s1, s2 = s1.lower(), s2.lower()

    b1, b2 = s1.encode('utf-8'), s2.encode('utf-8')

    # ssdeep
    h1 = ssdeep_hash(b1)
    h2 = ssdeep_hash(b2)
    ssd_score = ssdeep_compare(h1, h2)

    # simhash (byte n-gram, no disasm)
    sh1 = simhash_text(b1)
    sh2 = simhash_text(b2)
    dist = simhash_compare(sh1, sh2)

    case_label = '(case-sensitive) ' if case_sensitive else ''
    print(f'ssdeep:    {ssd_score}  [{_verdict_ssdeep(ssd_score)}]')
    print(f'simhash:   {dist:2d}  [{_verdict_simhash(dist, "text")}]  {case_label}(Hamming distance)')
    print(f'  hash1:  0x{sh1:016x}')
    print(f'  hash2:  0x{sh2:016x}')


def simhash_compare(h1: int, h2: int) -> int:
    return (h1 ^ h2).bit_count()


# ============================================================
# 阈值与判定
# ============================================================

# ssdeep: 0-100, higher = more similar. < 20 = unrelated.
SSDEEP_UNRELATED = 20    # below this = DIFFERENT
SSDEEP_SIMILAR = 50       # >= this = SIMILAR
SSDEEP_HIGH = 80          # >= this = HIGH (near-identical / same source)

# simhash (x86 code, mnemonic 4-gram): 0-64 Hamming distance, lower = more similar
SIMHASH_CODE_NEAR = 3     # <= this = NEAR-IDENTICAL
SIMHASH_CODE_SIMILAR = 10 # <= this = SIMILAR (default threshold for code search)
SIMHASH_CODE_UNRELATED = 16  # > this = DIFFERENT

# simhash (raw text/bytes, byte n-gram): broader noise floor than code
SIMHASH_TEXT_NEAR = 6     # <= this = NEAR-IDENTICAL
SIMHASH_TEXT_SIMILAR = 12 # <= this = SIMILAR
SIMHASH_TEXT_UNRELATED = 20  # > this = DIFFERENT


def _verdict_ssdeep(score: int) -> str:
    if score >= SSDEEP_HIGH:
        return 'HIGH (near-identical)'
    elif score >= SSDEEP_SIMILAR:
        return 'SIMILAR'
    elif score < SSDEEP_UNRELATED:
        return 'DIFFERENT'
    else:
        return 'UNCERTAIN'


def _verdict_simhash(dist: int, kind: str = 'code') -> str:
    """kind: 'code' (x86 mnemonic 4-gram) or 'text' (byte n-gram)"""
    if kind == 'text':
        near, similar, unrelated = SIMHASH_TEXT_NEAR, SIMHASH_TEXT_SIMILAR, SIMHASH_TEXT_UNRELATED
    else:
        near, similar, unrelated = SIMHASH_CODE_NEAR, SIMHASH_CODE_SIMILAR, SIMHASH_CODE_UNRELATED

    if dist <= near:
        return 'NEAR-IDENTICAL'
    elif dist <= similar:
        return 'SIMILAR'
    elif dist > unrelated:
        return 'DIFFERENT'
    else:
        return 'UNCERTAIN'


# ============================================================
# 已知函数库 (从 YAML 加载)
# ============================================================

KNOWN = {}  # lazy-loaded by _load_known()

def _load_known():
    """Load known function hashes from known-functions.yaml."""
    global KNOWN
    if KNOWN:
        return KNOWN
    import yaml
    with open(_KNOWN_YAML, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    for e in data.get('entries', []):
        simhash_val = e['simhash']
        if isinstance(simhash_val, str):
            simhash_val = int(simhash_val, 16)
        KNOWN[e['name']] = {
            'ssdeep': e['ssdeep'],
            'simhash': simhash_val,
            'file': e['file'],
            'func': e['func'],
            'size': e['size'],
            'mnemonics': e.get('mnemonics', 0),
            'desc': e['desc'],
        }
    return KNOWN


# ============================================================
# 主逻辑
# ============================================================

def _detect_and_compare(h1: str, h2: str):
    """自动识别 hash 类型并比较，输出判定结论。"""
    if ':' in h1 and ':' in h2:
        score = ssdeep_compare(h1, h2)
        if score >= 0:
            print(f'ssdeep: {score}  [{_verdict_ssdeep(score)}]')
        else:
            print('ssdeep 格式无效', file=sys.stderr)
    elif h1.startswith('0x') or h2.startswith('0x'):
        try:
            dist = simhash_compare(int(h1, 16), int(h2, 16))
            print(f'simhash: {dist}  [{_verdict_simhash(dist, "code")}]  (Hamming distance)')
        except ValueError:
            print('SimHash 格式无效 (应为 0x 开头的十六进制)', file=sys.stderr)
    else:
        print('无法识别 hash 类型。包含 ":" = ssdeep, 以 "0x" 开头 = SimHash', file=sys.stderr)


def _search_library(engine: str, target, threshold):
    """在 KNOWN 库中搜索。"""
    _load_known()
    results = []
    for name, info in KNOWN.items():
        if engine == 'ssdeep':
            score = ssdeep_compare(target, info['ssdeep'])
            if score >= threshold:
                results.append((name, score, info))
        else:
            dist = simhash_compare(target, info['simhash'])
            if dist <= threshold:
                results.append((name, dist, info))

    if engine == 'ssdeep':
        results.sort(key=lambda x: -x[1])
    else:
        results.sort(key=lambda x: x[1])

    if not results:
        print('未找到匹配')
        return
    for name, val, info in results:
        if engine == 'ssdeep':
            print(f'{name}: ssdeep={val}  [{info["desc"]}]')
        else:
            print(f'{name}: simhash_dist={val}  [{info["desc"]}]')


def main():
    parser = argparse.ArgumentParser(description='ssdeep + SimHash 双引擎模糊哈希')
    parser.add_argument('--hex', help='十六进制字节字符串')
    parser.add_argument('--file', help='二进制文件路径')
    parser.add_argument('--start', help='文件起始偏移')
    parser.add_argument('--size', type=int, default=0, help='读取字节数')
    parser.add_argument('--cmp', nargs=2, metavar=('H1', 'H2'), help='对比两个 hash')
    parser.add_argument('--cmp-str', nargs=2, metavar=('S1', 'S2'), help='对比两个原始字符串 (ssdeep + SimHash, 默认忽略大小写)')
    parser.add_argument('--case-sensitive', action='store_true', help='--cmp-str 区分大小写')
    parser.add_argument('--cmp-file', metavar='FILE', help='从文件读两行 hash 对比')
    parser.add_argument('--search', nargs=2, metavar=('ENGINE', 'TARGET'),
                        help='在库中搜索 (engine: ssdeep|simhash)')
    parser.add_argument('--threshold', type=int, help='阈值 (ssdeep默认80, simhash默认10)')
    parser.add_argument('--print-library', action='store_true', help='打印已知库')
    parser.add_argument('--json', action='store_true', help='JSON输出')
    parser.add_argument('--arch', choices=['x86', 'x64'], default='x64', help='目标架构 (默认x64)')

    args = parser.parse_args()

    # 查看库
    if args.print_library:
        _load_known()
        for name, info in KNOWN.items():
            print(f'{name}')
            print(f'  ssdeep:  {info["ssdeep"]}')
            print(f'  simhash: 0x{info["simhash"]:016x}')
            print(f'  file:    {info["file"]}  func: {info["func"]}  size: {info["size"]}B')
            print(f'  desc:    {info["desc"]}')
            print()
        return

    # 文件对比
    if args.cmp_file:
        try:
            with open(args.cmp_file, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f if l.strip()]
            if len(lines) < 2:
                print(f'文件需要 2 行 (每行一个 hash), 实际 {len(lines)} 行', file=sys.stderr)
                return
            _detect_and_compare(lines[0], lines[1])
        except FileNotFoundError as e:
            print(f'文件不存在: {e}', file=sys.stderr)
        return

    # 直接对比
    if args.cmp:
        _detect_and_compare(args.cmp[0], args.cmp[1])
        return

    # 原始字符串对比
    if args.cmp_str:
        fuzzy_compare_str(args.cmp_str[0], args.cmp_str[1],
                          case_sensitive=args.case_sensitive)
        return

    # 搜索
    if args.search:
        engine, target = args.search
        if engine == 'ssdeep':
            _search_library('ssdeep', target, args.threshold or 80)
        elif engine == 'simhash':
            _search_library('simhash', int(target, 16), args.threshold or 10)
        else:
            print('engine 只能是 ssdeep 或 simhash', file=sys.stderr)
        return

    # 计算 hash
    if args.hex:
        code = bytes.fromhex(args.hex.replace(' ', '').replace('\n', ''))
    elif args.file and args.start:
        offset = int(args.start, 16) if args.start.startswith('0x') else int(args.start)
        with open(args.file, 'rb') as f:
            f.seek(offset)
            code = f.read(args.size)
    else:
        parser.print_help()
        return

    ssh = ssdeep_hash(code)
    sh = simhash_from_bytes(code, args.arch)
    mn = simhash_mnemonics(code, args.arch)

    if args.json:
        import json
        print(json.dumps({
            'ssdeep': ssh, 'simhash': f'0x{sh:016x}',
            'bytes': len(code), 'mnemonics': len(mn),
        }))
    else:
        print(f'ssdeep:    {ssh}')
        print(f'SimHash:   0x{sh:016x}')
        print(f'bytes:     {len(code)}')
        print(f'mnemonics: {len(mn)}')


if __name__ == '__main__':
    main()
