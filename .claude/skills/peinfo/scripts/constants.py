#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""常量库 —— 国家级工具特征常量 + 加密算法常量。

只放「已知可复用的常量」，避免每次分析重新查。
数据来源：NSA Equation Group / DanderSpritz 泄露样本实测（见 nation-state-signatures.md）。
"""

# ============================================================================
# 一、加密算法常量（NSA Equation Group / DiBa 家族实测）
# ============================================================================

# CR-001 LCG 流密码（资源封装 / 数据解密）
# 递推：seed = (0xDD483B8F - 0x6033A96D * seed) mod 2^32；xor_byte = (seed >> 8) & 0xFF
CR001_LGC_MULT = 0x6033A96D
CR001_LGC_ADD = 0xDD483B8F

# CR-007 单字节替换表（95 字节双射，0x20-0x7E 排列）
# 加密：cipher = table.index(plain) + 0x20
# 解密：plain = table[ord(cipher) - 0x20]   （注意方向，早期 fact 记反过）
CR007_SUBSTITUTION_TABLE = r"""7;]KED<\{OtA}~5F#+rq@xLU9V0_P,)-yY:WSiwc&p*v`=31"GINuX4hk g2'eQ([.|o$J>dsmz?jTbBlH/%CR!f8Za^6Mn"""

# CR-011 glibc rand LCG（字符串解密）
# 递推：seed = (0x41C64E6D * seed + 0x3039) mod 2^32；xor_byte = (seed >> 16) & 0xFF
CR011_GLIBC_MULT = 0x41C64E6D  # 1103515245
CR011_GLIBC_ADD = 0x3039       # 12345

# CR-013 Numerical Recipes LCG 流密码（DiBa 内嵌驱动实测：10_102.sys=fvepxy.sys / 10_108.exe）
# 递推：seed = (0x19660D * seed + 0x3C6EF35F) mod 2^32
# 两变体（调用封装 sub_1FA2E 单字节 / sub_1FA00 宽字符）：
#   单字节：byte ^= (seed >> 16) & 0xFF | 0x80
#   宽字符：word ^= (seed >> 16) & 0xFFFF | 0x8000
# 每个被混淆字符串有独立 seed（存于调用点数组）。
# 实测用途：
#   fvepxy 单字节 = SSDT hook 服务名（ZwCreateThread/NtClose 等，seed 数组 sub_22071）
#   fvepxy 宽字符 = 设备名/模块名（\Driver\ / \Device\Null / ntdll.dll / ZwClose）
#   10_108.exe 宽字符 = bootkit 启动配置检测（SAFEBOOT / SystemBootDevice /
#                      \Registry\Machine\System\Select / SystemStartOptions）
#   10_100.sys HIBYTE 变体 = 配置块字段加密（Data[8]=加密计数器 / Data[9]=版本上限）
#      byte ^= (seed >> 24) & 0xFF（取最高字节，不强制 bit7；字段 N 递推 N-3 次）
# 自动定位：scan.scan_cr013_strings() 扫 .text 的 mov eax,imm16(负)+push imm32(seed) 模式。
CR013_NR_MULT = 0x19660D        # 1664525
CR013_NR_ADD = 0x3C6EF35F       # 1013904223

# CR-014 LCG 环境变量名生成（10_111.exe 用户态 helper 实测）
# 递推：seed = 0x29AF3011 * seed + 0x933D10AC (mod 2^32)
# 用途：从 PID 派生 12 字母环境变量名 Name[i] = seed % 26 + 65 (A-Z)
# 配合 GetEnvironmentVariableW 读值 + base-26 解码 + SetEvent 触发（DiBa 用户态 IPC）
DIBA_ENV_LCG_MULT = 0x29AF3011  # 699346961
DIBA_ENV_LCG_ADD = 0x933D10AC   # -1824714580 (mod 2^32)

# ============================================================================
# 二、magic 值（NSA DiBa bootkit 实测）
# ============================================================================

# PRNG 未初始化哨兵（DiBa 本体 sub_1002B9F4 的 5 熵源 PRNG）
MAGIC_PRNG_UNINIT = 0xBB40E64E  # 十进制 -1153374642
# 2026-09-15: 原名 MAGIC_PRNg_UNINIT 拼写有误（小写 g），已更正。全仓库无引用，改名安全。

# DiBa 安装函数 sub_10007575 内部 magic
MAGIC_DIBA_INSTALL = 0xBB370A33  # 十进制 -1153859789

# 10_109.bin 配置文件的 magic（DiBa 内嵌数据）
# 结构: [0x00]=版本2 / [0x04]=0x01030300 / [0x08]=0x01030300 / [0x0C]=magic / [0x10+]=填充
# DLL 验证: cmp [ecx],2(版本==2) + cmp [ecx+0xc],0xD0C0FFEE(magic) 双重验证后读取
MAGIC_DIBA_CONFIG = 0xD0C0FFEE  # 字节序 ee ff c0 d0

# ============================================================================
# 三、PDB GUID（NSA DiBa bootkit 内嵌驱动，实测）
# ============================================================================
# 这些 GUID 是「驱动身份指纹」。命中 = 该驱动是 NSA 修改版（去版本资源 + 注入 rootkit）。
# 用于查证：对比微软官方同名驱动的 PDB GUID，确认是否「修改版」。

PDB_GUIDS = {
    # 10_102.sys = fvepxy.sys（NSA 自定义驱动，非微软；伪装 fvevol，公开零记录）
    'fvepxy': {
        'guid': '77ee4659-0de7-4d6e-b814-5419bf4b6531',
        'age': 15,
        'note': 'NSA 自定义驱动，注入 SSDT/进程注入/反射加载，自定义 .MSRK 段，释放到 system32\\drivers\\fvepxy.sys',
    },
    # 10_104.sys = drmkflt 驱动（导入 fvepxy.__RCSO/__UCSO）
    'drmkflt': {
        'guid': 'fecd64c2-2a25-43bc-b727-32fa07b073fc',
        'age': 15,
        'note': '内存操作/反射加载驱动，通过 fvepxy 注册接口协同',
    },
    # 10_106.sys = hidsvc.sys（进程注入/反射加载/对象管理）
    'hidsvc': {
        'guid': '2596320c-0d7c-4745-a815-0be20de38dca',
        'age': 1,
        'note': '进程注入/反射加载/对象管理驱动，独立构建（age 1）',
    },
}

# ============================================================================
# 四、算法 ↔ 组件对照（DiBa bootkit 三层加密原语）
# ============================================================================
# 用途：快速判断「某个组件用哪种加密」，少走弯路。

CRYPTO_BY_COMPONENT = {
    'DiBa 本体 DLL': 'CR-007 替换表（字符串）+ CR-001 LCG（资源）',
    '内嵌驱动 10_104.sys': 'CR-011 glibc rand（字符串，解密内核 API 名）',
    '内嵌资源封装': 'CR-001 LCG + zlib（[4B seed][LCG: 4B size + zlib stream]）',
    'C2 通信': 'RC4 + 随机 session key（前 16 字节 = key，后续 = 密文）',
}

# DiBa 内嵌资源封装格式说明
# 每个 RT_RCDATA 资源：前 4 字节 = seed（LE），剩余 = LCG 加密的 [4 字节解压后大小 + zlib 流]
RESOURCE_FORMAT_DIBA = '[4B seed LE] + LCG_encrypt([4B decompressed_size] + zlib_stream)'

# ============================================================================
# 五、hidsvc.sys (10_106.sys) 独有常量（NSA DiBa bootkit 内嵌驱动，实测）
# ============================================================================

# hidsvc IRP dispatcher (sub_1189B) 的 8 个 IOCTL 码
# Check Point 2021 仅记录 0x85892408，本文 IDA 实测补全 8 个
HIDSVC_IOCTL_CODES = [0x85892400, 0x85892404, 0x85892408, 0x8589240C,
                      0x85892410, 0x85892414, 0x85892418, 0x8589241C]

# hidsvc 内部命令 ID（sub_142AC 次级分发）
HIDSVC_COMMAND_IDS = [0x222000, 0x222004, 0x222008, 0x22200C, 0x222010]

# hidsvc Pool tag "File"（ExAllocatePoolWithTag 标签，0x656C6946 = 'File' LE）
# 2026-08-27 实测：extracted/hidsvc.sys + 10_106.sys 两真样本均无此字节(count=0)，
# 疑运行时经变量传入 ExAllocatePoolWithTag，非静态立即数。不能作静态 YARA/VT 锚点。
POOL_TAG_FILE = 0x656C6946

# hidsvc API hash 算法乘数（position-weighted XOR over export name）
# val = 0; for i in 1..len: val ^= ((0x1A6B8613 * i) * name[i-1]) mod 2^32
# 见 nation-state-signatures.md CR-003
HIDSVC_API_HASH_MULT = 0x1A6B8613

# hidsvc 设备名（CR-013 宽字符解密，seed 0x17B4，scan.scan_cr013_strings 实测）
# 伪装微软卷影复制服务 msvss.sys
HIDSVC_DEVICE_NAME = '\\Driver\\msvss'

# ============================================================================
# 六、10_100.sys 服务配置维护驱动独有常量（NSA DiBa bootkit 内嵌驱动，实测）
# ============================================================================

# 10_100.sys 向其他驱动发命令的 IOCTL（sub_11B60 IoBuildDeviceIoControlRequest）
# device type 0x22 家族，与 mpdkg32 的 0x220000 系列同族（0x223F5C = 0x220000 + 0x3F5C）
DIBA_SVC_IOCTL = 0x223F5C

# 10_100.sys 维护的加密配置块：服务注册表 \\Parameters\\Data 值
# 格式：Data[0..3]=LCG seed；Data+12 子结构字段8=加密计数器 / 字段9=版本上限
# 解密：字段 N 的 keystream = HIBYTE(LCG^(N-3)(seed)) = (seed>>24)&0xFF（CR-013 HIBYTE 变体）
DIBA_SVC_CONFIG_VALUE = '\\Parameters\\Data'

# ============================================================================
# 七、DiBa SOTI 引导扇区持久化独有常量（NSA DiBa bootkit，实测）
# ============================================================================
# 来源：diba_errors.py（EQGRP 泄露）+ IDA 反编译 DiBa_Target_BH_2000.dll i386

# DiBa 四种持久化类型（Mcl_Cmd_DiBa_Tasking.py _CMD_PERSIST_TYPE_*）
#   DEFAULT=0  默认（按系统自动选）
#   LAUNCHER=1 launcher driver/thunk 服务持久化（对应 LC-026 驱动释放+服务注册）
#   SOTI=2     引导扇区持久化（本文件本节，对应 LC-027）
#   JUVI=3     JUVI 持久化（payload 未支持）
DIBA_PERSIST_TYPES = {
    0: 'DEFAULT',
    1: 'LAUNCHER',
    2: 'SOTI',
    3: 'JUVI',
}

# SOTI 写盘 Native API（动态解析，导入表 WriteFile=0 佐证）
#   sub_1002319F = ZwCreateFile（打开卷，GENERIC_READ 0x80000000）
#   sub_10022DE8 = ZwReadFile（读扇区，错误码 481 = DB_FAILURE_READFILE_FAILED）
#   对称 ZwWriteFile（错误码 480 = DB_FAILURE_WRITEFILE_FAILED "Native ZwWriteFile failed"）
DIBA_SOTI_NATIVE_APIS = ['ZwCreateFile', 'ZwReadFile', 'ZwWriteFile']

# SOTI boot sector MD4 hash 验证（写 VBR 前比对 known-good 列表）
# advapi32 SystemFunction007 = MD4（动态 LoadLibrary + GetProcAddress，非导入）
# 错误码: DB_ST_FAILED_TO_PERFORM_BOOT_SECTOR_HASH_VERIFICATION=682 / DB_ST_UNKNOWN_BOOT_SECTOR_FOUND=683
DIBA_SOTI_MD4_API = ('advapi32', 'SystemFunction007')

# SOTI VBR OEM ID 校验（sub_1000F2EC memcmp boot sector 偏移+3 的 9 字节）
# 标准 NTFS VBR = "NTFS    "；DiBa 自定义 = "NTFDS"（10_107.bin 双 boot sector）
# 注意: 写的是 VBR（卷引导记录），非 MBR（主引导记录）——OEM ID 字段是 VBR 特征
DIBA_SOTI_OEM_NTFS = 'NTFS'
DIBA_SOTI_OEM_DIBA = 'NTFDS'

# SOTI payload 隐藏机制：payload 藏 NTFS container 文件，boot sector 经 object id 定位
#   St_GenerateContainerFileName: GetSystemWindowsDirectoryW + 16 次尝试避冲突
#   St_GetObjectId: ZwQueryInformationFile FileObjectIdInfo 取 NTFS object id
#   St_OpenFileById: Native ZwCreateFile 按 object id 打开（非文件路径，绕过文件系统枚举）
# 10_107.bin = 双 boot sector（NTFS/NTFDS）；10_101.bin = 加密 shellcode payload（仿射密码）
