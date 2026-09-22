# 方案级冲突的解决：选项、实测与决定

> 生成于 round 71（目标恢复后）。本文件把两个一直阻塞 P2-S / P2-V / P2-I 的**方案级冲突**按
> `improve-codebase-architecture` skill 的框架（depth / leverage / seam / **deletion test**）拆成候选方案，
> 并**用实测**筛掉不能用的选项。所有数字都来自可复现的模拟：把 `src/` 与 `tests/` 复制到 `.scratch/sim/`，
> 在**副本**里实施变更，再跑真实测试套件，与**同一副本的对照组**比较失败节点集合。
>
> 关键的实验设计：对照组不是仓库基线，而是**未做变更的同一份副本**——因为副本本身会带来 12 个
> collection error（那些测试需要仓库根或样本文件）。只有与对照组比较，才能把「搬家的影响」与「复制的
> 影响」分开。这一步是我第一轮模拟做错的地方：当时拿副本结果直接对比仓库基线，把 12 个复制伪影读成了
> 12 个新失败。

## 冲突 1：`static/` 资源目录 vs `static/` 包名 —— 已解决（提交 `65b86ac`）

### 实测事实

| 事实 | 值 |
|---|---|
| 引用该**目录**的位置 | `main.py` 的 `asset_path`（1 处定义 + 1 处 `FileResponse`）、`pyproject.toml` 的 `package-data` 一行 |
| 挂载 URL 与目录的关系 | **互相独立**：`app.mount("/static", StaticFiles(directory=…))` |
| 现有测试是否覆盖 `/static` | **否**，0 处（所以改名若破坏挂载，套件不会发现） |
| 资源体积 | 3 个文件，33 KB |

### 候选与判定（deletion test）

| 选项 | 判定 |
|---|---|
| **A. 改资源目录名，保留挂载 URL**（选中） | 删掉这个改动，复杂度不会在别处重现——它只影响 2 行路径与 1 行 `package-data`；URL 面**逐字节不变** |
| B. 把包改名（`static/` → 别的名字） | 会与已复核方案的词汇、`docs/import-policy.json` 的分层规则冲突；把复杂度从 3 个文件扩散到该包全部未来 import |
| C. 让资源目录同时当包（加 `__init__.py`） | 不可行：`packages.find` 无 excludes，且 `package-data` 已把 `static/*` 当数据，会改变发布产物 |

### 决定与执行

目录改名 `static/ → assets/`，挂载 URL 保持 `/static`。落地内容：
`git mv` 三个文件（逐字节校验）＋ `pyproject.toml` 的 `"static/*" → "assets/*"` ＋ 新增
`tests/test_workbench_assets.py`（4 个测试）——**这是本次解决里唯一新增的可测面**，因为此前没有任何测试
请求过 `/static`。部署侧：`check-deployed-code-hashes.py` 是从磁盘枚举的，改名无需改门禁；实测重建镜像后
8 服务 × 81 文件全绿。

## 冲突 2：`investigation/`、`intake/` 包遮蔽同名模块 —— 已定案（方案已验证，实施待做）

### 实测事实

| 事实 | 值 |
|---|---|
| 此前记录的失败 | 145 个 ImportError（朴素搬运） |
| `recovered_thread_start_address` 的模块级导入者 | **5 个**：`emulation_plan`、`persist_how`、`reporting`、`service`、`static_analysis`（外加 `investigation` 自身使用） |
| `static_analysis.py:16` 的导入 | 模块级 `from threat_report_agent.investigation import recovered_thread_start_address` |
| `investigation` 的**模块级**出边 | 8 个，其中**没有**指向 `static_analysis` 的路径（`investigation → static_analysis` 只存在于**函数内**延迟导入，`investigation.py:5346`） |

### 候选与判定（全部实测）

| 选项 | 实测结果 | 判定 |
|---|---|---|
| **A. `sys.modules` 重绑**（包把自己替换成实现模块） | **157** 个 collection error；且 `from threat_report_agent.investigation import investigation_protocol` **直接失败**（替换后的模块没有 `__path__`，第二个模块再也放不进这个包） | 否决：与方案 7.7「一个包里放多个模块」不兼容 |
| **B. 立即式命名空间拷贝**（`globals().update(vars(impl))`） | **157** 个 collection error：包初始化时立刻导入实现，实现又被 `static_analysis:16` 反向解析成**半初始化**模块 | 否决 |
| **C. 惰性 `__getattr__` 门面**（PEP 562） | `intake.py` 单独搬：失败节点集合与对照组**完全一致**；`investigation.py` + `investigation_protocol.py` 一起搬：**157** 个新失败 | **对无环模块可用；对 `investigation` 不够** |
| **C + 把共享谓词下移到 `facts/`** | 把 `recovered_thread_start_address` 移入 `facts/thread_start.py` 并把 5 个模块级导入者改指新家后，再套用 C：失败节点集合与对照组**完全一致**（12 = 12，新增 0） | **选中** |

### 根因（实测得出，不是推测）

`threat_report_agent.investigation` 一旦变成**包**，`from …investigation import X` 就多了一层解析：包的
`__init__` 完成后，导入系统必须从*实现模块*取这个名字，而此刻实现模块可能正处于**半初始化**状态——
`static_analysis.py:16` 正卡在自己的导入过程中。今天之所以能work，是因为 `investigation` 是模块时
`static_analysis` 先导入它、而它回指 `static_analysis` 的那条边**已经在函数内延迟**；包化让这条单边依赖
变成了重入。直接证据：在副本里调用门面的 `__getattr__` 抛 `AttributeError`，而紧接着
`importlib.import_module('…investigation.investigation')` 却成功且**含有**该名字——即失败时刻的实现模块是
半初始化的。

### 决定与执行顺序

1. **P2-I（intake）现在就能做**：474 行、2 个生产导入者、3 个测试文件，用惰性门面，实测零新增失败。
2. **P2-V（investigation）先做「下移共享谓词」这一步**：`recovered_thread_start_address` 是纯
   mapping→str 的溯源谓词，被 5 个模块在**模块级**导入——按 `facts/` 层「拥有谓词」的定位，它本来就该在
   `facts/`。移到 `facts/thread_start.py` 并把导入者改指新家，既解环又加深了模块（deletion test：这个改动
   被删除后，5 处调用点会各自重新实现或继续跨层伸手，复杂度不会消失）。
3. 然后才搬 `investigation.py`（+ `investigation_protocol.py` 等）并按 §7.1 第 5 步逐个改调用方。

### 诚实的限制

- 模拟是**副本 + 真实套件**，但不是真实迁移：它没有覆盖部署冒烟、导入图门禁、结构 diff 门禁，也没有覆盖
  `reporting.py`/`service.py` 之外那些把 `investigation._name` 当属性访问的写法（实测为 0 处）。
- 对照组本身有 **12 个 collection error**，全部是副本伪影（需要仓库根或样本文件的测试）。这意味着模拟里
  **真正的回归判据是「新增 0」**，而不是「6 个基线失败」。
- 惰性门面的 `from … import *` 不会经过 `__getattr__`；实测仓库内对这两个模块的星号导入为 **0** 处，但这是
  一个必须随迁移一起复验的前提。
