# OLLVM-NDK 混淆使用手册

> [English](./USAGE_en.md) | 简体中文

> 本文档是 [README（中文）](./README.zh-CN.md) 的详细补充，集中收录**混淆参数速查表**与**混淆前后效果对比**（IDA 反汇编视图 / Graph View）。
> 快速上手请看 [README（中文） · 快速开始](./README.zh-CN.md#快速开始)。

## ⚠️ 参数语法规则

每个 `-mllvm` 后面的 LLVM 选项**必须带自己的 `-` 前缀**：

```bash
# ✅ 正确
clang -O2 -mllvm -irobf-bcf file.c -o file

# ❌ 错误（缺少选项前面的 -）
clang -O2 -mllvm irobf-bcf file.c -o file
```

---

## 混淆参数速查表

所有混淆参数通过 `-mllvm -<参数名>` 传递给编译器。

| 参数名 | 取值 | 默认值 | 说明 |
|:---|:---:|:---:|:---|
| **入口** | | | |
| `-irobf` | bool | false | 总开关（配合配置文件使用） |
| `-oboro-cfg` | string | "" | JSON 配置文件路径 |
| `-irobf-level` | int | 0 | 所有支持 level 的功能的默认强度 0–3；config 里各功能自己的 `level` 优先 |
| **OLLVM 原有** | | | |
| `-irobf-indbr` | `[=table\|full\|dual]` | 关闭 | 间接分支。不带值 = `table`（页表）；`full` = 无条件 `br` 也走页表；`dual` = 双目标 `blockaddress`。三种模式都在末端管线执行 |
| `-irobf-icall` | bool | false | 间接调用 |
| `-irobf-indgv` | bool | false | 间接全局变量 |
| `-irobf-fla` | bool | false | 控制流平坦化 |
| `-irobf-cse` | bool | false | 字符串加密 |
| `-irobf-cie` | bool | false | 整数常量加密 |
| `-irobf-cfe` | bool | false | 浮点常量加密 |
| `-irobf-rtti` | bool | false | 擦除 MSVC RTTI |
| **新功能** | | | |
| `-irobf-bcf` | `[=0..100]` | 关闭 | 虚假控制流 v2。不带值 = 强度 70 |
| `-irobf-decoy` | `[=0..100]` | 关闭 | 运行时诱饵路径（独立功能，不依赖 BCF）。不带值 = 30% 的站点走诱饵菱形，其余为纯 poison |
| `-irobf-rename` | bool | false | 内部符号随机重命名：函数 + 全局 + 别名。只对仍存在的 internal 符号生效（O1+ 会内联掉大部分）。调试信息不归本 pass 管，发布构建用 `-g0` 或 `strip --strip-debug` |
| `-irobf-aux` | `[=wrap,shuffle,split]` | 关闭 | 结构性后处理。不带值 = 三项全开 |

### 各功能的子配置（只走 config）

每个功能只接受自己域内的字段；写了不属于该功能的字段会打印 warning 并忽略。

| 功能 | 字段 | 默认 | 说明 |
|:---|:---|:---:|:---|
| `indbr` | `mode` | `table` | `table` / `full` / `dual` |
| | `split` | 0 | 间接化前把块拆到最多 N 条指令（0 = 不拆） |
| | `level` | 0 | 解密循环层数 1–3 |
| `icall` / `indgv` / `cie` / `cfe` | `level` | 0 | 各自的强度 |
| `cse` | `shared` | false | 全模块共用一个解密器（体积优先） |
| `bcf` | `strength` | 70 | 站点概率 0–100 |
| | `budget` | 16 | 每函数站点绝对上限（0 = 不限） |
| | `budget_pct` | 20 | 占可插桩块百分比（0 = 不用） |
| `decoy` | `ratio` | 30 | 站点中诱饵菱形的比例（0–100），其余站点为纯 poison |
| | `pollute` | false | L3 值污染 |
| | `probe` | `__oboro_probe` | App 提供的 probe 符号名 |
| `aux` | `wrap` | 100 | 转发包装概率 |
| | `shuffle` | true | 基本块乱序 |
| | `split` | 3 | 每函数最多切几刀 |

全局字段：`seed` / `randomSeed`、`ptrauth`、`deny`、`patterns`。

### 附加 pass 的边界

| 项 | 行为 |
|---|---|
| `-irobf-aux=wrap` | 默认 100% 全量包装，体积明显增加。只对 ABI 安全的函数生效（跳过 `main`、vararg、`alwaysinline`、`byval`/`sret`/`inalloca`、probe 符号） |
| `-irobf-aux=shuffle` | 只改基本块物理顺序，不改 CFG |
| `-irobf-aux=split` | 每函数最多切 `aux.split` 刀（默认 3，上限 7） |
| `-irobf-indbr`（全部模式） | 在末端管线执行：在 PipelineStart 跑会被后续 SimplifyCFG 折回（实测 39 个分支只剩 13 个）。代价是解密代码不参与优化，体积比早期挂载高约 10–20% |
| `-irobf-indbr=dual` | 双目标 `blockaddress`，**不做块拆分**（`indbr.split` 对 dual 无效），与页表模式互斥 |

隐藏的测试开关（不要用于生产）：`-irobf-bcf_pred`、`-irobf-bcf_topo`、`-irobf-force-decoy`、`-irobf-force-real`、`-irobf-debug-names`。

---

## 当前支持的混淆参数

### 基础启用

| 参数 | 说明 |
|---|---|
| `-mllvm -irobf` | 统一启用所有已通过配置文件开启的混淆 |

---

### 控制流混淆

#### 控制流平坦化 (FLA)
```bash
-mllvm -irobf-fla
```
将函数内所有基本块放入一个 switch-loop 分发器，隐藏原始控制流结构。switch 值通过 XOR 加密，对抗 IDA 值追踪。

> 超过 50 个基本块的函数自动跳过：平坦化会让 switch 分发器和 PHI 数量爆炸（zlib 的 `inflate`/`deflate` 实测 90s 不收敛）。

#### 虚假控制流 (BCF) v2
```bash
-mllvm -irobf-bcf=70      # 可选，块注入概率 0~100，默认 70
-mllvm -irobf-bcf_pred=3       # 可选，强制谓词族 1~12（0=随机，测试用）
```

为每个基本块注入**不透明谓词菱形**：真路走原代码，假路是永不执行的死块（内含
反编译器毒载荷）。谓词**每次编译随机**从 12 个数学族中选择（全部对 2^64 回绕
安全、经 InstSimplify 折叠筛选存活），并叠加随机输入变换、随机极性翻转、1/5
概率双族组合。谓词输入来自**多个独立熵源**：模块级 volatile 全局池与函数栈
锚点（entry 块 alloca 地址，指针宽度按 DataLayout 取），每个站点独立选源；
naked / 协程 / 带 personality 或 funclet 的函数自动回退到全局池。

生产权重只使用规则引擎不可折叠的族（5/8 连续积链、9/11 popcount、12 八连积），
按 d810 代理（`obftest/d810_proxy.py`）实测：这 5 族的规则可折叠率为 **0%**；
族 1/2/3/4/7（bit0 低位恒等式）与 6/10（MBA 恒等式）可被规则引擎折叠，权重置 0，
仅保留 `-irobf-bcf_pred` 强制供回归测试。

毒载荷同样全随机化：AArch64 用 SP 收敛投毒（`add sp, sp, #随机值`，制造
Hex-Rays `sp-analysis failed`）；x86_64 用随机字节序列制造 JUMPOUT（跳入指令
中部）。旧的固定指纹（`#0x100` / `B8 11 11 11 11`）已全部消除。

**效果**：IDA 图形视图出现大量菱形、反编译质量下降或失败；对自动化脚本 / LLM
逆向代理的破坏杠杆最大。

```bash
# 对所有块强制 100% 注入
clang -O2 -mllvm -irobf-bcf=100 test.c -o test
```

> 运行安全：谓词在数学上恒真，死块永不执行；安全性来自「不可达」，不是
> 「栈不平衡也能跑」。

**异常处理**：Itanium EH（Android/Linux，`__gxx_personality_v0`）函数正常参与
混淆，但 `landingpad`/EH pad 块与 `invoke` 终止符永不改写，unwind 边和 LSDA
call-site 范围保持不变；scoped EH（Windows MSVC funclets / Wasm）仍整体跳过
（funclet 内调用必须携带 operand bundle，菱形跨 funclet 边界风险不可控）。

#### decoy 反模拟执行（独立机制，与 BCF 正交，默认关闭）

decoy 是**独立于 BCF 的运行时误导机制**，不是 BCF 的变体：BCF 的判据是静态
恒真谓词（骗静态分析），decoy 的判据是**运行时 probe 结果**（骗模拟器/调试器），
环境可疑时诱饵路径会真实执行。二者共享站点/分支生成代码，但数学基础与用途
完全不同。

工具链**不做任何环境检测**——检测由你的 App 实现，通过弱符号 `__oboro_probe`
提供判定结果（非 0 = 真实路径，0 = 诱饵路径）：

```c
// 你的 App 源码（不进工具链仓库）
extern "C" int __oboro_probe(void);
extern "C" int __oboro_probe(void) {
    // 你的检测逻辑：模拟器 / 云手机 / 调试器 / 篡改 ... 由你定义
    return suspicious ? 0 : 1;
}
```

**启用方式**：`-irobf-decoy[=比例]` 全局开启（默认 30% 函数），或用**函数注解** / **config pattern** 按函数精确控制。
decoy 是独立功能域，不依赖 `-irobf-bcf`。

```c
__attribute__((annotate("+decoy")))          // 该函数启用 decoy（L1）
__attribute__((annotate("^decoy=50")))       // 该函数 50% 的站点走诱饵
__attribute__((annotate("+decoy_pollute")))  // 升级到 L3 值污染
```

```json
{ "patterns": [
  { "match": "Crypto::**", "decoy": { "enable": true, "ratio": 80, "pollute": true } }
] }
```

| 级别 | 行为 | 运行时结果 |
|---|---|---|
| **L1 重汇聚** | 诱饵块执行纯计算噪声后回到真实块重算 | **完全正确**（只增加 trace 噪声） |
| **L3 值污染** | 诱饵块是原块的克隆 + 安全常量变异，绕过真实块直达后继 | **错误但可执行**（分析者拿到不可信结果） |

L3 有硬性危险链过滤：变异值一旦触达除法/取余、内存地址、数组下标、调用参数、
分支条件、间接跳转、FP→int、原子操作，该站点自动回退 L1。默认每函数最多 4 个
L3 站点。

**传输层**：双份 share（`env ^ K1`、`env ^ K2`），密钥由函数地址（ASLR 随机）
派生、不落盘；每次函数调用校验两份 share，不一致则置粘性 `tampered`，后续全部
走诱饵。没有运行时采样。

测试开关（hidden）：`-mllvm -irobf-force-decoy`（强制诱饵）、`-mllvm -irobf-force-real`（强制真实）。
自定义 probe 符号名走 config：`"decoy": {"probe": "my_probe"}`。

> 无 probe、未初始化、probe 签名不匹配 → 默认走真实路径（fail-open），
> 保证产物在真机 / 模拟器 / 云手机 / 任意架构上都能稳定运行。

**部署约束（实测）**：

| 场景 | 结论 |
|---|---|
| probe 与混淆代码同一编译单元 / 同一 .so | ✅ 正常工作（推荐，`hidden` 可见性即可） |
| 多个混淆 .so，每个自带 probe | ✅ 各自绑定自己的 probe（RTLD_LOCAL 下互不干扰，已实测） |
| probe 在静态库 `libprobe.a` 里，普通链接 | ❌ **不会被提取**（工具链的弱定义已满足引用）→ decoy 静默失效 |
| probe 在静态库 + `-Wl,--whole-archive` | ✅ 正常工作（已实测） |
| 跨 .so 依赖（A.so 的 probe 给 B.so 用） | ❌ 不支持，probe 必须编进每个混淆 .so 的同一链接单元 |

---

### 间接化混淆

#### 间接分支 (INDBR)
```bash
-mllvm -irobf-indbr
-mllvm -irobf-level=1        # 可选，解密循环层数 1~3
```
条件分支目标地址通过加密页表（PageTable）在运行时 XOR 解密后跳转，IDA 无法静态分析跳转目标。


#### 间接调用 (ICALL)
```bash
-mllvm -irobf-icall
```
将直接函数调用替换为经过加密页表间接化的调用，函数地址在运行时动态解密。

#### 全局变量间接化 (INDGV)
```bash
-mllvm -irobf-indgv
```
全局变量的访问地址通过加密页表间接化，防止逆向工具静态定位全局变量。

---

### 数据混淆

#### 字符串加密 (CSE)
```bash
-mllvm -irobf-cse
```
所有字符串常量运行时才解密，防止 `strings` 命令或 IDA 直接提取明文。

#### 整数常量加密 (CIE)
```bash
-mllvm -irobf-cie
-mllvm -irobf-level=1          # 可选
```
对整数类型的常量进行运行时解密保护。

#### 浮点常量加密 (CFE)
```bash
-mllvm -irobf-cfe
```
对浮点类型的常量进行加密。

---

### 其他

#### RTTI 擦除 (RTTI)
```bash
-mllvm -irobf-rtti
```
擦除 C++ RTTI 信息，防止逆向工具通过类型信息还原类结构（实验性）。

---

## 推荐组合

### 标准混淆（性能影响小）
```bash
-mllvm -irobf-cse \
-mllvm -irobf-icall \
-mllvm -irobf-indbr
```

### 强力混淆（中）
```bash
-mllvm -irobf-fla \
-mllvm -irobf-icall \
-mllvm -irobf-indbr \
-mllvm -irobf-cse \
-mllvm -irobf-bcf=80
```

### 最强混淆（完全）
```bash
-mllvm -irobf-fla \
-mllvm -irobf-icall \
-mllvm -irobf-indbr \
-mllvm -irobf-level=1 \
-mllvm -irobf-indgv \
-mllvm -irobf-cse \
-mllvm -irobf-cie \
-mllvm -irobf-bcf=100
```

---

## 使用配置文件（oboro）⭐ 推荐

推荐用 JSON 配置文件统一管理策略——**只改构建脚本，源码零侵入**：

```bash
-mllvm -oboro-cfg=obf_config.json
```

### 完整示例

```json
{
  "bcf":  { "enable": true, "strength": 70, "budget": 16, "budget_pct": 20 },
  "decoy": { "enable": true, "ratio": 30 },
  "fla":  { "enable": true },
  "cse":  { "enable": true },

  "seed": "0123456789abcdef0123456789abcdef",

  "deny": ["MyCodec::*", "vendor::**"],

  "patterns": [
    { "match": "crypto::aes::**", "decoy": { "ratio": 80, "pollute": true } },
    { "match": "License::verify", "decoy": { "ratio": 50 } },
    { "file": "*generated_*.cpp", "bcf": { "enable": false } }
  ]
}
```

### 字段说明

| 字段 | 含义 |
|---|---|
| `<pass>.enable` | 开关（`true`/`false`） |
| `indbr.mode` | `table` / `full` / `dual` |
| `indbr.split` | 间接化前把块拆到最多 N 条指令（0 = 不拆） |
| `indbr.level` / `icall.level` / `indgv.level` | 0 = 全模块共享页表（体积优先），1~3 = 每函数独立页表 + 解密循环层数 |
| `cie.level` / `cfe.level` | 加密强度 0~3，默认 2（0 = 只做一次减法，最弱） |
| `bcf.strength` | 站点概率 0–100（默认 70） |
| `bcf.budget_pct` | 每函数毒点占可插桩块的百分比（0–100，默认 20）。与 `budget` 都为 0 时回落到 16/20%，**不是不限** |
| `bcf.budget` | 毒点绝对上限（0 = 不设；>0 时与百分比取较小值） |
| `decoy.ratio` | 进入诱饵路径的函数比例（0–100，默认 30） |
| `decoy.pollute` | L3 值污染（默认 false） |
| `decoy.probe` | App 提供的 probe 符号名（默认 `__oboro_probe`） |
| `aux.wrap` / `aux.shuffle` / `aux.split` | 包装概率 / 块乱序 / 每函数切几刀 |
| `cse.shared` | `true` = 全模块共用 i8/i16 各一个解密器（长度运行期传参），体积优先；默认每个字符串独立解密器（抗分析优先）。**仅 config 可用，没有对应命令行开关** |
| `seed` / `randomSeed` | 32 位十六进制（16 字节）固定随机种子，**仅用于测试/审计/问题复现**；不填则每次构建随机（生产默认）。不要跨版本复用同一个 seed |
| `deny` | **红区名单**：命中的函数永不混淆，注解也无法解锁 |
| `patterns[].match` | 按 demangled 函数名匹配（类/命名空间） |
| `patterns[].file` | 按源文件名匹配（不含路径） |
| `patterns[].decoy.ratio` | 规则内覆盖 decoy 比例 |
| `patterns[].decoy.pollute` | 规则内覆盖 L3 开关 |
| `patterns[].bcf.strength` | 规则内覆盖 BCF 概率 |
| `patterns[].bcf.budget_pct` | 规则内覆盖 BCF 百分比（0 = 继承全局） |
| `patterns[].bcf.budget` | 规则内覆盖 BCF 绝对上限（0 = 继承全局） |

> 写了不属于该功能域的字段会打印 warning 并忽略（例如给 `fla` 写 `level`）。

### 匹配规则

| 模式 | 匹配 | 不匹配 |
|---|---|---|
| `test` | 全局 `test` | `Class::test`、`ns::test` |
| `Class::*` | `Class` 下一层成员 | 全局函数、更深层 |
| `Class::**` | `Class` 下任意深度 | 全局函数 |
| `**::test` | 任意作用域下的 `test`（含全局） | — |
| `**` | 所有函数 | — |

`*` 不跨 `::`，`**` 跨 `::`（与 ProGuard 同构）。重载按去参数名匹配（同名重载
一起命中）；含 `*` 的 `operator*` 无法用 pattern 精确匹配，请用函数注解。

### 优先级链（越具体越优先）

```
① 红区（内置硬底线）        永不混淆，注解也无效
② deny 名单（config）       永不混淆
③ 黄区（内置默认禁区）      默认跳过，仅逐函数 +xxx 注解或精确函数名 pattern 解锁
④ 函数注解
⑤ 类/命名空间 pattern
⑥ 文件 pattern
⑦ CLI flags（.mk / CMake 拼出的命令行）
⑧ config 全局
⑨ 内置默认
```

### 内置安全底线

| 等级 | 覆盖 | 说明 |
|---|---|---|
| 🔴 红区 | weak 函数（含全部 STL 模板实例）、C++ 运行时胶水（`__cxa_`/`__gxx_`/`_GLOBAL__`）、静态构造/析构列表函数、`operator new/delete` | 永不混淆，**注解也无法解锁**（编译期会发警告） |
| 🟡 黄区 | 构造函数、析构函数、其他 `operator` | 默认跳过；只能逐函数 `+bcf` 注解或**精确函数名** pattern（不含任何 `*`）+ `enable:true` 解锁 |

红黄区对**全部 8 个混淆/加密 pass** 统一生效（BCF/FLA/INDBR/ICALL/INDGV/CSE/
CIE/CFE），命令行参数无法绕过。

### 结构性安全跳过

以下函数/调用形态在语义上无法与 CFG 重写共存，所有 pass 自动跳过（同样不受
注解或配置影响）：

| 形态 | 原因 |
|---|---|
| coroutine（`llvm.coro.*` / presplit） | 状态机 proto 与 suspend 点依赖原始 CFG |
| convergence（`llvm.experimental.convergence.*`） | token 必须留在 convergence region 内 |
| GC statepoint（`gc.statepoint/result/relocate`） | stack map 记录精确调用点，改写调用即失配 |
| `inalloca` / `preallocated` | 调用方持有参数存储，间接化会改变 ABI |
| `naked` / `returns_twice` | prologue / 返回契约不允许插入基本块 |
| FLA：含不可达块的函数 | LowerSwitch 在不可达循环上不终止 |
| FLA：alloca 不在 entry 开头或位于其他块 | 平坦化后 alloca 与使用可能落入不同 case，破坏支配关系 |

---

## 混淆前后效果对比

以下对比图均为 IDA Pro 反汇编视图（Graph View）。

---

### BCF 虚假控制流

**源代码**

<img src="images/code_bcf.png" width="800px">

| 原始反汇编（无混淆） | 开启 `-irobf-bcf=100` 后 |
|:---:|:---:|
| <img src="images/bcf_org.png" width="400px"> | <img src="images/bcf.png" width="400px"> |

---

### FLA 控制流平坦化

**源代码**

<img src="images/code_fla.png" width="800px">

| 原始反汇编（无混淆） | 开启 `-irobf-fla` 后 |
|:---:|:---:|
| <img src="images/fla_org.png" width="400px"> | <img src="images/fla.png" width="400px"> |

---

### INDBR 间接分支

**源代码**

<img src="images/code_indbr.png" width="800px">

| 原始反汇编（无混淆） | 开启 `-irobf-indbr -irobf-level=3` 后 |
|:---:|:---:|
| <img src="images/indbr_org.png" width="400px"> | <img src="images/indbr.png" width="400px"> |

---

### ICALL 间接函数调用

**源代码**

<img src="images/code_icall.png" width="800px">

---

### CSE 字符串加密

**源代码**

<img src="images/code_cse.png" width="800px">

---

### CIE 整数常量加密

**源代码**

<img src="images/code_cie.png" width="800px">

---

### CFE 浮点常量加密

**源代码**

<img src="images/code_cfe.png" width="800px">

---

## 验证混淆效果

```bash
# 编译一个不混淆的对比版本
clang -O2 test.c -o test_plain.exe

# 编译混淆版本
clang -O2 -mllvm -irobf-bcf=100 test.c -o test_bcf.exe

# 用 IDA 分别载入两个文件，对比反汇编视图（Graph View）差异
```
