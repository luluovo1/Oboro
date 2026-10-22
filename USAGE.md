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

| 参数名 | 类型 | 默认值 | 说明 |
|:---|:---:|:---:|:---|
| `-irobf` | bool | false | 全局启用混淆（配合配置文件使用） |
| `-irobf-fla` | bool | false | 控制流平坦化：打散所有基本块至 switch 分发器 · [查看混淆前后效果对比](#fla-控制流平坦化) |
| `-irobf-bcf` | bool | false | 虚假控制流：注入永远不会到达的假分支 · [查看混淆前后效果对比](#bcf-虚假控制流) |
| `-irobf-bcf_prob` | int | 70 | BCF 注入概率（0-100），越大执行保护越密集 |
| `-irobf-bcf_budget_pct` | int | 20 | 每函数毒点占可插桩块的百分比（0–100）；0 = 不用百分比（此时只受 budget 绝对上限约束） |
| `-irobf-bcf_budget` | int | 16 | 毒点绝对上限（0 = 不设）；默认与 20% 百分比取较小值，即大函数最多 16 个站点、小函数按 20% |
| `-irobf-bcf_sources` | int | 3 | 不透明谓词熵源：1=模块全局池、2=函数栈锚点、3=两者 |
| `-irobf-indbr` | bool | false | 间接分支：跳转目标运行时解密 · [查看混淆前后效果对比](#indbr-间接分支) |
| `-level-indbr` | int | 0 | 间接分支加密循环层数（推荐 1，慎用 3+） |
| `-irobf-indbr_full` | bool | false | 无条件 `br` 也走加密页表（全 CFG 边间接化）。O2 下单目标 `indirectbr` 可能被优化器还原，多目标条件边保留 |
| `-irobf-indbr_split` | int | 0 | 间接化前把基本块拆到最多 N 条指令（0 = 不拆，每函数新增块上限 256） |
| `-irobf-icall` | bool | false | 间接调用：函数地址运行时解密 · [查看混淆前后效果对比](#icall-间接函数调用) |
| `-level-icall` | int | 0 | 间接调用加密循环层数（推荐 1） |
| `-irobf-indgv` | bool | false | 间接全局变量：全局变量访问地址运行时解密 |
| `-level-indgv` | int | 0 | 全局变量加密循环层数（推荐 1，Lv3 性能损耗极大） |
| `-irobf-ptrauth` | bool | false | AArch64 PAC：构造器为间接页表签名、使用点认证（需函数带 `+pauth`；默认关闭，仅显式开启）。config 等价键 `"ptrauth": true`。**注意**：与 Darwin arm64e 的 `-fptrauth-init-fini` 不兼容——该选项会把已有构造器条目签名，而本选项插入的条目仍是裸指针，dyld 认证失败会在 `main` 前崩溃 |
| `-irobf-cse` | bool | false | 字符串加密：C 字符串常量在运行时解密 · [查看混淆前后效果对比](#cse-字符串加密) |
| `-irobf-cie` | bool | false | 整数常量加密：对如 `0xDEADBEEF` 等整数加密 · [查看混淆前后效果对比](#cie-整数常量加密) |
| `-level-cie` | int | 0 | 整数常量加密强度 |
| `-irobf-cfe` | bool | false | 浮点常量加密：对 double/float 字面量加密 · [查看混淆前后效果对比](#cfe-浮点常量加密) |
| `-level-cfe` | int | 0 | 浮点常量加密强度 |
| `-irobf-rtti` | bool | false | 擦除 C++ RTTI 类型信息（实验性） |
| `-oboro-cfg` | string | "" | 指向 JSON 格式的混淆配置文件路径 |

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

#### 虚假控制流 (BCF) v2
```bash
-mllvm -irobf-bcf
-mllvm -irobf-bcf_prob=70      # 可选，块注入概率 0~100，默认 70
-mllvm -irobf-bcf_budget_pct=20   # 可选，每函数 20% 的块做毒点（默认）
-mllvm -irobf-bcf_budget=16       # 可选，绝对上限；与百分比取较小值
-mllvm -irobf-bcf_sources=3    # 可选，谓词熵源：1=模块全局池 2=栈锚点 3=两者（默认）
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
clang -O2 -mllvm -irobf-bcf -mllvm -irobf-bcf_prob=100 test.c -o test
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

**资格门**：decoy 只能由**函数注解**或 **config pattern** 显式声明，命令行
（.mk / CMake）永远打不开——避免一行全局参数把 decoy 铺到所有函数。

```c
__attribute__((annotate("+bcf_decoy")))          // 该函数启用 decoy（L1）
__attribute__((annotate("^bcf_decoy=50")))       // 50% 的 BCF 站点走诱饵
__attribute__((annotate("+bcf_decoy_pollute")))  // 升级到 L3 值污染
```

```json
{ "patterns": [
  { "match": "Crypto::**", "bcf": { "enable": true, "decoy": 80, "decoy_pollute": true } }
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

测试开关（hidden）：`-mllvm -irobf-force-decoy`（强制诱饵）、
`-mllvm -irobf-force-real`（强制真实）、`-mllvm -irobf-probe-symbol=xxx`
（自定义 probe 符号名）。

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
-mllvm -level-indbr=1        # 可选，加密循环层数，越高越强
```
条件分支目标地址通过加密页表（PageTable）在运行时 XOR 解密后跳转，IDA 无法静态分析跳转目标。


#### 间接调用 (ICALL)
```bash
-mllvm -irobf-icall
-mllvm -level-icall=1        # 可选
```
将直接函数调用替换为经过加密页表间接化的调用，函数地址在运行时动态解密。

#### 全局变量间接化 (INDGV)
```bash
-mllvm -irobf-indgv
-mllvm -level-indgv=1        # 可选
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
-mllvm -level-cie=1          # 可选
```
对整数类型的常量进行运行时解密保护。

#### 浮点常量加密 (CFE)
```bash
-mllvm -irobf-cfe
-mllvm -level-cfe=1          # 可选
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
-mllvm -irobf-bcf -mllvm -irobf-bcf_prob=80
```

### 最强混淆（完全）
```bash
-mllvm -irobf-fla \
-mllvm -irobf-icall \
-mllvm -level-icall=1 \
-mllvm -irobf-indbr \
-mllvm -level-indbr=1 \
-mllvm -irobf-indgv \
-mllvm -irobf-cse \
-mllvm -irobf-cie \
-mllvm -irobf-bcf -mllvm -irobf-bcf_prob=100
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
  "bcf":  { "enable": true, "level": 1 },
  "fla":  { "enable": true },
  "cse":  { "enable": true },

  "seed": "0123456789abcdef0123456789abcdef",

  "deny": ["MyCodec::*", "vendor::**"],

  "patterns": [
    { "match": "crypto::aes::**", "bcf": { "decoy": 80, "decoy_pollute": true } },
    { "match": "License::verify", "bcf": { "decoy": 50 } },
    { "file": "*generated_*.cpp", "bcf": { "enable": false } }
  ]
}
```

### 字段说明

| 字段 | 含义 |
|---|---|
| `<pass>.enable` | 开关（`true`/`false`） |
| `<pass>.level` | 加密强度 0~3（CIE/CFE/INDBR/ICALL/INDGV 有效） |
| `bcf.budget_pct` | BCF 每函数毒点占可插桩块的百分比（0–100，默认 20） |
| `bcf.budget` | BCF 毒点绝对上限（0 = 不设；>0 时与百分比取较小值） |
| `cse.shared` | `true` = 全模块共用 i8/i16 各一个解密器（长度运行期传参），体积优先；默认每个字符串独立解密器（抗分析优先）。**仅 config 可用，没有对应命令行开关** |
| `seed` / `randomSeed` | 32 位十六进制（16 字节）固定随机种子，**仅用于测试/审计/问题复现**；不填则每次构建随机（生产默认）。不要跨版本复用同一个 seed |
| `deny` | **红区名单**：命中的函数永不混淆，注解也无法解锁 |
| `patterns[].match` | 按 demangled 函数名匹配（类/命名空间） |
| `patterns[].file` | 按源文件名匹配（不含路径） |
| `patterns[].bcf.decoy` | decoy 资格 + 比例（0~100） |
| `patterns[].bcf.decoy_pollute` | L3 值污染开关 |
| `patterns[].bcf.budget_pct` | 规则内覆盖 BCF 百分比（0 = 继承全局） |
| `patterns[].bcf.budget` | 规则内覆盖 BCF 绝对上限（0 = 继承全局） |

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

| 原始反汇编（无混淆） | 开启 `-irobf-bcf -irobf-bcf_prob=100` 后 |
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

| 原始反汇编（无混淆） | 开启 `-irobf-indbr -level-indbr=3` 后 |
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
clang -O2 -mllvm -irobf-bcf -mllvm -irobf-bcf_prob=100 test.c -o test_bcf.exe

# 用 IDA 分别载入两个文件，对比反汇编视图（Graph View）差异
```
