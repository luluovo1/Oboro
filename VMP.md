# Oboro VMP (IR-level virtualization)

VMP 把函数体翻译成私有寄存器虚拟机的字节码，并把原函数体替换成一个保持原 ABI 的
wrapper；wrapper 把参数打包后调用该函数专属的解释器。解释器本身用 LLVM IR 生成，
因此同一套字节码在 AArch64 / ARMv7 / x86_64 上都能运行。

## 1. 使用

```bash
# 全局开启（受 config / 注解 / 红黄区约束）
clang++ -O2 -mllvm -irobf-vmp -mllvm -level-vmp=2 ...

# 只保护指定函数（源码注解）
__attribute__((annotate("+vmp"))) void check_license(...);
```

config（`-mllvm -oboro-cfg=oboro.json`）：

```json
{
  "vmp": { "enable": true, "level": 2 },
  "patterns": [
    { "file": "auth.cpp", "vmp": { "enable": true, "level": 3 } },
    { "match": "Crypto::**", "vmp": { "enable": true } }
  ]
}
```

优先级与其它 pass 相同：函数注解 > pattern > CLI > 全局 config。红区/黄区/deny
规则同样生效。

### 管线位置

VMP 不在 `PipelineStart` 运行，而是挂在 `OptimizerLast`（`FullLtoLast` 同理）。
原因：如果在优化前生成 VM，InstCombine/GVN 可以把加密字节码和解释器一起常量折叠，
还原出原始逻辑。LTO 的 prelink 阶段被显式排除，只在 postlink 的末尾运行。

## 2. 覆盖范围

支持（函数整体可翻译时）：

- `i1/i8/i16/i32/i64`、指针（32/64 位）与 `float/double` 标量
- 整数算术、位运算、移位、`icmp` 全部谓词、`select`
- 浮点 `fadd/fsub/fmul/fdiv/frem`、`fneg`、全部 `fcmp` 谓词、`fabs/sqrt/fmuladd`
- `trunc/zext/sext/ptrtoint/inttoptr/bitcast`（同宽）、
  `fpext/fptrunc/fptosi/fptoui/sitofp/uitofp`
- 结构化 `getelementptr`（常量与动态下标，含全局基址）
- 标量 `load/store`（非 volatile、非 atomic）
- 分支、`switch`、PHI、循环、递归、直接调用
- **间接调用**（函数指针、虚表、`std::function`）与 **variadic 调用点**
  （如 `printf`）：按调用点签名生成两参数 thunk（参数块 + 动态 callee）
- 返回 `void` 的函数
- 入口块静态 `alloca`（局部数组/结构体，放在 wrapper 的 VM frame 中）
- `llvm.memcpy/memmove/memset`（转 native thunk）
- `llvm.ctpop/ctlz/cttz/bswap/bitreverse`、`llvm.smax/smin/umax/umin`、
  `llvm.abs`、`llvm.trap`、`llvm.expect`
- `llvm.lifetime.*`、`llvm.assume`、`llvm.dbg.*`、`llvm.prefetch`（丢弃）

安全跳过（函数保持原样，不做部分虚拟化）：

- 向量/聚合值、`half`/`fp128`、非 1/8/16/32/64 位整数（如循环优化产生的 `i33`）
- **函数本身**是 variadic（`int f(int, ...)`）、内联汇编、`musttail`
- 异常处理（`invoke`/`landingpad`/`resume`）、`returns_twice`、`naked`
- volatile/atomic 访存、动态 `alloca`、非入口块 `alloca`
- `blockaddress`（与 INDBR 同函数时自动让路）
- `switch` 的 **default 目标是 PHI 块**：保守跳过（见“已知限制”）
- 超过 235 个 SSA 值、超过 16 个调用实参
- 无法用 64 位槽精确表示的常量表达式

跳过是**函数粒度**的：一个函数失败不会影响同模块其它函数，也不会留下半成品 IR。
翻译阶段只读，失败直接返回；成功后才替换函数体，并在替换后 `verifyFunction`，
失败会恢复原函数。

### Level 语义

| level | 行为 |
| --- | --- |
| 1 | 基线：opcode 随机置换、每函数密钥、PC 派生流加密 |
| 2 | 在 1 的基础上加：虚拟寄存器物理槽位随机置换、整数常量池加密（volatile 读取，防折叠） |
| 3 | 预留给后续的 superinstruction / 分块密钥；当前等同 2 |

建议生产使用 `-level-vmp=2`。

## 3. 实现要点

- **寄存器 VM**：每个 SSA 值一个 64 位虚拟寄存器，寄存器保存零扩展位模式；有符号
  运算在使用点做符号扩展，结果再截回宽度，二补码语义与原 IR 一致。
- **指令编码**：每条指令 12 字节（3 个 i32 字）。opcode 在每个函数内做一次随机
  置换，二进制里不存在固定的 opcode 表。
- **加密**：以 `(key + pc * 黄金比例常数)` 派生的 LCG 流对三个字做 XOR；解释器用
  `volatile` 读取代码字，优化器无法把密文折叠回明文。密钥每个函数不同。
- **解释器**：每个被保护函数生成一个独立解释器（随机符号名、`noinline`），避免
  整个 binary 共用同一个可识别的 dispatcher。调用通过每次调用点签名对应的
  native thunk 完成：thunk 形如 `i64 (ptr args, ptr fn)`，按调用点具体类型装载
  参数，直接调用时 `fn` 为 null、间接调用时由寄存器传入目标指针。
- **生成物标记**：解释器与 thunk 都带 `oboro.vmp.generated` 属性，任何驱动都不会
  再虚拟化它们；管理器另有一层函数工作列表快照和“成功次数 ≤ 原函数数”的预算。
- **边界检查**：PC 越界或未知 opcode 走 `llvm.trap()`，不会越界执行。
- **常量**：整数常量放在常量池，指针常量放在指针池（保留重定位），常量在函数
  prologue 统一物化，避免条件分支里的 use 未定义。
- **栈帧**：入口块静态 alloca 统一映射到 wrapper 的 frame；VM 寄存器区 2 KiB，
  每个 VM 调用额外占用 wrapper + 解释器两层栈帧。

## 4. 安全边界

VMP 不是密码学保护：密钥、加密字节码和解释器都在最终二进制里，有能力的攻击者
可以提取密钥并离线解码。它的目标是提高静态反编译、脚本化特征匹配和跨函数分析的
成本，而不是抵抗拥有二进制与充足时间的逆向者。关键授权/密钥逻辑仍应配合服务端
校验、签名或硬件根信任。

当前实现没有运行时完整性校验（不检测补丁/断点）；需要时可在 probe 层由 App 提供。

## 5. 体积与性能

实测（x86_64，300 个各约 20 条 IR 指令的小函数，每个都是独立解释器）：

| 指标 | 数值 |
| --- | --- |
| IR 体积 | 245 KB → 23.7 MB（约 97×） |
| 二进制体积 | 181 KB → 4.26 MB（约 23×） |
| 运行开销 | 48 ms → 312 ms（约 6.5×，20M 次整数循环） |
| `opt` 处理时间 | 0.37 s |

单函数约 7 KiB 机器码的解释器开销。因此：

- 运行开销主要来自每条指令的取指/解密/switch 分派，实测约 6–7×（解释器循环
  会被后端优化），朴素解释器通常更慢；
- **必须按函数选择**：用 config `patterns`、源码注解或 `vmp` 红黄区把范围收敛到
  鉴权、密钥派生、协议校验等敏感函数；不要对整包或热循环开启；
- 需要对大量函数开启时，优先考虑后续的“模块级共享 runtime + 每函数描述符”模式
  （体积可降一个数量级，代价是解释器成为单点特征）。

## 5.1 已知限制

- `switch` 的 default 边如果落到带 PHI 的块，当前**整函数跳过**而不是冒险生成
  错误的 PHI 拷贝。真实正则库里有 7/62 个函数命中这一条（主要是把 switch 当作
  状态机跳转的解析器）。这是当前最大的覆盖率损失项，后续用显式的“边拆分块”
  实现替代。
- 235 个虚拟寄存器的上限没有做复用/溢出，超过就跳过；Release 代码里存在
  少量超大函数会命中。
- 固定向量、原子、volatile 访存仍整体跳过（见上）。

## 6. 与其它 pass 的组合

- `bcf`/`fla` 在 `PipelineStart` 先跑，VMP 在末尾看到的是已经混淆过的 CFG；可以
  组合，但字节码规模会显著增加，建议二选一。
- `indbr` 会把条件分支改成 `indirectbr`；含 `indirectbr` 的函数会被 VMP 跳过。
- `cse`/`cie`/`cfe` 与 VMP 可组合；VMP 函数内部的常量仍会进入常量池，CSE 只处理
  字符串全局。

## 6. 验证

开发期的差分测试（同一份源码，VMP 前后输出/退出码必须一致）覆盖：

- x86_64（Windows host）、AArch64（Android 真机）、ARMv7（Android 真机，32 位指针）
- `-O0` 与 `-O2` 输入
- 整数宽度、符号/无符号除余、移位、比较、结构体/GEP、全局、switch、嵌套循环、
  递归、直接调用、memcpy/memset、位运算 intrinsic
- 浮点算术/比较/转换、间接调用（函数指针表、C++ 虚函数、`std::function`）、
  variadic 调用点、`void` 函数、C++ 模板/STL 子集
- 300 函数规模用例（924 个 define，语义一致）
- 真实第三方代码：LLVM 自带 BSD regex 库（`regcomp/regexec/regfree`，2.1k 行 C），
  O0/O1/O2 输入 × level 1/2 共 6 组，全部与基线逐字节一致
- 5 个用例 × level 1/2 × 3 次随机种子 = 30 组差分，全部通过
- 25 轮随机函数差分（每轮 8 个函数、120 组输入）

`llvm/test/Transforms/Obfuscation/vmp-*.ll` 提供 IR 级回归（需要重新构建 opt）。
