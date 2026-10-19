# Oboro VMP (IR-level virtualization)

VMP 把函数体翻译成私有寄存器虚拟机的字节码，并把原函数体替换成一个保持原 ABI 的
wrapper；wrapper 把参数打包后调用该函数专属的解释器。解释器本身用 LLVM IR 生成，
因此同一套字节码在 AArch64 / ARMv7 / x86_64 上都能运行。

## 1. 使用

```bash
# 全局开启（受 config / 注解 / 红黄区约束）
clang++ -O2 -mllvm -irobf-vmp -mllvm -level-vmp=2 ...

# 只保护指定函数（源码注解）
__attribute__((annotate("vmp"))) void check_license(...);
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

- `i1/i8/i16/i32/i64` 与指针（32/64 位）标量
- 整数算术、位运算、移位、`icmp` 全部谓词、`select`
- `trunc/zext/sext/ptrtoint/inttoptr/bitcast`（同宽）
- 结构化 `getelementptr`（常量与动态下标，含全局基址）
- 标量 `load/store`（非 volatile、非 atomic）
- 分支、`switch`、PHI、循环、递归、直接调用
- 入口块静态 `alloca`（局部数组/结构体，放在 wrapper 的 VM frame 中）
- `llvm.memcpy/memmove/memset`（转 native thunk）
- `llvm.ctpop/ctlz/cttz/bswap/bitreverse`
- `llvm.lifetime.*`、`llvm.assume`、`llvm.dbg.*`、`llvm.prefetch`（丢弃）

安全跳过（函数保持原样，不做部分虚拟化）：

- 浮点/向量/聚合值、非 1/8/16/32/64 位整数（如循环优化产生的 `i33`）
- 可变参数、间接调用、内联汇编、`musttail`
- 异常处理（`invoke`/`landingpad`/`resume`）、`returns_twice`、`naked`
- volatile/atomic 访存、动态 `alloca`、非入口块 `alloca`
- `blockaddress`（与 INDBR 同函数时自动让路）
- 超过 235 个 SSA 值、超过 16 个调用实参
- 无法用 64 位槽精确表示的常量表达式

跳过是**函数粒度**的：一个函数失败不会影响同模块其它函数，也不会留下半成品 IR。
翻译阶段只读，失败直接返回；成功后才替换函数体，并在替换后 `verifyFunction`，
失败会恢复原函数。

## 3. 实现要点

- **寄存器 VM**：每个 SSA 值一个 64 位虚拟寄存器，寄存器保存零扩展位模式；有符号
  运算在使用点做符号扩展，结果再截回宽度，二补码语义与原 IR 一致。
- **指令编码**：每条指令 12 字节（3 个 i32 字）。opcode 在每个函数内做一次随机
  置换，二进制里不存在固定的 opcode 表。
- **加密**：以 `(key + pc * 黄金比例常数)` 派生的 LCG 流对三个字做 XOR；解释器用
  `volatile` 读取代码字，优化器无法把密文折叠回明文。密钥每个函数不同。
- **解释器**：每个被保护函数生成一个独立解释器（随机符号名、`noinline`），避免
  整个 binary 共用同一个可识别的 dispatcher。调用外部函数通过每模块生成的
  native thunk（按真实签名装载参数）完成，ABI 正确。
- **边界检查**：PC 越界或未知 opcode 走 `llvm.trap()`，不会越界执行。
- **常量**：整数常量放在常量池，指针常量放在指针池（保留重定位），常量在函数
  prologue 统一物化，避免条件分支里的 use 未定义。
- **栈帧**：入口块静态 alloca 统一映射到 wrapper 的 frame；VM 寄存器区 2 KiB，
  每个 VM 调用额外占用 wrapper + 解释器两层栈帧。

## 4. 体积与性能

以一个 ~200 条 IR 指令的函数为例：

- 代码段约 2–4 KiB 字节码 + 6–10 KiB 解释器（IR 生成后由后端展开）；
- 运行开销主要来自每条指令的取指/解密/switch 分派，通常比原函数慢一个数量级；
- 建议只对鉴权、密钥派生、协议校验等敏感函数开启，不要对热循环/音视频路径开启。

## 5. 与其它 pass 的组合

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
- 50 轮随机函数差分（每轮 8 个函数、120 组输入）

`llvm/test/Transforms/Obfuscation/vmp-*.ll` 提供 IR 级回归（需要重新构建 opt）。
