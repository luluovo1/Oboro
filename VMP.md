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
- **向量代码（整体标量化）**：翻译失败后，如果函数里的向量指令都是“逐 lane
  有意义”的形态，pass 会把整个函数拆成标量再重试——向量 load/store 拆成逐元素
  访存（要求内存布局与等价数组一致，如 `<4 x i32>`、`<2 x ptr>`；`<3 x i32>`
  有尾部填充，不拆）、向量算术/比较/`select`/非 `bitcast` 转换逐 lane 重建、
  `insertelement`/`extractelement`/`shufflevector` 按 lane 展开、向量 PHI 拆成
  每 lane 一个标量 PHI、逐元素 intrinsic（`llvm.usub.sat.v8i32`、
  `llvm.ctpop.v4i32`、`llvm.fshl.v2i64` 等）按 lane 调用标量重载、
  `llvm.vector.reduce.*` 折叠回标量
- 分支、`switch`、PHI、循环、递归、直接调用
- **间接调用**（函数指针、虚表、`std::function`）与 **variadic 调用点**
  （如 `printf`）：按调用点签名生成两参数 thunk（参数块 + 动态 callee）
- **`sret` 调用**：结构体返回槽由调用者分配、被调用者写入，thunk 原样转发指针并
  继承调用点的属性表；被虚拟化的函数自身带 `sret` 形参时，wrapper 保持签名，
  VM 通过该指针写回返回值
- 返回 `void` 的函数
- 入口块静态 `alloca`（局部数组/结构体，放在 wrapper 的 VM frame 中）
- **跨块值超过寄存器槽位**：自动改用帧溢出（`spill`/`fill`），见 §3
- `llvm.memcpy/memmove/memset`（转 native thunk）
- `llvm.ctpop/ctlz/cttz/bswap/bitreverse`、`llvm.fshl/fshr`（rotate 惯用法）、
  `llvm.smax/smin/umax/umin`、`llvm.abs`、`llvm.trap`、`llvm.expect`
- `llvm.lifetime.*`、`llvm.assume`、`llvm.dbg.*`、`llvm.prefetch`（丢弃）

安全跳过（函数保持原样，不做部分虚拟化）：

- 无法逐 lane 解释的向量形态：`bitcast`（整体重解释寄存器）、向量类型的函数
  参数/返回值、`llvm.masked.*`/`llvm.vp.*`/`llvm.experimental.vector.*` 一类带
  mask 或指针语义的 intrinsic、可伸缩向量、非逐元素 intrinsic
- 聚合值（结构体/数组 SSA 值）、`half`/`fp128`、
  非 1/8/16/32/64 位整数（如循环优化产生的 `i33`）
- **函数本身**是 variadic（`int f(int, ...)`）、内联汇编、`musttail`
- 异常处理（`invoke`/`landingpad`/`resume`）、`returns_twice`、`naked`
- volatile/atomic 访存、动态 `alloca`、非入口块 `alloca`
- `blockaddress`（与 INDBR 同函数时自动让路）
- 同一基本块内同时活跃超过 235 个值（帧溢出只覆盖跨块值）
- 溢出后的帧超过 64 KiB（帧是 wrapper 的栈对象，再大就是栈溢出风险）
- 超过 16 个调用实参
- 无法用 64 位槽精确表示的常量表达式

跳过是**函数粒度**的：一个函数失败不会影响同模块其它函数，也不会留下半成品 IR。
翻译阶段只读，失败直接返回；成功后才替换函数体，并在替换后 `verifyFunction`，
失败会恢复原函数。

唯一的例外是向量标量化：翻译失败后，如果函数里的向量代码全部是逐 lane 可解释的
形态，pass 会先把整个函数拆成标量再翻译一次。只要出现一个不能逐 lane 解释的形态
（`bitcast`、向量参数、带 mask 的 intrinsic 等），整函数就按原样跳过，不做部分改写。
重试先在函数的克隆上做一次完整翻译，只有克隆能翻译成功才把同样的拆分落到原函数上——
否则函数保持原样，不会为一次失败的尝试留下劣化 IR。

### Level 语义

| level | 行为 |
| --- | --- |
| 1 | 基线：opcode 随机置换（每语义一个编码）、每函数密钥、PC 派生流加密 |
| 2 | 在 1 的基础上加：**opcode alias**（每语义 3–4 个编码，按 `(key, pc)` 选择，分派器全部接受）、虚拟寄存器槽位随机置换、整数常量池加密（volatile 读取，防折叠） |
| 3 | 预留给后续的分块密钥 / 控制流平坦化；当前等同 2 |

以下两项与 level 无关，始终生效：

- **块内寄存器复用**：只在同一基本块内定义并使用的值会被回收，PHI 与跨块值
  在块内最后一次使用后同样回收。寄存器压力从“每个 SSA 值一个槽位”降到“块内峰值”，
  中小函数不再因为 235 个槽位耗尽而被跳过；跨块值总数超过槽位的函数改用帧溢出。
- **`icmp` + `br` 融合**：比较结果不进寄存器文件，一条分派替代两条。
- **调用结果直存**：`call` 的结果由 `OP_CALL` 直接写进目标寄存器，省掉每次调用后
  的一条 `mov`；`void` 调用与 memcpy/memset 一类内建调用写固定暂存槽。

另有两类不改变语义的编码优化，同样与 level 无关：

- **立即数超级指令**：`add/sub/mul/and/or/xor/shl/lshr/ashr` 的右操作数是
  “唯一使用”的整型常量时，常量直接进指令编码（移位量内联，其余走常量池索引），
  不再为它单独物化一个寄存器。仅当该常量在函数内只被这一条指令使用时生效。
- **地址计算合并**：`getelementptr` 的常量偏移直接变成一条 `add_imm`（64 位指针），
  动态下标用 `mul_imm` 折算步长，最后一步直接写进结果寄存器——不再产生临时寄存器
  和收尾的 `mov`。

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
- **帧溢出**：跨块值与 PHI 本来永久占一个寄存器槽，槽位只有 235 个。翻译失败且
  原因恰好是“寄存器耗尽”时，pass 会自动重译一次：这一次所有跨块值住在 wrapper
  的 frame 里——定义块末尾 `OP_SPILL` 写入槽位并立刻回收寄存器，其它块用
  `OP_FILL` 读回。槽位偏移是 32 位立即数，所以可寻址的帧不受 8 位寄存器操作数
  限制。帧内值在块内仍优先用寄存器，只在离开定义块后才真正走内存；PHI 边拷贝
  在两端都是帧槽时用同一个暂存寄存器中转，所以上千个 PHI 的并行拷贝也不会
  同时占用上千个寄存器。帧大小上限 64 KiB，超过就跳过函数——帧是栈对象，
  再大就是运行期栈溢出。
- **`sret`**：thunk 转发指针并复制调用点的属性表；函数自身的 `sret` 形参按普通
  指针实参处理（wrapper 保留签名，调用者仍传返回槽）。`byval`/`inalloca`/
  `preallocated`/`swiftself`/`swifterror`/`nest` 仍跳过，它们改的是调用约定本身，
  普通转发无法复现。

## 3.1 目标平台

pass 只生成目标无关的 LLVM IR，ABI 由后端处理，因此同一份实现覆盖所有
LLVM 支持的目标。已实测（同一份 `suite.c`，基线与虚拟化产物逐字节对比）：

| 目标 | 工具链 | 结果 |
| --- | --- | --- |
| Windows x86-64（MSVC ABI） | clang 21 | 输出一致 |
| Windows i686（MSVC ABI，含 `__stdcall` 间接调用） | clang 21 | 输出一致 |
| Linux x86-64（glibc） | clang 21 / WSL Ubuntu | 输出一致 |
| Android aarch64（bionic，NDK r30） | NDK clang | 真机输出一致 |
| Android armv7（bionic，AAPCS） | NDK clang | 真机输出一致 |

平台相关的处理只有三处，且都不分支：

- 指针宽度从 `DataLayout` 读取（32/64 位），`ptrtoint` 掩码同步；
- thunk 按**调用点**的 calling convention 发起调用，`__stdcall`/`__fastcall`
  这种 callee 清栈的约定不会被改成 C；
- 参数打包成 8 字节槽的参数块，解包时按真实类型截断/位转，不依赖寄存器传参规则。

普通调用约定（`__stdcall`/`__fastcall`/AAPCS/AAPCS-VFP）不影响保护。函数签名或
调用点带 `byval`、`sret`、`inalloca`、`preallocated`、`swiftself`、
`swifterror`、`nest` 属性时整函数跳过——这些属性会把结构体布局或隐藏参数
带进 ABI，超出标量 VM 的表达范围。

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
| IR 体积 | 245 KB → 10.3 MB（约 42×） |
| 二进制体积 | 185 KB → 2.23 MB（约 12×） |
| 运行开销 | 84 ms → 510 ms（约 6.1×，20M 次整数循环） |
| `opt` 处理时间 | 0.37 s |

真实第三方代码（BSD regex，62 个函数 / 2.1k 行 C，`default<O2>` 之后 55 个函数
被虚拟化，剩余 7 个中 6 个是 variadic/`available_externally` 的 libc 包装）：

| 指标 | 基线 | VMP L2 |
| --- | --- | --- |
| 二进制体积 | 202 KB | 663 KB（3.28×） |
| IR 文本体积 | 370 KB | 2.53 MB |
| 字节码指令数 | — | 9418 条（55 个函数） |
| `opt` 处理时间 / 峰值内存 | — | 0.81 s / 37 MB |

（以上为固定种子 `000102…0f`、`-level-vmp=2` 的一次测量；种子随机时体积有 ±1% 波动。）

zlib 1.3（`zlib.bc`）：二进制 312 KB → 1485 KB（4.76×），157 个函数虚拟化，
9 档压缩输出与基线逐字节一致，解压回环一致；`opt` 0.58 s / 峰值 31 MB，
字节码 28108 条，其中 `spill`/`fill` 7060 条（`inflate`、`inflateBack`、
`inflate_fast` 三个核心函数靠帧溢出才得以覆盖）。
lz4 + lz4hc（`lz4.all.bc`）：二进制 429 KB → 1404 KB（3.27×），92 个函数虚拟化
（11 个走帧溢出），`opt` 1.12 s / 峰值 38 MB，字节码 52356 条（`spill`/`fill`
21765 条），驱动输出与基线一致。

溢出函数的字节码里帧搬运占比很高（lz4 42%、zlib 25%）：这些函数有数千个跨块值，
普通寄存器槽位（约 235–250 个）之外的部分只能进内存，这是覆盖它们的固有代价，
而不是实现浪费。

单函数约 7 KiB 机器码的解释器开销。因此：

- 运行开销主要来自每条指令的取指/解密/switch 分派，实测约 6×（解释器循环会被
  后端优化），朴素解释器通常更慢；
- **必须按函数选择**：用 config `patterns`、源码注解或 `vmp` 红黄区把范围收敛到
  鉴权、密钥派生、协议校验等敏感函数；不要对整包或热循环开启；
- 需要对大量函数开启时，优先考虑后续的“模块级共享 runtime + 每函数描述符”模式
  （体积可降一个数量级，代价是解释器成为单点特征）。

## 5.1 已知限制

- **向量代码已通过整体标量化覆盖，剩下的都是无法逐 lane 解释的形态**。
  `default<O2>` 下 regex 的 `nch`（`<4 x i8>` 比较 + `<4 x i32>` 累加 +
  `llvm.vector.reduce.add`）、zlib 的 `fill_window`/`slide_hash`
  （`llvm.usub.sat.v8i32` + `insertelement`/`shufflevector` 广播 + `zext`/`trunc`）、
  lz4 的 `LZ4_compress_fast_continue`/`LZ4_compress_forceExtDict`
  （`<4 x i32>` 常量算术）现在都能虚拟化：向量 PHI 拆成每 lane 一个标量 PHI、
  逐元素 intrinsic 按 lane 调用标量重载、归约 intrinsic 折回标量。
  按函数计的覆盖率（`-level-vmp=2`）：
  - regex 51/62，未覆盖的 11 个是 5 个 variadic libc 包装（`printf`/`_snprintf`
    等）、`linkonce_odr` 的 `__local_stdio_printf_options`（红区，永不混淆），以及
    递归下降解析器的 5 个互相递归成员（`lbackref`/`sbackref` 直接自递归，
    `p_ere_exp`/`p_bracket`/`p_simp_re` 构成 2–3 元的调用环，每层 VM 状态
    736–1304 字节，被下面的递归栈预算挡下）；
  - zlib 161/169，未覆盖的 8 个是 5 个 variadic 包装、1 个红区弱符号，以及
    `gzfread`/`gzfwrite`（`llvm.umul.with.overflow`，返回结构体）；
  - lz4 94/98，未覆盖的 4 个是 2 个 variadic 包装、1 个红区弱符号、1 个含
    `llvm.experimental.noalias.scope.decl` 的函数（共用安全门）。
  去掉这些设计上不支持的形态后是 51/51、161/162、94/94。SLP 留下的 broadcast
  形态（广播后整体 store，如 lz4 的 `LZ4_decompress_*`、zlib 的 `inflate`）
  也在覆盖范围内：逐元素 store 之后广播链整条变死，函数可以继续翻译。
- **递归函数的每层栈开销被显式限制**。wrapper 与解释器的栈帧在每次调用（含递归
  展开）时都要重新分配。寄存器文件现在按函数实际用到的槽数分配（`NextReg` 个槽
  加 0–7 个随机填充），不再是固定的 2 KB；`rec` 这类小函数每层约 0.5 KB，实测
  2000 层正常、2100 层栈溢出（1 MiB 栈；同一二进制改成 4 MiB 栈后 8500 层才溢出，
  说明确实是栈上限而不是别的问题；基线 16000 层不崩，修复前 400 层就崩）。但 VM
  状态仍显著大于原生栈帧，因此**处在调用环上**且「寄存器文件 + 溢出帧 + 参数块
  > 1 KiB」的函数会被跳过（跳过原因 `recursive function with N bytes of per-call
  VM state`），宁可少混淆一个函数，也不生成几百层就爆栈的产物。按这个预算，递归
  函数的安全深度约 400–2000 层（寄存器越多越浅），递归下降解析器够用；regex 的
  `lbackref`/`sbackref`（回溯深度与输入长度相关）因此被跳过。
  调用环由 pass 在 `doInitialization` 里对模块的直接调用图做一次 Tarjan 求 SCC
  得到：直接自调用是长度为 1 的环，互相递归（A→B→A）是长度为 2 的环。环上每个
  函数分到的预算是 `1024 / 环上会被虚拟化的函数个数`，因为一层递归会把环上每个
  成员各执行一次；没有被虚拟化的成员保留原生小帧，不计入分母。实测互相递归对
  （15/17 个寄存器）在 1 MiB 栈上约 2100 层崩溃，与预算吻合。**通过函数指针的
  递归仍不检测**（调用图里没有边），这类程序需要用户自己用注解排除。
- **寄存器槽位约 235–250 个，跨块值已可溢出到帧，同一块内的峰值压力仍不可溢出**。
  跨块值与 PHI 在寄存器模式下永久占槽，所以压力等于“跨块值的总数”，不是同时
  活跃数；超过时自动改用帧溢出（§3），lz4 的
  `LZ4HC_compress_generic_internal`（3768 个跨块值、2536 个帧槽）和 zlib 的
  `inflate`/`inflateBack`/`inflate_fast` 因此转为可虚拟化。剩下的是单块内同时
  活跃超过可用槽位——那是块内寄存器分配问题，需要活跃区间拆分才能解决。
  曾试过按“翻译顺序上的最后一次使用 + 块可达性”提前回收跨块寄存器：寄存器总量
  只降 5–8%，没有一个函数因此变成可虚拟化，却引入 PHI 边拷贝与回边的正确性约束，
  已回退。
- 超级指令目前覆盖 `icmp+br`、`imm_<alu>` 两类。`load_<alu>`、`gep_load`
  实现过并做了 A/B：省 312 条字节码（约 3.7 KB）换来 +72 KB 二进制——每多一个
  opcode 解释器 handler 约 2–3 KB（含 6 路宽度分派），远超分派节省。已完整回退，
  不再考虑。
- PHI 边拷贝是逐边 `mov`，占字节码约 12%。下一步做“单 PHI 块 + 单使用”的
  寄存器合并可以直接消掉一部分，但有并行赋值风险，需要单独的验证矩阵。
- **原子、volatile 访存仍整体跳过（见上）。**
- **非默认地址空间的模块整体跳过**。解释器把寄存器文件、溢出帧和常量池都放在
  默认地址空间里，并用 i64 算术索引；`A200`/`G200` 这类 datalayout（CHERI 风格的
  128 位 alloca/全局空间、GPU 的 private 空间）会让 `alloca` 产生
  `ptr addrspace(200)`，而解释器的形参声明是 `ptr`——这是硬类型错误，不是能靠
  `addrspacecast` 糊过去的东西。`functionShapeOK` 因此直接拒绝
  （`non-default alloca/global address space`）。同理，指针常量池是 `[N x ptr]`
  数组，非 0 地址空间的指针常量（`addrspacecast` 之后仍带 AS 的 GEP 常量）会让
  `ConstantArray::get` 断言，翻译器改为 `pointer constant in a non-default address
  space` 跳过。
- **memintrinsic 跟随模块里已有的声明**。`memset`/`memcpy`/`memmove` 在模块里可能
  已经有声明，而且原型不一定和我们合成的一致：libc 头文件是
  `void *memset(void *, int, size_t)`，也有代码声明成返回 `void`；长度参数是
  `size_t` 还是 `unsigned` 取决于源码。`getOrInsertFunction` 会把已有声明原样返回，
  于是「按自己的签名建调用」就会撞上 `Calling a function with a bad signature`；
  同一个模块里 `llvm.memset.p0.i32` 和 `llvm.memset.p0.i64` 两个调用点也会争用
  同一个 `memset` 符号。现在一律取**实际声明**的参数类型来建 thunk，由 thunk 把
  VM 寄存器转换成真实形参类型（`i32`↔`i64` 的零扩展/截断在 unmarshal 里完成），
  原型不是 3 个参数或参数不是指针/32/64 位整数时跳过该函数。
- **调用实参个数不再打进 opcode flags**。`OP_CALL` 的 `Flags` 只有 bit 7 有含义
  （间接调用），参数个数由 thunk 的签名决定。以前把 `arg_size()` 的低位也塞进去，
  于是一个有 128 个以上实参的调用自己就把 bit 7 置上了，解释器按间接调用处理，
  从**一个从未写过的寄存器**里取函数指针跳过去。现在 `Flags` 只保留 indirect 位，
  参数个数仍由 `ArgBase + arg_size <= TmpReg` 的检查保证不越界。130 个实参的用例
  （`manyargs.c`，前 6 个走寄存器、其余走栈）在 x86-64 与 `-m32` 三级全部一致。
- **重试路径的释放顺序**。`scalarizeVectors` 与 `VMRuntimeBuilder::discard` 都持有
  裸指针列表：前者擦除非 PHI 指令后仍遍历整张 `Dead` 表做 `isa<PHINode>`，后者先删
  `Interp` 再遍历包含它的 `CreatedFunctions`。两处都会在对象释放后继续解引用，只在
  分配器恰好复用那块内存时崩——这正是「不固定种子跑几百次偶发 0xC0000005」的来源
  （种子决定函数是否走到标量化重试）。现在先分流 PHI 再擦除，`discard` 对每个函数
  只删一次。修复后同一输入连跑 500 次无失败（修复前 200 次崩 3 次）。

## 6. 与其它 pass 的组合

- `bcf`/`fla` 在 `PipelineStart` 先跑，VMP 在末尾看到的是已经混淆过的 CFG；可以
  组合，但字节码规模会显著增加，建议二选一。
- `indbr` 会把条件分支改成 `indirectbr`；含 `indirectbr` 的函数会被 VMP 跳过。
- `cse`/`cie`/`cfe` 与 VMP 可组合；VMP 函数内部的常量仍会进入常量池，CSE 只处理
  字符串全局。

## 7. 验证

开发期的差分测试（同一份源码，VMP 前后输出/退出码必须一致）覆盖：

- x86_64（Windows host）、AArch64（Android 真机）、ARMv7（Android 真机，32 位指针）
- `-O0` 与 `-O2` 输入
- 整数宽度、符号/无符号除余、移位、比较、结构体/GEP、全局、switch、嵌套循环、
  递归、直接调用、memcpy/memset、位运算 intrinsic、`fshl/fshr`（rotate）、
  饱和算术与 `llvm.abs`（`sadd/uadd/ssub/usub.sat`，8/16/32/64 位）、
  向量整体标量化（常量向量 store、向量 load/store 拷贝、`extractelement`、
  broadcast store、向量算术/比较/`select`/转换、向量 PHI + `llvm.vector.reduce`、
  逐元素 sat intrinsic）
- 浮点算术/比较/转换、间接调用（函数指针表、C++ 虚函数、`std::function`）、
  variadic 调用点、`void` 函数、C++ 模板/STL 子集、`sret` 结构体返回
  （调用点与被调函数两侧）、130 个实参的调用（前 6 个走寄存器、其余走栈，
  覆盖 `OP_CALL` 的 flags 不再携带参数个数）
- 帧溢出：240 / 2000 个 PHI 的循环（240 个即超过普通寄存器槽位）、入口块内即用即弃
  的 alloca（指针留在寄存器，其余跨块值进帧）、10000 个 PHI 触发 64 KiB 帧上限后
  跳过；`spill_corpus.c` 把 200 个循环携带累加器分别用在算术、比较、`switch`、
  调用实参、store 与返回值上
- `memcpy`/`memmove`/`memset` 被降成三参数调用，与普通调用的参数块共用同一段
  预留槽；`vec_corpus.c` 的结构体拷贝（`llvm.memcpy` 16 字节）在三级 × 多随机
  种子下都逐字节一致
- 递归深度：`recurse.c`（每层 2 个形参 + 1 个跨块累加器）在 n=2000 与基线一致，
  修复前 400 层即段错误；`recurse_spill.c`（80 个跨块值的自调用函数）被递归保护
  跳过，去掉自调用的 `flat_spill.c` 则正常虚拟化（regs=93）
- 互相递归：`mutual.c`（`is_even`/`is_odd`，深度 2000）三级全部一致，说明长度为
  2 的环仍可虚拟化；`mutual_big.c`（两个 80 跨块值的函数互相调用）被环预算跳过
  （dump 里只有 `main` 和 `-O2` 特化出来的 11 个克隆，原始两个函数没有解释器），
  且编译器自身的函数特化不会因此无限展开
- 300 函数规模用例（924 个 define，语义一致）
- 真实第三方代码：LLVM 自带 BSD regex 库（`regcomp/regexec/regfree`，2.1k 行 C），
  O0/O1/O2 输入 × level 1/2 共 6 组，全部与基线逐字节一致；zlib 9 档压缩 +
  解压回环；lz4/lz4hc 驱动输出
- 固定种子矩阵：8 个用例 × level 1/2/3 × 5 个种子 = 120 组差分，全部通过
- 25 轮随机函数差分（每轮 8 个函数、120 组输入）
- 压力用例（4000 条依赖算术、600 分支 switch、120 层嵌套 if、800 个不同 64 位
  常量）× level 1/2/3，全部一致；`opt` 峰值内存 20–35 MB，无失控
- **真实 IR 语料全量扫描**：`llvm/test` 下 InstCombine / SimplifyCFG /
  LoopVectorize / CodeGen-X86 共 7815 个 `.ll`，level 2 与 level 3 各跑一遍
  （带 `-verify-each`），共 15630 次。除了 5 个**基线（不带本 pass）也崩**的上游
  用例（`addrsig`/`partition` 的 GlobalOpt 断言、`fsafdo_test3` 的 module flag、
  `elf-associated-discarded` 的 associated metadata、`bitcast` 的 scalable 向量），
  没有任何崩溃、断言、超时或 verifier 报错。
- 同种子输出确定性：固定 `randomSeed` 跑两次，`opt -S` 输出逐字节相同（66 KB）。
- **Android 真机（aarch64 + armeabi-v7a）**：`run_android.sh` 用 NDK sysroot + 本
  分支 clang 交叉编译 11 个 C 语料 × 3 级 = 33 组，push 到设备跑，stdout 与退出码
  逐字节比对，两个 ABI 各 33/33 一致。32 位这一档不是重复覆盖：指针宽度、`size_t`
  与寄存器传参规则全变，`ptr` 到 `i64` 的往返、帧偏移和 spill 槽宽都走另一条路径。

当前回归矩阵（全部通过）：

| 套件 | 规模 | 结果 |
| --- | --- | --- |
| lit（`vmp-*.ll`） | 15 个 | 15/15 |
| C 语料 × level 1/2/3 | 22 个 × 3 | 66/66 |
| 独立 `.ll` 程序 × level 1/2/3 | 13 个 × 3 | 39/39 |
| 32 位（`-m32`）× level 1/2/3 | 22 个 × 3 | 66/66 |
| 固定种子扫描（8 用例 × 3 级 × 5 种子） | 120 组 | 120/120 |
| 无种子重复压测（8 用例 × 3 级 × 30 次） | 720 组 | 720/720 |
| 真实代码 × level 1/2/3 | regex / zlib / lz4 | 9/9 |
| `llvm/test` 真实 IR 扫描（× level 2/3） | 7815 个 × 2 | 15630/15630 无 pass 引起崩溃 |
| IR 合法性（`-verify-each`，C 语料） | 22 × 3 | 66/66 |
| Android aarch64 真机 × level 1/2/3 | 11 个 × 3 | 33/33 |
| Android armeabi-v7a 真机 × level 1/2/3 | 11 个 × 3 | 33/33 |

真实代码的 `opt` 峰值内存 30–38 MB，处理时间 regex 0.84 s、zlib 0.60 s、
lz4 1.12 s（含 `default<O2>` 全流程）。zlib 的 6.8 MB 已优化 IR（169 个函数，
161 个被虚拟化）：基线 66 MB / 1.88 s，加 pass 后 76 MB / 1.79 s，体积与时间都
没有可测的退化（`-verify-each` 会额外把整模块验证一遍，那是 50 s 的来源，不是
pass 本身）。2000 个 PHI 的合成用例（16000 字节帧）
89 ms / 16 MB；10000 个 PHI 的用例（80008 字节帧）触发 64 KiB 上限，函数被跳过
而不是生成一个会爆栈的 wrapper。`spill_corpus.c`（200 个循环携带累加器，
415 个帧槽）在 x86-64 与 `-m32` 下三级全部一致。

`llvm/test/Transforms/Obfuscation/vmp-*.ll` 提供 IR 级回归（需要重新构建 opt）：
`vmp-basic`、`vmp-calls`、`vmp-fp`、`vmp-indirect`、`vmp-skip`、`vmp-annotation`、
`vmp-imm`、`vmp-funnel`、`vmp-switch-phi`、`vmp-vector`、`vmp-spill`、`vmp-sat`、
`vmp-mutual`、`vmp-memintrinsic`、`vmp-addrspace`。
