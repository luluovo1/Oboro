# VMP 防护性评估：Oboro vs amice

对比对象：

- **Oboro**：`llvm/lib/Transforms/Obfuscation/Virtualize.cpp`（约 2.6k 行 C++），
  本文档所在分支 `feat/vmp-integration`。
- **amice**：`crates/amice-vm` + `crates/amice/src/aotu/vm_virtualize`（约 33.6k 行
  Rust，另有 profile DSL 层），参考版本为 2026-10-19 的主干。

两者的威胁模型相同：攻击者拿到最终二进制，拥有 IDA/Ghidra、脚本能力和调试器，
目标是恢复受保护函数的语义。两者都**不是**密码学保护。

## 1. 结构对比

| 维度 | Oboro | amice |
| --- | --- | --- |
| 执行模型 | 寄存器 VM，每 SSA 值一个 64 位槽 | 寄存器 VM，`x0..x31` + `q0..q64` |
| 寄存器分配 | 块内复用（PHI/跨块值固定），>236 槽位跳过 | 块内复用 + 溢出到 VM 帧，预算不足才跳过 |
| runtime 粒度 | **每函数一个解释器** | **模块级共享 runtime + descriptor table** |
| 解释器符号 | 随机名，无固定字符串 | 默认 `.amice.vm.dispatch`（`runtime.rs:128`） |
| 字节码编码 | 固定 12 字节记录，3×i32 | profile 定义，支持 varint opcode |
| 指令流保护 | 每函数密钥派生的 LCG 流 XOR，PC 索引，volatile 取指 | `decoder.vm` 流水线（`xor_stream key=function_key`、`varint_decode` 等），可配置 |
| 常量池 | level 2 起 XOR 掩码 + volatile 读取 | `const_pool encryption`（`xor_stream`/`add_stream`，`profile.rs:2757`） |
| opcode 随机化 | 每函数置换；level 2 起每语义 3–4 个 alias，按 `(key, pc)` 选 | **opcode alias 集合 + `(function_key, pc)` 选择**（`isa.rs:1889`） |
| 超级指令 | `icmp_*_cbr`（比较结果不进寄存器） | 27 种模板（`iadd_xor`、`icmp_br_if`、`gep_load`、`load_iadd` …） |
| 覆盖 | 标量整数/指针/float/double、间接与变参调用、void | 上述 + 固定向量、原子、volatile、饱和/溢出 intrinsic、half |
| 反调试/完整性 | 无 | 无 |

## 2. 实测成本（Oboro）

| 指标 | 数值 | 测量方式 |
| --- | --- | --- |
| 二进制体积 | 185 KB → 2.23 MB（**12×**） | 300 个 ~20 条 IR 指令的小函数 |
| IR 体积 | 245 KB → 10.3 MB（42×） | 同上 |
| 运行开销 | 48 ms → 312 ms（**6.5×**） | 20M 次迭代的整数循环，均以 `-O2` 编译 |
| `opt` 时间 | 0.37 s / 300 函数 | 同上 |

12× 体积仍是“每函数独立解释器”的代价；amice 的共享 runtime 通常能把这一项
压到个位数倍率。6.5× 是解释器循环被后端优化后的结果，比朴素解释器好，但仍
意味着**只能用于敏感函数**。

## 3. 对 Oboro 的攻击路径

以下步骤不需要破解任何密码学原语，只需要模式识别：

1. **定位 wrapper**：函数体退化成“参数打包 alloca + 调用一个内部 `i64` 函数”。
   更稳定的特征是解释器：一个内部函数包含约 59 个 case 的 `switch`，每个 case
   结尾都写 `pc+1` 并跳回同一个 loop 头。
2. **定位字节码**：解释器引用一个 private 常量全局（`[N x i32]`），取指处是
   `GEP + load volatile`，每次读 3 个字。
3. **恢复密钥流**：`K = key + pc*stride`、`K = K*mul + inc` 的四个参数都是
   立即数，就在取指循环里。恢复后即可离线解密整个字节码数组。
   （加固前这里还有固定的 LCG 常数可以直接搜索；现在常数由函数密钥派生，
   但仍然以立即数形式出现在同一个基本块里。）
4. **恢复 opcode 映射**：每个 handler 的语义由函数体唯一确定（例如
   `GEP + load` 是 LOAD，`udiv + select` 是 SDIV…）。写一个 IDAPython 脚本
   对 59 个 case 分类，即可自动建立“本函数 opcode → 语义”表。
5. **提升/模拟**：记录是固定 12 字节、操作数是字节字段，写一个 200 行的
   emulator 就能把字节码还原成可读的伪 IR；也可以直接在 dispatch 处下断点，
   记录 `(pc, opcode, operands)` 轨迹。

工作量估计：熟悉 IDA + LLVM IR 的分析者 **1–2 天**可以得到一个函数的可读语义，
脚本可复用到同模块所有函数（解释器的**代码形状**是共享的，只有 opcode 编号、
寄存器槽位和密钥不同）。动态 trace 路线更短：**几小时**。

## 4. 对 amice 的攻击路径

结构相同，但多了三层阻力：

- opcode alias + `(function_key, pc)` 选择：同一个语义在不同 PC 上可能是不同
  字节值，静态分类表不再是一对一映射；
- 超级指令：`load_iadd` 这类融合指令把 2–3 个原始操作压成一条，恢复出的语义
  粒度更粗，需要先识别融合模板；
- 共享 runtime + 加密 descriptor table：反一次 dispatcher 可以覆盖全模块，
  但 descriptor 需要先解密，且 handler 由 profile 生成，没有源码级固定形状。

代价是：**反一次就全解**。Oboro 的每函数独立解释器没有这个“单点”，但每个
函数的解释器形状又高度相似，脚本仍然可以批处理。两者在这一维度上的实际差距
没有代码量差距那么大。

## 5. 结论

| 维度 | 更强的一方 | 说明 |
| --- | --- | --- |
| 静态特征收敛 | **Oboro** | 无固定符号名、无固定 LCG 常数、寄存器文件大小随机；amice 有 `.amice.vm.dispatch` 等固定串 |
| 语义密度/抗提升 | **amice** | 超级指令 + opcode alias + varint，恢复粒度更粗 |
| 覆盖率 | **amice** | 向量、原子、volatile、饱和/溢出；Oboro 遇到这些整函数跳过 |
| 体积 | **amice** | 共享 runtime，实测差距约一个数量级 |
| 单点失效 | **Oboro** | 每函数独立解释器，不存在“反一个覆盖全包” |
| 动态对抗 | 平局 | 两者都没有反调试/完整性校验，trace 都能拿到语义 |

一句话：**amice 的 VMP 在工程完成度和覆盖面（尤其向量/原子/超级指令）上明显
更强；Oboro 在“没有稳定指纹”和“每函数独立”上更靠前，但代价是 23× 体积和
更窄的覆盖面。**

## 6. 下一步优先级（按防护收益排序）

1. **超级指令**：先做 `gep_load`、`load_<alu>`、`icmp_br` 三类，能把字节码
   规模降 20–40%，同时提高提升难度；
2. **opcode alias**：每个语义 2–4 个字节值，按 `(key, pc)` 选择，打断一对一
   分类表；
3. **寄存器复用 + 溢出**：把 235 上限的跳过率降下来（真实 Release 代码里有
   大量函数超过这个值）；
4. **固定向量/原子/volatile**：直接决定真实 App 的覆盖率，优先级高于任何
   编码层技巧；
5. **可选共享 runtime 模式**：给“整包保护”场景一个体积可接受的选项。

反调试与完整性校验不在工具链范围内（按项目边界由 App 的 probe 层提供）。
