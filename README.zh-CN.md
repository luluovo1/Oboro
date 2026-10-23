# Oboro — Android NDK Obfuscator

[![Build NDK OLLVM Toolchain](https://github.com/luluovo1/Oboro/actions/workflows/build-ndk-ollvm.yml/badge.svg)](https://github.com/luluovo1/Oboro/actions/workflows/build-ndk-ollvm.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.TXT)
[![LLVM Version](https://img.shields.io/badge/LLVM-21.0.0-red.svg)](https://llvm.org/)
[![NDK Version](https://img.shields.io/badge/NDK-r30-green.svg)](https://developer.android.com/ndk)

<p align="center">
  <a href="./README.md"><img src="https://img.shields.io/badge/README-English-2980b9?style=for-the-badge" alt="English"/></a>
  <a href="./README.zh-CN.md"><img src="https://img.shields.io/badge/README-%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87-c0392b?style=for-the-badge" alt="简体中文"/></a>
</p>

> [!CAUTION]
> **⚠️ 重要声明：本仓库即将与上游分道扬镳**
>
> 自提交 [`7596be6`](https://github.com/luluovo1/Oboro/commit/7596be6880a2118c36d46953ecf4314fc4fa8829)（2026-10-16 17:44 UTC）起，本仓库将**逐步剥离 LLVM 官方（[llvm/llvm-project](https://github.com/llvm/llvm-project)）与 [KomiMoe/Arkari](https://github.com/KomiMoe/Arkari) 上游**，走向**独立的分支演进路线**，并发展**自有的混淆算法与实现逻辑**。
>
> 该次提交完成了文档体系重构（README 精简为概览主页，详细使用说明拆分至独立文档），并新增英文文档与贡献指南。
>
> - 后续版本的混淆参数、Pass 行为与二进制产物特征**可能与上游产生差异**，且**不再保证与上游同步**；
> - 基于 Arkari / 官方文档或旧版本编写的教程与配置**可能不再适用**，请以本仓库的 [混淆使用手册](./USAGE.md) 为准；
> - 历史版本仍可正常使用；新功能与新算法将仅在本仓库的独立分支上迭代。

---

## 简介

本仓库基于 [llvm/llvm-project](https://github.com/llvm/llvm-project)（官方 LLVM 源码），在其基础上集成了 [KomiMoe/Arkari](https://github.com/KomiMoe/Arkari) 混淆引擎，并针对 Android NDK 环境进行了定制适配，深度移植到 **Google 官方 Android NDK** 使用的 LLVM 版本（当前为 LLVM 21）上。

本项目以 **NDK r30 / LLVM 21** 为稳定基准版本，不追随 LLVM 官方主分支更新，以确保混淆工具链的长期稳定性与可靠性。

当前支持的混淆能力概览：

- **控制流混淆**：FLA 控制流平坦化、BCF 虚假控制流（不透明谓词注入）
- **间接化混淆**：INDBR 间接分支、ICALL 间接调用、INDGV 间接全局变量（支持加密循环层数 0–3）
- **数据混淆**：CSE 字符串加密、CIE 整数常量加密、CFE 浮点常量加密
- **辅助保护**：RTTI 类型信息擦除（实验性）
- **三种控制方式**：命令行参数、函数级 `annotate` 注解、JSON 配置文件（`-oboro-cfg`）

> 📖 完整的**参数速查表**与**混淆前后效果对比**（IDA 反汇编视图 / Graph View）属于详细使用说明，已迁移至 → [**混淆使用手册（USAGE.md）**](./USAGE.md)

## 快速开始

### 1. 下载预编译工具链

前往 [Releases](https://github.com/luluovo1/Oboro/releases) 页面下载对应平台的预编译工具链压缩包，解压到本地任意目录（路径不要包含中文或空格）。

### 2. 在 Android CMake 项目中接入

在 `CMakeLists.txt` 中通过 `target_compile_options` 添加混淆参数：

```cmake
# 推荐第一档：普通业务逻辑全局保护
target_compile_options(your_target PRIVATE
    -mllvm -irobf-cse
    -mllvm -irobf-icall
    -mllvm -irobf-indbr -mllvm -irobf-level=1
)
```

如需直接调用 clang：

```bash
export PATH=/path/to/ollvm-toolchain/bin:$PATH
clang -O2 -mllvm -irobf-cse -mllvm -irobf-icall foo.c -o foo
```

### 3. 验证混淆生效

- 使用 `strings` 命令检查 `.so` 中是否仍有明文字符串（开启 `-irobf-cse` 后应消失）
- 使用 IDA Pro 打开 `.so`，检查反汇编视图（Graph View）中是否出现 `JUMPOUT` 或碎片化的 switch 分发结构

> 更多参数组合与效果演示见 [混淆使用手册（USAGE.md）](./USAGE.md)

## 差异对比

本项目以 [Arkari](https://github.com/KomiMoe/Arkari) 作为混淆核心引擎基础：

| 对比维度 | Arkari | 本项目 |
|:---|:---|:---|
| 目标平台 | 通用 LLVM / iOS | 专为 NDK 定制，并同时适配 Windows |
| LLVM 版本 | 官方 LLVM 分支 | Google NDK 官方 LLVM 21 |
| 控制流平坦化 (FLA) | 标准实现 | 基于 Arkari 适配迁移 |
| 间接分支 (INDBR) | 标准加密页表 | 基于 Arkari 适配迁移 |
| 间接调用 (ICALL) | 标准加密页表 | 基于 Arkari 适配迁移 |
| 虚假控制流 (BCF) | 不含 | **BCF v2**：11 族随机不透明谓词 + 随机毒载荷（AArch64 SP 收敛 / x86_64 JUMPOUT） |
| 反模拟诱饵 | 不含 | **可选**：probe 驱动 L1 重汇聚 / L3 值污染 |
| 安全底线 | 不含 | **红/黄区**：weak 符号、C++ 运行时胶水、构造/析构/运算符永不混淆 |
| 策略系统 | 仅命令行 | **config 优先**：JSON `deny` + 类/文件 `patterns`，字段级级联 |
| 兼容性 | 通用 | 通用 |

细节差异：

- 新增 **BCF（虚假控制流）** Pass。v2 每次编译从 11 个数学上严格恒真的谓词族中随机选择（回绕安全、经 InstSimplify 折叠筛选），并随机化输入变换 / 极性 / 载荷常量；注入毒块或可选的诱饵块
- **安全底线**统一实现在 `toObfuscate()`：红区（weak 符号含全部 STL 模板实例、`__cxa_`/`__gxx_` 胶水、静态构造/析构列表、`operator new/delete`）永不混淆，注解也无法解锁；黄区（构造/析构/其他运算符）需逐函数注解或精确函数名 config pattern 才能解锁
- **config 优先策略**：`-oboro-cfg=policy.json` 支持 `deny` 名单与类/命名空间/文件 `patterns`，字段级级联（`注解 > 类 pattern > 文件 pattern > CLI > config > 内置`）
- **decoy（可选）**：工具链不做任何环境检测。由 App 提供 `__oboro_probe()`；返回 0 时代码静默走诱饵路径——L1 语义完全正确（trace 噪声），L3 污染数值（错误但可执行），并受硬性危险链过滤保护
- 移除无效的 PseudoStackOffset Pass
- 修复 `CryptoUtils.h` 宏污染导致的 MSVC 编译问题

## 最佳实践

基于对 18 种参数组合的自动化性能基准测试，给出以下三档使用建议。

### 第一档：普通代码全局保护

适合对整个项目范围内的普通业务逻辑开启。体积膨胀约 `+3.6%`，运行耗时增加约 `+79%`，但由于实际业务代码运算密度低，实际用户感知约 0。

```cmake
# Android CMake
target_compile_options(your_target PRIVATE
    -mllvm -irobf-cse
    -mllvm -irobf-icall
    -mllvm -irobf-indbr -mllvm -irobf-level=1
)
```

```bash
# clang 直接使用
clang -O2 -mllvm -irobf-cse -mllvm -irobf-icall -mllvm -irobf-indbr -mllvm -irobf-level=1 foo.c -o foo
```

### 第二档：核心算法和加密函数保护

适合对鉴权逻辑、License 校验、加解密核心函数单独开启。性能损耗约 `+450%`，但这类函数每次实际执行时间上限数毫秒，用户无感知，却极大提升逆向难度。

```c
// 在函数上添加注解，仅对该函数开启强力混淆
__attribute__((__annotate__("irobf-fla")))
__attribute__((__annotate__("irobf-bcf")))
__attribute__((__annotate__("irobf-indbr")))
int verify_license(const char* key) {
    // ... 鉴权逻辑
}
```

或使用编译参数对单个翻译单元开启：

```bash
clang -O2 -mllvm -irobf-fla -mllvm -irobf-icall -mllvm -irobf-indbr \
      -mllvm -irobf-cse -mllvm -irobf-bcf=80 \
      crypto.c -o crypto.o
```

### 第三档：高性能场景（主循环、渲染、物理引擎）

这类代码**不建议开启 FLA、BCF 和高 Level 的间接化混淆**。原因：这三类混淆会完全破坏 CPU 分支预测和数据访问局部性，导致核心循环性能下降 `400%~500%`，对游戏、音视频编解码这类场景不可接受。

推荐只开启**数据层**混淆：

```bash
# 对渲染/物理等高性能模块
clang -O2 -mllvm -irobf-cse -mllvm -irobf-cie -mllvm -irobf-level=1 hotpath.c -o hotpath.o
```

> 性能敏感模块只加密"数据"（字符串、常量），不干扰"控制流"（分支、跳转），是高性能场景下的黄金原则。

### Level 参数注意事项

`-irobf-level` 统一控制所有支持档位的功能（INDBR / ICALL / INDGV / CIE / CFE / rename）的运行时解密循环层数。**Level 越高，逆向越难，性能损耗也呈指数级增长。** 需要单个功能单独调档时，用 config 的对应节点，例如 `"indgv": {"level": 1}`。

| Level 值 | 性能额外开销（参考）| 适用场景 |
|:---:|:---:|:---|
| `1` | `+20% ~ +75%` | 通用推荐，所有场景 |
| `2` | `+120% ~ +250%` | 核心函数，非热路径 |
| `3` | `+300% ~ +470%` | 极限保护，非循环代码 |

**禁忌**：`"indgv": {"level": 3}` 会在每次访问全局变量时都触发多层解密循环，对含游戏状态读取、渲染管线全局变量等高频访问场景，极易导致 Android ANR。

## 许可

本项目基于 LLVM Apache 2.0 协议（见 [`LICENSE.TXT`](./LICENSE.TXT)），混淆引擎部分基于 [Arkari](https://github.com/KomiMoe/Arkari)。

仅供学习和软件保护研究用途，请勿用于任何违法用途，用户需自行承担合规责任。

## 贡献

欢迎任何形式的贡献！在提交 Issue 或 Pull Request 前，请先阅读 [**贡献指南（CONTRIBUTING.zh-CN.md）**](./CONTRIBUTING.zh-CN.md)。

- 🐞 **报告问题**：请附上复现步骤、工具链版本与混淆参数
- 💡 **功能建议**：欢迎在 [Issues](https://github.com/luluovo1/Oboro/issues) 中提出
- 🔧 **代码贡献**：当前规划方向包括引入更多混淆选项、独立混淆算法的持续演进

如果本项目对你有帮助，欢迎点一个 ⭐ Star 支持一下！

## 致谢

本项目建立在 OLLVM 生态的肩膀上：

- [LLVM Project](https://github.com/llvm/llvm-project) — 编译器基础设施，本工具链的基石
- [OLLVM（obfuscator-llvm）](https://github.com/obfuscator-llvm/obfuscator) — 经典混淆 Pass（BCF / FLA / ICALL）的原始设计与实现
- [Hikari](https://github.com/HikariObfuscator/Hikari) — Naville 的 LLVM 混淆器，其 `-irobf-*` 参数体系与设计思路深刻影响了本工具链
- [Goron](https://github.com/amimo/goron) — Arkari 所基于的技术基础
- [KomiMoe / Arkari](https://github.com/KomiMoe/Arkari) — 本项目最初的直接上游

感谢所有提交 Issue、Pull Request 以及提供反馈的贡献者——你们的参与让这个项目不断前进。

## Star History

<a href="https://www.star-history.com/#luluovo1/Oboro&date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=luluovo1/Oboro&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=luluovo1/Oboro&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=luluovo1/Oboro&type=Date" />
 </picture>
</a>
