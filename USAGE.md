# OLLVM-NDK 混淆使用手册

> 本文档是 [README](./README.md) 的详细补充，集中收录**混淆参数速查表**与**混淆前后效果对比**（IDA 截图）。
> 快速上手请看 [README · 快速开始](./README.md#快速开始)。

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
| `-irobf-indbr` | bool | false | 间接分支：跳转目标运行时解密，触发 IDA JUMPOUT · [查看混淆前后效果对比](#indbr-间接分支) |
| `-level-indbr` | int | 0 | 间接分支加密循环层数（推荐 1，慎用 3+） |
| `-irobf-icall` | bool | false | 间接调用：函数地址运行时解密 · [查看混淆前后效果对比](#icall-间接函数调用) |
| `-level-icall` | int | 0 | 间接调用加密循环层数（推荐 1） |
| `-irobf-indgv` | bool | false | 间接全局变量：全局变量访问地址运行时解密 |
| `-level-indgv` | int | 0 | 全局变量加密循环层数（推荐 1，Lv3 性能损耗极大） |
| `-irobf-cse` | bool | false | 字符串加密：C 字符串常量在运行时解密 · [查看混淆前后效果对比](#cse-字符串加密) |
| `-irobf-cie` | bool | false | 整数常量加密：对如 `0xDEADBEEF` 等整数加密 · [查看混淆前后效果对比](#cie-整数常量加密) |
| `-level-cie` | int | 0 | 整数常量加密强度 |
| `-irobf-cfe` | bool | false | 浮点常量加密：对 double/float 字面量加密 · [查看混淆前后效果对比](#cfe-浮点常量加密) |
| `-level-cfe` | int | 0 | 浮点常量加密强度 |
| `-irobf-rtti` | bool | false | 擦除 C++ RTTI 类型信息（实验性） |
| `-samsara-cfg` | string | "" | 指向 JSON 格式的混淆配置文件路径 |

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

#### 虚假控制流 (BCF) ⭐ 新增
```bash
-mllvm -irobf-bcf
-mllvm -irobf-bcf_prob=70   # 可选，注入概率 0~100，默认 70
```
为每个基本块注入以**不透明谓词**（`(x*(x+1))%2==0`，永为真）为条件的虚假分支，构造**不可约控制流图**（Irreducible CFG）。

**效果**：触发 IDA Hex-Rays 反编译失败 → `optimizations loop too much`。

示例：
```bash
# 对所有块强制 100% 注入
clang -O2 -mllvm -irobf-bcf -mllvm -irobf-bcf_prob=100 test.c -o test
```

---

### 间接化混淆

#### 间接分支 (INDBR)
```bash
-mllvm -irobf-indbr
-mllvm -level-indbr=1        # 可选，加密循环层数，越高越强
```
条件分支目标地址通过加密页表（PageTable）在运行时 XOR 解密后跳转，IDA 无法静态分析跳转目标（触发 `JUMPOUT`）。

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

## 使用配置文件（samsara）

可以用 JSON 配置文件代替命令行参数：
```bash
-mllvm -samsara-cfg=obf_config.json
```

配置文件中可对特定函数单独控制混淆级别，详见 `Flattening.cpp` / `ObfuscationOptions.cpp` 中的 attribute 注解机制。

---

## 混淆前后效果对比

以下截图均使用 IDA Pro 的 Hex-Rays 反编译器（F5）生成，源代码见 [`testresu/`](./testresu/)。

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

# 用 IDA 分别打开两个文件，对比 Hex-Rays 反编译结果
```
