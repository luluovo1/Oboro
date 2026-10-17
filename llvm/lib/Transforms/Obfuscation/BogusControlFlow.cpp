// BogusControlFlow.cpp
// BCF (Bogus Control Flow) pass
//
// 原理：对每个 BasicBlock 以不透明谓词（永为真，但IDA静态分析无法证伪）为条件
// 制造菱形分支结构：
//
//   EntryBB
//    |        \
//    v         v
//  OrigBB   BogBB（垃圾指令） --> OrigBB
//    |       /
//    v      /
//  [SuccBB]
//
// IDA 静态分析会把 BogBB 当作可达路径，引入大量额外分析节点，
// 触发 Hex-Rays "optimizations loop too much" 或显著降低反编译质量。

// ---- 先包含所有 LLVM 头文件，防止 CryptoUtils.h 的宏污染它们 ----
#include "llvm/Transforms/Obfuscation/BogusControlFlow.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringExtras.h"

// ---- CryptoUtils 最后包含，避免其 R/S/Maj/Ch 等宏污染上方头文件 ----
#include "llvm/CryptoUtils.h"
// CryptoUtils.h 为 SHA256 定义了大量单字母/短名宏，会与 APInt.h 等冲突，立即清理
#ifdef R
#undef R
#endif
#ifdef S
#undef S
#endif
#ifdef Maj
#undef Maj
#endif
#ifdef Ch
#undef Ch
#endif
#ifdef Sigma0
#undef Sigma0
#endif
#ifdef Sigma1
#undef Sigma1
#endif
#ifdef Gamma0
#undef Gamma0
#endif
#ifdef Gamma1
#undef Gamma1
#endif
#ifdef MIN
#undef MIN
#endif
#ifdef RND
#undef RND
#endif
#ifdef RORc
#undef RORc
#endif

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

using namespace llvm;


// 混淆概率：0-100，默认 70。用 -mllvm -irobf-bcf_prob=X 覆盖。
static cl::opt<unsigned>
    BCFProb("irobf-bcf_prob", cl::init(70), cl::NotHidden,
            cl::desc("Probability (0-100) that each basic block gets BCF "
                     "applied. Default: 70"),
            cl::ZeroOrMore);

// 测试旋钮：强制指定不透明谓词族（0=随机，1..11=指定族）。默认隐藏。
// 用于验证/回归：-mllvm -irobf-bcf_pred=3 可确定性地检查某个族是否存活。
static cl::opt<unsigned>
    BCFPred("irobf-bcf_pred", cl::init(0), cl::Hidden,
            cl::desc("Force opaque predicate family (0=random, 1..11). "
                     "Testing knob."),
            cl::ZeroOrMore);

// decoy 的 probe 符号名。App 定义同名强符号即可覆盖工具链生成的弱定义。
static cl::opt<std::string>
    BCFProbeSymbol("irobf-probe-symbol", cl::init("__oboro_probe"),
                   cl::NotHidden,
                   cl::desc("Symbol name of the project-provided decoy probe "
                            "(default: __oboro_probe)."),
                   cl::ZeroOrMore);

// 测试用：强制 env=0（走诱饵）/ env=1（走真实路径）。
static cl::opt<bool>
    BCFForceDecoy("irobf-force-decoy", cl::init(false), cl::Hidden,
                  cl::desc("Force decoy env=0 for testing."), cl::ZeroOrMore);
static cl::opt<bool>
    BCFForceReal("irobf-force-real", cl::init(false), cl::Hidden,
                 cl::desc("Force decoy env=1 for testing/CI."), cl::ZeroOrMore);

// ============================================================
// 不透明谓词引擎 v2 —— 多族谓词库 + 每实例随机化（抗特征化）
//
// 设计目标：
//   1. 多族：11 个数学族，全部经 C 原型验证——
//      a) fuzz 恒真：双架构（AArch64/x86-64）× 数百万随机值 + 边界值
//      b) 防折叠：-O2/-O3 全管线后反汇编确认未被 InstSimplify /
//         InstCombine 折叠（被折叠的族已淘汰，见下）
//   2. 每实例随机化：
//      a) 输入变换链：源值先过 1~2 步随机变换（rotl/rotr/xor/add）
//      b) 随机常量：偏移/乘数/掩码全部每次编译随机
//      c) 极性随机：恒真 / 恒假（恒假 = 取反 + 分支方向互换）
//      d) 概率性双族 AND 组合：两族都被证伪才会折叠
//   3. 回绕安全纪律（必须遵守）：只允许
//      a) mod 2^k 低位恒等式（2^64 截断只丢高位，低位性质保持）
//      b) 补码精确代数（mul/xor/and/or/not/shl/shr 原生模 2^64）
//      绝不用 mod 奇数/符号位性质（如 x*x>=0），回绕会破坏恒真性。
//
// 存活族（C 原型 AArch64 -O2 反汇编 + 符号尺寸验证，单位字节）：
//   1  x*~x bit0==0                                        (28)
//   2  x*(x+1) bit0==0                                     (28)
//   3  x^4 & 14 == 0        （4 次幂剩余 {0,1} mod 16）      (28)
//   4  bit0(x+y)==bit0(x)^bit0(y)                          (36)
//   5  4/5 连续数积 & 7 == 0（v2(4!)=v2(5!)=3）             (40)
//   6  (x-y)==(x^y)-((~x&y)<<1)（减法借位恒等式）            (40)
//   7  bit0(x*y)==bit0(x)&bit0(y)                          (52)
//   8  6 连续数积 & 15 == 0（v2(6!)=4）                     (56)
//   9  popcount(x)+popcount(~x)==64                        (60)
//   10 (x^y)+2*(x&y)==x+y（进位恒等式）                      (76)
//   11 popcount(x|y)+popcount(x&y)==popcount(x)+popcount(y) (120)
//
// 已被 LLVM 折叠、禁止再用的族（C 原型实测退化为 mov w0,#1）：
//   x^2≡x(mod 2)、(x&1) 分类讨论、模逆双射往返 (x*K)*Ki、
//   xorshift 对合、or/and 恒等式、旋转/bswap 往返、半字重装、
//   bit0(x^y) 分布、清位/置位恒等式。
// ============================================================

// rotl/rotr（经 fshl/fshr intrinsic；调用方保证 R 非 0）
static Value *bcfRotl(IRBuilder<> &B, Module &M, Value *V, unsigned R) {
  R &= 63;
  if (!R)
    return V;
  return B.CreateCall(
      Intrinsic::getOrInsertDeclaration(&M, Intrinsic::fshl, {V->getType()}),
      {V, V, ConstantInt::get(V->getType(), R)}, "bcf.r");
}
static Value *bcfRotr(IRBuilder<> &B, Module &M, Value *V, unsigned R) {
  R &= 63;
  if (!R)
    return V;
  return B.CreateCall(
      Intrinsic::getOrInsertDeclaration(&M, Intrinsic::fshr, {V->getType()}),
      {V, V, ConstantInt::get(V->getType(), R)}, "bcf.r");
}

// 随机输入变换链（1~2 步）。恒真谓词对任意输入恒真，
// 因此对源值做任意变换不改变恒真性，但会改变每个实例的指令形态。
static Value *bcfTransformInput(IRBuilder<> &B, Module &M, Value *X) {
  unsigned Steps = 1 + cryptoutils->get_uint32_t() % 2;
  for (unsigned i = 0; i < Steps; ++i) {
    switch (cryptoutils->get_uint32_t() % 4) {
    case 0:
      X = bcfRotl(B, M, X, 1 + cryptoutils->get_uint32_t() % 63);
      break;
    case 1:
      X = bcfRotr(B, M, X, 1 + cryptoutils->get_uint32_t() % 63);
      break;
    case 2:
      X = B.CreateXor(
          X, ConstantInt::get(X->getType(), cryptoutils->get_uint64_t()),
          "bcf.t");
      break;
    default:
      X = B.CreateAdd(
          X, ConstantInt::get(X->getType(), cryptoutils->get_uint64_t()),
          "bcf.t");
      break;
    }
  }
  return X;
}

// 惰性创建/获取"编译期未知"的 64 位运行时值来源：
// 内部链接、非常量的全局变量，通过 volatile load 读取。volatile 阻止
// GlobalOpt 提升为常量；两次 volatile 读之间无值关系保证，可作为
// 相互独立的随机源（见 bcfDeriveY）。
static GlobalVariable *getOrCreateOpaqueGlobal(Module &M) {
  if (GlobalVariable *G = M.getGlobalVariable("llvm.bcf.opaque", true))
    return G;
  IntegerType *I64Ty = Type::getInt64Ty(M.getContext());
  GlobalVariable *GV = new GlobalVariable(
      M, I64Ty, /*isConstant=*/false, GlobalValue::PrivateLinkage,
      ConstantInt::get(I64Ty, cryptoutils->get_uint64_t()),
      "llvm.bcf.opaque");
  GV->setAlignment(MaybeAlign(8));
  return GV;
}

// 派生 Y：从"第二次 volatile 读"独立派生，与 X 的低位无关。
//
// 为什么不能从 X 确定性派生（旧实现 Y=X*odd+C / rotl(X)^C / C-rotr(X)）：
// 族 4（bit0(x+y)==bit0(x)^bit0(y)）、族 7（bit0(x*y)）等谓词的恒真性
// 数学上对任意 x,y 成立，但若 Y 由 X 确定性派生，bit0(Y) 与 bit0(X)
// 有确定关系（如 Y=X*odd+even ⇒ bit0(Y)=bit0(X)），InstCombine 的
// KnownBits 分析可逐步证明谓词恒真、塌缩菱形，只剩孤儿 volatile 读
// （实测：50 次随机编译 6% 命中折叠，注入原始 IR 确认根因为
// mul(odd)+add(even) 派生）。两次 volatile 读同一地址之间没有
// 值关系保证，X 与 Y 的低位无法被静态关联。
static Value *bcfDeriveY(IRBuilder<> &B, Module &M, Value *X) {
  (void)X; // 保留签名；Y 不再从 X 派生（见上）
  Value *Src2 = B.CreateLoad(B.getInt64Ty(), getOrCreateOpaqueGlobal(M),
                             /*isVolatile=*/true, "bcf.ctr2");
  return bcfTransformInput(B, M, Src2);
}

// 连续 K 个数之积恒被 2^(v2(K!)) 整除（Legendre: v2(K!)=K-popcount(K)）。
// K=4,5 -> 8 的倍数（掩码 7）；K=6 -> 16 的倍数（掩码 15）。
// 起始偏移 A 每次编译随机；mod 2^k 低位恒等式，回绕安全。
static Value *bcfConsecProduct(IRBuilder<> &B, Value *X, unsigned K,
                               uint64_t Mask) {
  Type *I64 = B.getInt64Ty();
  uint64_t A = cryptoutils->get_uint64_t();
  Value *T = B.CreateAdd(X, ConstantInt::get(I64, A), "bcf.t");
  Value *P = T;
  for (unsigned i = 1; i < K; ++i) {
    Value *Ti = B.CreateAdd(T, ConstantInt::get(I64, i), "bcf.t");
    P = B.CreateMul(P, Ti, "bcf.p");
  }
  return B.CreateICmpEQ(B.CreateAnd(P, ConstantInt::get(I64, Mask), "bcf.b"),
                        ConstantInt::get(I64, 0), "bcf.c");
}

// 族选择：加权（廉价族高频；popc_union 重，低频）。BCFPred 强制时直接返回。
static unsigned bcfPickKind() {
  if (unsigned Forced = BCFPred.getValue())
    return Forced;
  static const unsigned Weights[11] = {2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1};
  unsigned R = cryptoutils->get_uint32_t() % 16;
  for (unsigned i = 0; i < 11; ++i) {
    if (R < Weights[i])
      return i + 1;
    R -= Weights[i];
  }
  return 2;
}

// 构造一个恒真谓词（返回 i1）。X 必须是"编译期未知"的 64 位运行时值。
static Value *bcfBuildFamily(IRBuilder<> &B, Module &M, Value *X,
                             unsigned Kind) {
  Type *I64 = B.getInt64Ty();
  auto C = [&](uint64_t V) { return ConstantInt::get(I64, V); };

  switch (Kind) {
  case 1: { // x*~x：bit0(x)·bit0(~x) = b·(1-b) = 0
    Value *P = B.CreateMul(X, B.CreateNot(X, "bcf.n"), "bcf.p");
    return B.CreateICmpEQ(B.CreateAnd(P, C(1), "bcf.b"), C(0), "bcf.c");
  }
  case 2: { // x*(x+1)：连续数之积恒偶
    Value *P = B.CreateMul(X, B.CreateAdd(X, C(1), "bcf.a"), "bcf.p");
    return B.CreateICmpEQ(B.CreateAnd(P, C(1), "bcf.b"), C(0), "bcf.c");
  }
  case 3: { // x^4 mod 16 ∈ {0,1}：偶数 → 0，奇数 → 1
    Value *X2 = B.CreateMul(X, X, "bcf.s");
    Value *X4 = B.CreateMul(X2, X2, "bcf.q");
    return B.CreateICmpEQ(B.CreateAnd(X4, C(14), "bcf.b"), C(0), "bcf.c");
  }
  case 4: { // bit0(x+y) == bit0(x)^bit0(y)（bit0 无进位入）
    Value *Y = bcfDeriveY(B, M, X);
    Value *L = B.CreateAnd(B.CreateAdd(X, Y, "bcf.s"), C(1), "bcf.b");
    Value *R = B.CreateXor(B.CreateAnd(X, C(1), "bcf.b"),
                           B.CreateAnd(Y, C(1), "bcf.b"), "bcf.bx");
    return B.CreateICmpEQ(L, R, "bcf.c");
  }
  case 5: { // 4/5 连续数之积 & 7 == 0
    unsigned K = (cryptoutils->get_uint32_t() & 1) ? 4 : 5;
    return bcfConsecProduct(B, X, K, 7);
  }
  case 6: { // (x-y) == (x^y) - ((~x&y)<<1)（减法借位恒等式）
    Value *Y = bcfDeriveY(B, M, X);
    Value *D = B.CreateSub(X, Y, "bcf.d");
    Value *XO = B.CreateXor(X, Y, "bcf.x");
    Value *NAY = B.CreateAnd(B.CreateNot(X, "bcf.n"), Y, "bcf.na");
    Value *SH = B.CreateShl(NAY, C(1), "bcf.sh");
    return B.CreateICmpEQ(D, B.CreateSub(XO, SH, "bcf.r"), "bcf.c");
  }
  case 7: { // bit0(x*y) == bit0(x)&bit0(y)
    Value *Y = bcfDeriveY(B, M, X);
    Value *L = B.CreateAnd(B.CreateMul(X, Y, "bcf.p"), C(1), "bcf.b");
    Value *R = B.CreateAnd(B.CreateAnd(X, C(1), "bcf.b"),
                           B.CreateAnd(Y, C(1), "bcf.b"), "bcf.ba");
    return B.CreateICmpEQ(L, R, "bcf.c");
  }
  case 8: // 6 连续数之积 & 15 == 0
    return bcfConsecProduct(B, X, 6, 15);
  case 9: { // popcount(x)+popcount(~x) == 64（每个 bit 恰贡献 1）
    Function *Ctpop =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::ctpop, {I64});
    Value *P1 = B.CreateCall(Ctpop, {X}, "bcf.pc");
    Value *P2 = B.CreateCall(Ctpop, {B.CreateNot(X, "bcf.n")}, "bcf.pc");
    return B.CreateICmpEQ(B.CreateAdd(P1, P2, "bcf.s"), C(64), "bcf.c");
  }
  case 10: { // (x^y)+2*(x&y) == x+y（进位恒等式）
    Value *Y = bcfDeriveY(B, M, X);
    Value *XO = B.CreateXor(X, Y, "bcf.x");
    Value *A2 = B.CreateShl(B.CreateAnd(X, Y, "bcf.a"), C(1), "bcf.a2");
    Value *L = B.CreateAdd(XO, A2, "bcf.l");
    return B.CreateICmpEQ(L, B.CreateAdd(X, Y, "bcf.r"), "bcf.c");
  }
  case 11: { // popcount(x|y)+popcount(x&y) == popcount(x)+popcount(y)
    Value *Y = bcfDeriveY(B, M, X);
    Function *Ctpop =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::ctpop, {I64});
    Value *PO = B.CreateCall(Ctpop, {B.CreateOr(X, Y, "bcf.o")}, "bcf.pc");
    Value *PA = B.CreateCall(Ctpop, {B.CreateAnd(X, Y, "bcf.a")}, "bcf.pc");
    Value *PX = B.CreateCall(Ctpop, {X}, "bcf.pc");
    Value *PY = B.CreateCall(Ctpop, {Y}, "bcf.pc");
    return B.CreateICmpEQ(B.CreateAdd(PO, PA, "bcf.l"),
                          B.CreateAdd(PX, PY, "bcf.r"), "bcf.c");
  }
  default: { // 兜底：族 2
    Value *P = B.CreateMul(X, B.CreateAdd(X, C(1), "bcf.a"), "bcf.p");
    return B.CreateICmpEQ(B.CreateAnd(P, C(1), "bcf.b"), C(0), "bcf.c");
  }
  }
}

// 顶层入口：变换链 → 选族 → （概率）双族 AND 组合。返回恒真 i1。
static Value *buildOpaqueCond(IRBuilder<> &B, Module &M, Value *Src) {
  Value *X = bcfTransformInput(B, M, Src);
  unsigned Kind = bcfPickKind();
  Value *Cond = bcfBuildFamily(B, M, X, Kind);
  // 概率 1/5：双族 AND 组合（两族都被证伪才会折叠；强制测试时不组合）
  if (!BCFPred.getValue() && (cryptoutils->get_uint32_t() % 5 == 0)) {
    unsigned Kind2 = bcfPickKind();
    if (Kind2 == Kind)
      Kind2 = (Kind % 11) + 1;
    Value *C2 = bcfBuildFamily(B, M, bcfTransformInput(B, M, Src), Kind2);
    Cond = B.CreateAnd(Cond, C2, "bcf.c2");
  }
  return Cond;
}

// ============================================================
// Decoy runtime（M1）
//
// 工具链不做任何环境判断：只调用项目提供的 probe 并消费返回值。
//   probe 非 0 -> 真实路径
//   probe == 0 -> 诱饵路径
// 默认弱定义返回 1（fail-open）；App 的强定义在链接期覆盖。
//
// 传输层：双份 share，密钥由两个锚点函数地址 + 编译期常量运行时派生，
// 密钥不落盘；每次 getenv() 解码并比较，不一致置粘性 tampered。
// 初始化：构造函数 + 惰性兜底（防模拟器跳过 .init_array）；原子状态机
// 0->1->2，probe 递归调用混淆函数时返回 fail-open。
// ============================================================

static std::string getOboroRuntimeSuffix(Module &M) {
  if (NamedMDNode *NMD = M.getNamedMetadata("oboro.runtime")) {
    if (NMD->getNumOperands() > 0) {
      if (auto *MD = dyn_cast<MDNode>(NMD->getOperand(0))) {
        if (MD->getNumOperands() > 0) {
          if (auto *S = dyn_cast<MDString>(MD->getOperand(0)))
            return S->getString().str();
        }
      }
    }
  }
  std::string Suffix = utohexstr(cryptoutils->get_uint32_t(), true);
  NamedMDNode *NMD = M.getOrInsertNamedMetadata("oboro.runtime");
  NMD->addOperand(
      MDNode::get(M.getContext(), {MDString::get(M.getContext(), Suffix)}));
  return Suffix;
}

static Function *getOrCreateDecoyRuntime(Module &M) {
  LLVMContext &Ctx = M.getContext();
  // 类型不匹配的 probe 声明会让 CreateCall 生成非法 IR（verifier abort）。
  // 一旦发现，禁用本模块的 decoy 并留下标记，避免每个函数重复告警。
  if (M.getNamedMetadata("oboro.disabled"))
    return nullptr;
  const std::string Suffix = getOboroRuntimeSuffix(M);
  const std::string Prefix = "oboro.";
  const std::string GetEnvName = Prefix + "getenv." + Suffix;
  if (Function *Existing = M.getFunction(GetEnvName))
    return Existing;

  Type *I32 = Type::getInt32Ty(Ctx);
  Type *I64 = Type::getInt64Ty(Ctx);
  Type *Void = Type::getVoidTy(Ctx);
  FunctionType *ProbeTy = FunctionType::get(I32, /*isVarArg=*/false);

  // ---- probe：弱定义（App 强定义覆盖）----
  const std::string ProbeName = BCFProbeSymbol.getValue();
  Function *Probe = M.getFunction(ProbeName);
  if (Probe && Probe->getFunctionType() != ProbeTy) {
    llvm::errs() << "oboro: probe symbol '" << ProbeName
                 << "' has incompatible type (expected i32(void)); "
                    "decoy disabled for this module\n";
    M.getOrInsertNamedMetadata("oboro.disabled");
    return nullptr;
  }
  auto EmitDefaultProbeBody = [&](Function *F) {
    F->setLinkage(GlobalValue::WeakAnyLinkage);
    F->setVisibility(GlobalValue::HiddenVisibility);
    F->addFnAttr(Attribute::NoInline);
    F->addFnAttr(Attribute::OptimizeNone);
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
    IRBuilder<> B(BB);
    GlobalVariable *DefaultEnv = M.getNamedGlobal("oboro.default_env");
    if (!DefaultEnv) {
      DefaultEnv = new GlobalVariable(
          M, I32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
          ConstantInt::get(I32, 1), "oboro.default_env");
      DefaultEnv->setAlignment(Align(4));
    }
    B.CreateRet(B.CreateLoad(I32, DefaultEnv, /*isVolatile=*/true));
  };
  if (!Probe) {
    Probe = Function::Create(FunctionType::get(I32, false),
                             GlobalValue::WeakAnyLinkage, ProbeName, M);
    EmitDefaultProbeBody(Probe);
  } else if (Probe->isDeclaration()) {
    EmitDefaultProbeBody(Probe);
  }

  // ---- 两个锚点函数（地址参与密钥派生；奇偶不同防 ICF 合并）----
  auto GetOrCreateAnchor = [&](const std::string &Name,
                               uint32_t Value) -> Function * {
    if (Function *F = M.getFunction(Name))
      return F;
    Function *F = Function::Create(FunctionType::get(I32, false),
                                   GlobalValue::InternalLinkage, Name, M);
    F->addFnAttr(Attribute::NoInline);
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
    IRBuilder<> B(BB);
    B.CreateRet(B.getInt32(Value));
    return F;
  };
  Function *A0 = GetOrCreateAnchor(Prefix + "anchor0." + Suffix,
                                   cryptoutils->get_uint32_t() & ~1u);
  Function *A1 = GetOrCreateAnchor(Prefix + "anchor1." + Suffix,
                                   cryptoutils->get_uint32_t() | 1u);

  // ---- 编译期常量 ----
  const uint32_t KeyConst1 = cryptoutils->get_uint32_t();
  const uint32_t KeyConst2 = cryptoutils->get_uint32_t();
  const uint32_t MixOdd = cryptoutils->get_uint32_t() | 1u;
  const uint32_t TamperKey = cryptoutils->get_uint32_t();

  auto GetOrCreateI32Global = [&](const std::string &Name,
                                  uint32_t Init) -> GlobalVariable * {
    if (GlobalVariable *G = M.getNamedGlobal(Name))
      return G;
    auto *G = new GlobalVariable(M, I32, /*isConstant=*/false,
                                 GlobalValue::PrivateLinkage,
                                 ConstantInt::get(I32, Init), Name);
    G->setAlignment(Align(4));
    return G;
  };
  GlobalVariable *S1 = GetOrCreateI32Global(Prefix + "s1." + Suffix, 0);
  GlobalVariable *S2 = GetOrCreateI32Global(Prefix + "s2." + Suffix, 0);
  GlobalVariable *Inited =
      GetOrCreateI32Global(Prefix + "inited." + Suffix, 0);
  GlobalVariable *Tampered =
      GetOrCreateI32Global(Prefix + "tampered." + Suffix, TamperKey);

  auto BuildKey = [&](IRBuilder<> &B, Function *Anchor,
                      uint32_t KeyConst) -> Value * {
    Value *Addr = B.CreatePtrToInt(Anchor, I64);
    Value *T = B.CreateLShr(Addr, ConstantInt::get(I64, 4));
    T = B.CreateXor(T, ConstantInt::get(I64, KeyConst));
    T = B.CreateMul(T, ConstantInt::get(I64, MixOdd));
    return B.CreateTrunc(T, I32);
  };

  auto CreateAtomicLoadI32 = [&](IRBuilder<> &B, Value *Ptr,
                                 const Twine &Name) -> LoadInst * {
    LoadInst *LI = B.CreateLoad(I32, Ptr, Name);
    LI->setAtomic(AtomicOrdering::Monotonic);
    return LI;
  };
  auto CreateAtomicStoreI32 = [&](IRBuilder<> &B, Value *Val, Value *Ptr) {
    StoreInst *SI = B.CreateStore(Val, Ptr);
    SI->setAtomic(AtomicOrdering::Monotonic);
  };

  // ---- init：原子状态机 0->1->2；防递归 ----
  Function *Init = Function::Create(FunctionType::get(Void, false),
                                    GlobalValue::InternalLinkage,
                                    Prefix + "init." + Suffix, M);
  Init->addFnAttr(Attribute::NoInline);
  Init->addFnAttr(Attribute::OptimizeNone);
  Init->addMetadata("noobf", *MDNode::get(Ctx, {}));
  BasicBlock *InitEntry = BasicBlock::Create(Ctx, "entry", Init);
  BasicBlock *InitDo = BasicBlock::Create(Ctx, "doinit", Init);
  BasicBlock *InitDone = BasicBlock::Create(Ctx, "done", Init);
  IRBuilder<> IB(InitEntry);
  Value *Old = IB.CreateAtomicRMW(AtomicRMWInst::Xchg, Inited, IB.getInt32(1),
                                  MaybeAlign(4), AtomicOrdering::Monotonic);
  IB.CreateCondBr(IB.CreateICmpEQ(Old, IB.getInt32(0)), InitDo, InitDone);
  IB.SetInsertPoint(InitDo);
  Value *Env = nullptr;
  if (BCFForceDecoy)
    Env = IB.getInt32(0);
  else if (BCFForceReal)
    Env = IB.getInt32(1);
  else {
    Value *P = IB.CreateCall(Probe, {});
    Env = IB.CreateZExt(IB.CreateICmpNE(P, IB.getInt32(0)), I32);
  }
  IB.CreateStore(IB.CreateXor(Env, BuildKey(IB, A0, KeyConst1)), S1,
                 /*isVolatile=*/true);
  IB.CreateStore(IB.CreateXor(Env, BuildKey(IB, A1, KeyConst2)), S2,
                 /*isVolatile=*/true);
  CreateAtomicStoreI32(IB, IB.getInt32(TamperKey), Tampered);
  CreateAtomicStoreI32(IB, IB.getInt32(2), Inited);
  IB.CreateBr(InitDone);
  IB.SetInsertPoint(InitDone);
  IB.CreateRetVoid();

  // ---- getenv：惰性初始化 + 双 share 解码 + 校验 + 粘性 tampered ----
  Function *GetEnv = Function::Create(FunctionType::get(I32, false),
                                      GlobalValue::InternalLinkage,
                                      GetEnvName, M);
  GetEnv->addFnAttr(Attribute::NoInline);
  GetEnv->addFnAttr(Attribute::OptimizeNone);
  GetEnv->addMetadata("noobf", *MDNode::get(Ctx, {}));
  BasicBlock *GE = BasicBlock::Create(Ctx, "entry", GetEnv);
  BasicBlock *GFast = BasicBlock::Create(Ctx, "fast", GetEnv);
  BasicBlock *GSlow = BasicBlock::Create(Ctx, "slow", GetEnv);
  BasicBlock *GDefault = BasicBlock::Create(Ctx, "default", GetEnv);
  BasicBlock *GSetTamper = BasicBlock::Create(Ctx, "tamper", GetEnv);
  BasicBlock *GCheck = BasicBlock::Create(Ctx, "check", GetEnv);
  IRBuilder<> GB(GE);
  Value *St = CreateAtomicLoadI32(GB, Inited, "st");
  GB.CreateCondBr(GB.CreateICmpNE(St, GB.getInt32(2)), GSlow, GFast);
  GB.SetInsertPoint(GSlow);
  GB.CreateCall(Init, {});
  Value *St2 = CreateAtomicLoadI32(GB, Inited, "st2");
  GB.CreateCondBr(GB.CreateICmpEQ(St2, GB.getInt32(2)), GFast, GDefault);
  GB.SetInsertPoint(GDefault);
  GB.CreateRet(GB.getInt32(1)); // 初始化中/递归：fail-open
  GB.SetInsertPoint(GFast);
  Value *V1 = GB.CreateXor(
      GB.CreateLoad(I32, S1, /*isVolatile=*/true, "s1"),
      BuildKey(GB, A0, KeyConst1));
  Value *V2 = GB.CreateXor(
      GB.CreateLoad(I32, S2, /*isVolatile=*/true, "s2"),
      BuildKey(GB, A1, KeyConst2));
  GB.CreateCondBr(GB.CreateICmpEQ(V1, V2), GCheck, GSetTamper);
  GB.SetInsertPoint(GSetTamper);
  CreateAtomicStoreI32(GB, GB.getInt32(1 ^ TamperKey), Tampered);
  GB.CreateBr(GCheck);
  GB.SetInsertPoint(GCheck);
  Value *T = GB.CreateXor(CreateAtomicLoadI32(GB, Tampered, "t"),
                          GB.getInt32(TamperKey));
  Value *Good = GB.CreateAnd(
      GB.CreateICmpEQ(V1, GB.getInt32(1)),
      GB.CreateNot(GB.CreateICmpNE(T, GB.getInt32(0))));
  GB.CreateRet(GB.CreateZExt(Good, I32));

  // ---- constructor：优先 101，尽早初始化 ----
  Function *Ctor = Function::Create(FunctionType::get(Void, false),
                                    GlobalValue::InternalLinkage,
                                    Prefix + "ctor." + Suffix, M);
  Ctor->addFnAttr(Attribute::NoInline);
  Ctor->addFnAttr(Attribute::OptimizeNone);
  Ctor->addMetadata("noobf", *MDNode::get(Ctx, {}));
  BasicBlock *CB = BasicBlock::Create(Ctx, "entry", Ctor);
  IRBuilder<> CIB(CB);
  CIB.CreateCall(Init, {});
  CIB.CreateRetVoid();
  appendToGlobalCtors(M, Ctor, 101);

  return GetEnv;
}

// ============================================================
// AArch64 专用：惰性创建"随机垃圾字节 blob" + "指向 blob 中部的指针"两个
// 模块级全局变量（每个 Module 只创建一次，所有函数的 BogBB 共用）。
//
// 原理：
//   llvm.bcf.bogus_blob   —— .text.bogus 段里的一段随机字节（非法指令流）
//   llvm.bcf.bogus_target —— 一个指针型全局变量，初始值 = &blob[17]
//                             （故意取一个不对齐/无意义的偏移，落在 blob 中部）
// BogBB 通过 `ldr xN, [$0]` 把 bogus_target/blob 的数据引用拉进死块
// （xref 污染 + 数据引用噪声；值不参与跳转）。blob 本体是随机字节，
// 若反汇编器顺着引用找到并强行解码，将产生非法指令流。
// ============================================================
static GlobalVariable *getOrCreateBogusBlob(Module &M) {
  if (GlobalVariable *G = M.getGlobalVariable("llvm.bcf.bogus_blob", true))
    return G;
  LLVMContext &Ctx = M.getContext();
  const unsigned BlobSize = 64;
  std::vector<uint8_t> Bytes(BlobSize);
  for (auto &Byte : Bytes)
    Byte = static_cast<uint8_t>(cryptoutils->get_uint32_t());
  Constant *Init = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(Bytes));
  auto *Blob = new GlobalVariable(M, Init->getType(), /*isConstant=*/true,
                                  GlobalValue::PrivateLinkage, Init,
                                  "llvm.bcf.bogus_blob");
  Blob->setAlignment(MaybeAlign(4));
  // 独立 section，链接时会被 lld 合并进最终的 .text 输出段（可执行），
  // 但其内容并非合法函数序言 —— 反汇编器强行解码会产生垃圾指令流。
  Blob->setSection(".text.bogus");
  return Blob;
}

static GlobalVariable *getOrCreateBogusTargetPtr(Module &M) {
  if (GlobalVariable *G = M.getGlobalVariable("llvm.bcf.bogus_target", true))
    return G;
  LLVMContext &Ctx = M.getContext();
  GlobalVariable *Blob = getOrCreateBogusBlob(M);
  Constant *Idx[] = {ConstantInt::get(Type::getInt64Ty(Ctx), 0),
                     ConstantInt::get(Type::getInt64Ty(Ctx), 17)};
  Constant *TargetAddr = ConstantExpr::getInBoundsGetElementPtr(
      Blob->getValueType(), Blob, Idx);
  auto *Ptr = new GlobalVariable(M, PointerType::getUnqual(Ctx),
                                 /*isConstant=*/true,
                                 GlobalValue::PrivateLinkage, TargetAddr,
                                 "llvm.bcf.bogus_target");
  Ptr->setAlignment(MaybeAlign(8));
  return Ptr;
}

// 惰性创建"垃圾写回槽"：一个非常量私有全局，供 BogBB 做
// volatile 读-改-写（真实副作用，DCE 无法删除；运行时永不执行）。
static GlobalVariable *getOrCreateBogusSink(Module &M) {
  if (GlobalVariable *G = M.getGlobalVariable("llvm.bcf.sink", true))
    return G;
  LLVMContext &Ctx = M.getContext();
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  auto *GV = new GlobalVariable(M, I64Ty, /*isConstant=*/false,
                                GlobalValue::PrivateLinkage,
                                ConstantInt::get(I64Ty, cryptoutils->get_uint64_t()),
                                "llvm.bcf.sink");
  GV->setAlignment(MaybeAlign(8));
  return GV;
}

// x86 死块载荷生成：全部常量每次编译随机化——
//   步长（16 的倍数）、填充立即数、mov 目标寄存器、跳入偏移。
// 布局：add/sub 随机步长（配平）；mov <reg>, <随机 imm32>；
// jmp 落入 mov 指令中部（随机偏移 1..4 字节）。
// IDA 递归下降在此处重叠解码 → JUMPOUT，后续线性/递归扫描错位。
static std::string buildX86PoisonAsm(bool Is64) {
  unsigned Step = 16 * (1 + cryptoutils->get_uint32_t() % 63); // 16..1008
  uint32_t Fill = cryptoutils->get_uint32_t();
  unsigned MovOp = 0xB8 + (cryptoutils->get_uint32_t() % 8); // mov eax..edi
  unsigned Land = 1 + (cryptoutils->get_uint32_t() % 4);     // 落入偏移 1..4
  unsigned DispLow = 0xF7 + (Land - 1);                      // -9..-6 低字节
  const char *Suf = Is64 ? "q" : "l";
  const char *Sp = Is64 ? "%rsp" : "%esp";
  const char *Ax = Is64 ? "%rax" : "%eax";
  char Buf[512];
  snprintf(Buf, sizeof(Buf),
           "add%s $$0x%x, %s\n\t"
           "sub%s $$0x%x, %s\n\t"
           "push%s %s\n\t"
           "pop%s %s\n\t"
           ".byte 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X\n\t"
           ".byte 0xE9, 0x%02X, 0xFF, 0xFF, 0xFF\n\t",
           Suf, Step, Sp, Suf, Step, Sp, Suf, Ax, Suf, Ax, MovOp, Fill & 0xFF,
           (Fill >> 8) & 0xFF, (Fill >> 16) & 0xFF, (Fill >> 24) & 0xFF,
           DispLow);
  return std::string(Buf);
}

// ============================================================
// 向 BogusBlock (死分支) 填充指令、栈扰动与 Anti-Disassembler 载荷。
//
// 运行时不透明谓词 100% 走真实分支，死分支绝对不执行 (0% 崩溃风险)；
// 但 IDA / Hex-Rays 静态遍历会：
//   1. 把 BogBB 当作可达路径，引入大量分析节点；
//   2. 遭遇虚假栈指针扰动，触发 "positive sp" / SP 分析失败；
//   3. 遭遇 jmp 到指令中部的重叠代码，打出 "JUMPOUT" 注解，
//      使线性/递归扫描在 .text 段落错位，函数边界与段解析失效。
//
// 所有常量（步长/立即数/寄存器/跳入偏移）每次编译随机化，
// 消除固定字节指纹（旧的 0x100 / B8 11 11 11 11 / E9 F7 FF FF FF）。
// ============================================================
static void fillBogusBB(BasicBlock *BogBB, Function &F) {
  LLVMContext &Ctx = F.getContext();
  Module *M = F.getParent();
  IRBuilder<> B(BogBB);
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);

  // 1. 真实副作用的垃圾读改写（volatile load → 随机运算 → volatile store，
  //    无法被 DCE；运行时永不执行，但静态分析必须处理这段数据流）
  {
    GlobalVariable *Sink = getOrCreateBogusSink(*M);
    Value *J = B.CreateLoad(I64Ty, Sink, /*isVolatile=*/true, "bcf.j");
    unsigned NOps = 2 + cryptoutils->get_uint32_t() % 2;
    for (unsigned i = 0; i < NOps; ++i) {
      uint64_t C = cryptoutils->get_uint64_t();
      switch (cryptoutils->get_uint32_t() % 4) {
      case 0:
        J = B.CreateXor(J, ConstantInt::get(I64Ty, C), "bcf.j");
        break;
      case 1:
        J = B.CreateAdd(J, ConstantInt::get(I64Ty, C), "bcf.j");
        break;
      case 2:
        J = B.CreateMul(J, ConstantInt::get(I64Ty, C | 1ull), "bcf.j");
        break;
      default:
        J = B.CreateSub(J, ConstantInt::get(I64Ty, C), "bcf.j");
        break;
      }
    }
    B.CreateStore(J, Sink, /*isVolatile=*/true);
  }

  // 2. 架构专属 Anti-Decompiler / Anti-Disassembler 载荷
  Triple TargetTriple(M->getTargetTriple());
  FunctionType *AsmFTy = FunctionType::get(Type::getVoidTy(Ctx), false);

  if (TargetTriple.isX86() &&
      M->getDataLayout().getPointerSizeInBits() == 64) {
    // x86_64：栈扰动（配平）+ "跳入指令中部"（JUMPOUT 制造机），
    // 全部常量随机化（见 buildX86PoisonAsm）。
    // 该块之后编译器仍会附加 jmp 到 OrigBB（对应 IR 的 br）。
    // 注意：绝不可在 mov/jmp 之前插入"跳过"指令，否则载荷成为
    // 无引用死字节，IDA 不会反汇编它们，也就不会产生 JUMPOUT。
    std::string Ops = buildX86PoisonAsm(/*Is64=*/true);
    InlineAsm *IA = InlineAsm::get(AsmFTy, Ops, "", true);
    B.CreateCall(IA, {});
  } else if (TargetTriple.isX86()) {
    // x86 (32-bit)：同上
    std::string Ops = buildX86PoisonAsm(/*Is64=*/false);
    InlineAsm *IA = InlineAsm::get(AsmFTy, Ops, "", true);
    B.CreateCall(IA, {});
  } else if (TargetTriple.isAArch64() ||
             TargetTriple.getArch() == Triple::aarch64) {
    // AArch64：SP 收敛投毒 —— Hex-Rays 的杀手。
    //
    // 死块把 SP 随机加减 N（16 的倍数，方向随机）后直落 IR 终止符
    // (b <destination>) 对应的位置。真路以正常 SP 到达汇合点，死路
    // 以 SP±N 到达。两条"可达"路径汇合时，Hex-Rays 的 SP 追踪器
    // 发现不一致，直接放弃：sp-analysis failed / positive sp value，
    // 整个函数的伪代码质量崩溃或无法生成。
    //
    // 关键：死块不得以 br xN / noreturn BL 收尾 —— 不可解的间接跳转
    // 会让 IDA 停止跟随死路，SP 冲突永远观察不到（旧实现的 bug）。
    //
    // ldr 仅作数据引用噪声：把随机字节 blob 的引用拉进死块（xref 污染），
    // 其值不参与跳转。寄存器编号随机化。
    //
    // 运行时安全：不透明谓词恒真，死块永不执行，SP 扰动不可能污染真栈。
    GlobalVariable *TargetPtr = getOrCreateBogusTargetPtr(*M);
    unsigned Step = 16 * (1 + cryptoutils->get_uint32_t() % 63); // 16..1008
    const char *Op = (cryptoutils->get_uint32_t() & 1) ? "add" : "sub";
    unsigned RegN = 16 + (cryptoutils->get_uint32_t() & 1); // x16 / x17
    std::string Reg = "x" + std::to_string(RegN);
    std::string Ops = std::string(Op) + " sp, sp, #" + std::to_string(Step) +
                      "\n\t" + "ldr " + Reg + ", [$0]\n\t" + "eor " + Reg +
                      ", " + Reg + ", " + Reg + "\n\t";
    FunctionType *AsmFTy2 = FunctionType::get(
        Type::getVoidTy(Ctx), {PointerType::getUnqual(Ctx)}, false);
    InlineAsm *IA = InlineAsm::get(AsmFTy2, Ops, "r", true);
    B.CreateCall(IA, {TargetPtr});
    // BogBB 的 IR 终止符 (br <destination>) 会生成 b <destination>：
    // IDA 带着 SP±N 跟随死路进入汇合块 → SP 毒化生效。
  }
}

// ============================================================
// L1 重汇聚诱饵块：
//   只做纯寄存器运算（xor/add/mul），不写内存、不调用、不除法；
//   末尾用空内联汇编 sink 保留副作用（防 ADCE 删除）。
//   两条路都进入 OrigBB，OrigBB 重算一切 → 语义与 base 完全一致。
//   作用：trace/CFG 噪声 + decoy 机制验证；不产生错误结果。
// ============================================================
static void fillDecoyBB(BasicBlock *DecoyBB, Function &F) {
  LLVMContext &Ctx = F.getContext();
  Module *M = F.getParent();
  IRBuilder<> B(DecoyBB);
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  const unsigned PtrBits = M->getDataLayout().getPointerSizeInBits();
  IntegerType *Ty = IntegerType::get(Ctx, PtrBits);
  const uint64_t Mask =
      PtrBits >= 64 ? ~0ull : ((1ull << PtrBits) - 1ull);

  GlobalVariable *Sink = getOrCreateBogusSink(*M);
  Value *J = B.CreateLoad(I64Ty, Sink, /*isVolatile=*/true, "bcf.d");
  if (PtrBits < 64)
    J = B.CreateTrunc(J, Ty);

  unsigned NOps = 2 + cryptoutils->get_uint32_t() % 3;
  for (unsigned i = 0; i < NOps; ++i) {
    uint64_t C = cryptoutils->get_uint64_t() & Mask;
    switch (cryptoutils->get_uint32_t() % 3) {
    case 0:
      J = B.CreateXor(J, ConstantInt::get(Ty, C), "bcf.d");
      break;
    case 1:
      J = B.CreateAdd(J, ConstantInt::get(Ty, C), "bcf.d");
      break;
    default:
      J = B.CreateMul(J, ConstantInt::get(Ty, C | 1ull), "bcf.d");
      break;
    }
  }

  // 空内联汇编 + 输入寄存器 + sideeffect：强制保留 J 的计算，不产生
  // 任何内存访问/函数调用/异常路径。
  FunctionType *FTy = FunctionType::get(Type::getVoidTy(Ctx), {Ty}, false);
  InlineAsm *IA = InlineAsm::get(FTy, "", "r", /*hasSideEffects=*/true);
  B.CreateCall(IA, {J});
}

// ============================================================
// L3 值污染：危险链过滤。
//
// 从 Root（被变异的指令）出发遍历所有使用点。允许的"汇点"只有整数
// return（错误结果正是 L3 的目的）。一旦触达下列任一危险点就拒绝：
//   - 内存写 / 指针操作（load/store/atomic/GEP/alloca）—— 变异值当地址 = 崩溃
//     （唯一例外：写入函数内不逃逸的 alloca 槽，见下方说明；此时沿该槽的
//      load 继续追踪，下游危险用途仍会被拒绝）
//   - 除法/取余（任何操作数）—— 变异值当除数 = 除零/INT_MIN/-1
//   - 移位量 —— 变异后可能 >= 位宽 = poison
//   - 调用/内联汇编参数 —— 被调方行为未知
//   - 分支/switch/间接跳转条件 —— 走错控制流可能死循环
//   - FP->int 转换 —— 越界/NaN = UB
//   - void 消费 / 未知消费者 —— 无法判定
// 遍历预算 400 个 use，超出即拒绝（保守）。
// debug intrinsic 直接跳过（否则 -g 构建会拒绝一切变异）。
// ============================================================
static bool polluteChainIsSafe(Value *Root) {
  SmallPtrSet<Value *, 32> Visited;
  SmallVector<Value *, 32> Worklist;
  Worklist.push_back(Root);
  unsigned Budget = 400;

  while (!Worklist.empty()) {
    Value *V = Worklist.pop_back_val();
    if (!Visited.insert(V).second)
      continue;

    for (Use &U : V->uses()) {
      if (Budget-- == 0)
        return false;

      Instruction *User = dyn_cast<Instruction>(U.getUser());
      if (!User)
        return false;

      if (isa<DbgInfoIntrinsic>(User))
        continue;

      if (auto *RI = dyn_cast<ReturnInst>(User)) {
        Value *RV = RI->getReturnValue();
        if (RV && RV->getType()->isPointerTy())
          return false;
        continue; // 整数/void 返回：允许（污染输出）
      }

      // 内存访问：V 要么是地址，要么是被写值。
      //
      // 例外：写入"函数内、不逃逸的 alloca 槽"是安全的。BCF 跑在
      // pipeline start（mem2reg 之前），此时源码里的局部变量全部是
      // alloca+load/store 形态；若一律拒绝，L3 在真实产物里永远没有
      // 合格站点（实测 e2e 值污染不生效的根因）。
      //
      // 放行条件（全部满足）：
      //   1. 指针是 alloca（stripPointerCasts 后）；
      //   2. 该 alloca 的所有使用都是 load/store/调试/生命周期内建
      //      （任何其它使用 = 地址逃逸 → 拒绝）；
      //   3. V 是被写值（operand 0），不是地址（operand 1）；
      //   4. 从该槽的每个 load 继续追踪（下游危险用途仍会被检查）。
      if (auto *SI = dyn_cast<StoreInst>(User)) {
        if (U.getOperandNo() != 0)
          return false; // V 是地址：变异地址 = 崩溃
        auto *AI = dyn_cast<AllocaInst>(SI->getPointerOperand()
                                            ->stripPointerCasts());
        if (!AI)
          return false;
        for (Use &AU : AI->uses()) {
          Instruction *AUInst = dyn_cast<Instruction>(AU.getUser());
          if (!AUInst)
            return false;
          if (isa<LoadInst>(AUInst) || isa<StoreInst>(AUInst))
            continue;
          if (isa<DbgInfoIntrinsic>(AUInst) ||
              isa<LifetimeIntrinsic>(AUInst))
            continue;
          return false; // alloca 地址逃逸（GEP/调用/...）
        }
        // 沿该槽的 load 继续追踪下游用途。
        for (Use &AU : AI->uses())
          if (auto *LI = dyn_cast<LoadInst>(AU.getUser()))
            Worklist.push_back(LI);
        continue;
      }
      if (isa<LoadInst>(User) || isa<AtomicRMWInst>(User) ||
          isa<AtomicCmpXchgInst>(User))
        return false;
      if (isa<GetElementPtrInst>(User) || isa<AllocaInst>(User))
        return false;

      if (auto *BO = dyn_cast<BinaryOperator>(User)) {
        switch (BO->getOpcode()) {
        case Instruction::SDiv:
        case Instruction::UDiv:
        case Instruction::SRem:
        case Instruction::URem:
          return false;
        default:
          break;
        }
        if (BO->isShift() && U.getOperandNo() == 1)
          return false;
      }

      // 调用 / invoke / callbr：参数不可控。
      if (isa<CallBase>(User))
        return false;

      // 控制流条件：可能死循环。
      if (isa<BranchInst>(User) || isa<SwitchInst>(User) ||
          isa<IndirectBrInst>(User) || isa<InvokeInst>(User) ||
          isa<CallBrInst>(User))
        return false;

      if (auto *CI = dyn_cast<CastInst>(User)) {
        if (isa<FPToSIInst>(CI) || isa<FPToUIInst>(CI))
          return false;
      }

      if (User->getType()->isVoidTy())
        return false;

      Worklist.push_back(User);
    }
  }
  return true;
}

// ============================================================
// L3 值污染：克隆 OrigBB、变异安全常量、绕过 OrigBB 直达后继。
//
// 只处理 br/ret 终止、且不含 alloca/call 的块（栈增长与未知副作用）。
// 变异范围：add/sub/mul/and/or/xor 的整数常量（>=8 位），每条指令最多
// 变异一个；变异前后都要通过 polluteChainIsSafe。
// 克隆后清除 nsw/nuw/exact —— 变异可能让这些 flag 变成 UB。
// 返回 nullptr 表示该块不适合 L3（调用方回退 L1）。
// ============================================================
static BasicBlock *buildPollutedClone(BasicBlock *OrigBB, Function &F) {
  Instruction *Term = OrigBB->getTerminator();
  if (!isa<BranchInst>(Term) && !isa<ReturnInst>(Term))
    return nullptr;

  for (Instruction &I : *OrigBB) {
    if (isa<AllocaInst>(I))
      return nullptr;
    // 原子操作/fence 克隆后会被执行两次，内存序语义改变 → 拒绝。
    if (isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I) || isa<FenceInst>(I))
      return nullptr;
    if (auto *LI = dyn_cast<LoadInst>(&I))
      if (LI->isAtomic())
        return nullptr;
    if (auto *SI = dyn_cast<StoreInst>(&I))
      if (SI->isAtomic())
        return nullptr;
    // lifetime/dbg 内建无实际副作用，克隆后重复执行无害；
    // 其它调用（未知副作用/栈增长）一律拒绝。
    if (auto *CB = dyn_cast<CallBase>(&I))
      if (!isa<LifetimeIntrinsic>(CB) && !isa<DbgInfoIntrinsic>(CB))
        return nullptr;
  }

  ValueToValueMapTy VMap;
  BasicBlock *DecoyBB = CloneBasicBlock(OrigBB, VMap, ".decoy", &F);
  // CloneBasicBlock 把新块追加到函数末尾，且不重映射操作数：
  // 先移到 OrigBB 前面，再对每条指令做 RemapInstruction。
  DecoyBB->moveBefore(OrigBB);
  for (Instruction &I : *DecoyBB)
    RemapInstruction(&I, VMap,
                     RF_NoModuleLevelChanges | RF_IgnoreMissingLocals);

  // 清除可能因变异而变成 UB 的 flag。
  for (Instruction &I : *DecoyBB) {
    if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
      BO->setHasNoSignedWrap(false);
      BO->setHasNoUnsignedWrap(false);
      if (BO->isShift())
        BO->setIsExact(false);
    }
  }

  bool Mutated = false;
  for (Instruction &I : *DecoyBB) {
    if (I.isTerminator())
      continue;
    auto *BO = dyn_cast<BinaryOperator>(&I);
    if (!BO)
      continue;
    switch (BO->getOpcode()) {
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Mul:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Xor:
      break;
    default:
      continue; // 移位/除法/FP 等不改
    }

    for (unsigned Op = 0; Op < BO->getNumOperands(); ++Op) {
      auto *C = dyn_cast<ConstantInt>(BO->getOperand(Op));
      if (!C || C->getBitWidth() < 8)
        continue;
      // 危险链过滤：变异后的值不得触达地址/除数/调用/分支/内存写。
      if (!polluteChainIsSafe(BO))
        continue;

      APInt V = C->getValue();
      uint64_t Delta = 1 + (cryptoutils->get_uint32_t() % 7);
      APInt D(V.getBitWidth(), Delta);
      V = (cryptoutils->get_uint32_t() & 1) ? (V - D) : (V + D);
      BO->setOperand(Op, ConstantInt::get(C->getType(), V));
      Mutated = true;
      break; // 每条指令最多变异一个常量
    }
  }

  if (!Mutated) {
    DecoyBB->eraseFromParent();
    return nullptr;
  }

  // 后继 PHI 增加来自 DecoyBB 的入边（值按 VMap 映射到克隆）。
  for (BasicBlock *Succ : successors(DecoyBB)) {
    for (PHINode &PN : Succ->phis()) {
      Value *In = PN.getIncomingValueForBlock(OrigBB);
      if (!In)
        continue;
      Value *Mapped = In;
      auto It = VMap.find(In);
      if (It != VMap.end())
        Mapped = It->second;
      PN.addIncoming(Mapped, DecoyBB);
    }
  }

  return DecoyBB;
}

namespace {

struct BogusControlFlow : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  // 每函数 L3 站点预算（代码膨胀控制）。
  unsigned PolluteLeft = 0;

  BogusControlFlow(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->ArgsOptions = argsOptions;
  }

  // 复用模块级自由函数（与 bcfDeriveY 的独立随机源共用同一全局变量）。
  GlobalVariable *getOpaqueGlobal(Module &M) {
    return getOrCreateOpaqueGlobal(M);
  }

  StringRef getPassName() const override { return {"BogusControlFlow"}; }

  // 模块级初始化：只有确实存在 decoy 资格（pattern 或注解）时才创建
  // decoy runtime，保证默认构建（decoy=0）零额外符号/全局。
  bool doInitialization(Module &M) override {
    bool NeedDecoy = false;
    for (const ConfigPatternRule &Rule : ArgsOptions->patternRules()) {
      auto It = Rule.Overrides.find("bcf");
      if (It != Rule.Overrides.end() && It->second.Decoy &&
          *It->second.Decoy > 0) {
        NeedDecoy = true;
        break;
      }
    }
    if (!NeedDecoy) {
      for (Function &F : M) {
        if (F.isDeclaration())
          continue;
        if (auto D = readDecoyAnnotation(&F)) {
          if (*D > 0) {
            NeedDecoy = true;
            break;
          }
        }
      }
    }
    if (NeedDecoy)
      getOrCreateDecoyRuntime(M);
    return false;
  }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration() || F.isIntrinsic())
      return false;

    // 工具链自己的运行时函数绝不参与混淆（防递归/自污染）。
    if (F.getMetadata("noobf") || F.getName().starts_with("oboro."))
      return false;
    // 项目提供的 probe 是策略入口，绝不能反过来被 BCF/decoy 插桩
    // （否则 probe -> getenv -> probe 递归）。
    if (F.getName() == BCFProbeSymbol.getValue())
      return false;

    // 特殊函数：改动它们会破坏 ABI/异常/协程/尾调用语义。
    // 注意：optnone 不在此列 —— clang -O0 会给所有函数加 optnone，
    // 若跳过它，-O0 构建将完全无法混淆（实测回归）。optnone 只是
    // "优化器不要动"，BCF 插入菱形不依赖优化，语义安全。
    if (F.hasFnAttribute(Attribute::Naked) ||
        F.hasFnAttribute(Attribute::ReturnsTwice) ||
        F.isPresplitCoroutine())
      return false;
    for (Instruction &I : instructions(F)) {
      if (isa<CallBrInst>(I))
        return false;
      if (auto *CI = dyn_cast<CallInst>(&I))
        if (CI->isMustTailCall())
          return false;
    }

    // 弱符号（STL 模板实例化等）/ 运行时胶水 / 静态初始化 / 构造析构 /
    // 运算符等红黄区函数的跳过已统一收敛到
    // ObfuscationOptions::toObfuscate()（安全底线），此处不再单独判断。

    // 含异常处理（personality / invoke / landingpad）的函数无条件跳过：
    // BCF 菱形 + SP 扰动汇合边与 EH 展开边组合会引发编译时间爆炸
    // （实测 try/catch 函数卡死 >5min），且落地 pad 边界风险高。
    // runtime 安全优先 —— 注解也无法强制参与。
    if (F.hasPersonalityFn())
      return false;

    // 检查是否对此函数应用 BCF
    auto Opt = ArgsOptions->toObfuscate(ArgsOptions->bcfOpt(), &F);
    if (!Opt.isEnabled())
      return false;

    LLVMContext &Ctx = F.getContext();
    unsigned DecoyPct = std::min(100u, Opt.decoy());
    // L3 值污染只在函数显式声明时启用；每函数最多 4 个站点（控体积）。
    PolluteLeft = Opt.decoyPollute() ? 4 : 0;

    // decoy 资格函数：入口取一次 env，所有菱形复用；同时完成校验。
    // 非 decoy 函数完全不产生这条路径（默认零影响）。
    Function *GetEnv = nullptr;
    AllocaInst *EnvSlot = nullptr;
    std::unique_ptr<DominatorTree> DT;
    if (DecoyPct > 0) {
      GetEnv = getOrCreateDecoyRuntime(*F.getParent());
      if (!GetEnv) {
        // probe 类型不兼容等：本模块退回纯 poison 模式。
        DecoyPct = 0;
      } else {
        DT = std::make_unique<DominatorTree>(F);
        IRBuilder<> EB(&F.getEntryBlock(),
                       F.getEntryBlock().getFirstInsertionPt());
        EnvSlot = EB.CreateAlloca(Type::getInt32Ty(Ctx), nullptr,
                                  "bcf.env.slot");
        Value *Env = EB.CreateCall(GetEnv, {}, "bcf.env");
        EB.CreateStore(Env, EnvSlot);
      }
    }

    bool Changed = false;

    // 收集所有合法的目标块（快照，防止迭代时被修改）
    SmallVector<BasicBlock *, 16> Targets;
    for (BasicBlock &BB : F) {
      if (BB.isLandingPad() || BB.isEHPad())
        continue;
      // 只处理有正常终止指令且无 invoke/landingpad 的块
      if (BB.size() < 2)
        continue;
      Instruction *Term = BB.getTerminator();
      if (isa<ReturnInst>(Term) || isa<BranchInst>(Term) ||
          isa<SwitchInst>(Term))
        Targets.push_back(&BB);
    }

    unsigned Prob = BCFProb.getValue();
    if (Prob > 100) Prob = 100;

    // 每函数 BCF 处理块数上限：iostream 等展开的巨型函数有几百个块，
    // 全块 BCF + fixStack 全函数 demote 会让编译时间爆炸。每函数 16 个
    // 毒点对 IDA/Hex-Rays 的破坏效果已经足够。
    unsigned MaxBlocks = 16;

    for (BasicBlock *BB : Targets) {
      if (MaxBlocks == 0)
        break;
      if ((cryptoutils->get_uint32_t() % 100) >= Prob)
        continue;

      // env alloca 位于入口块；若入口块被 split，alloca 会被移到 OrigBB，
      // 不再支配入口 shell 里的 env load。decoy 启用时跳过入口块。
      if (DecoyPct > 0 && BB == &F.getEntryBlock())
        continue;

      bool UseDecoy =
          DecoyPct > 0 && (cryptoutils->get_uint32_t() % 100) < DecoyPct;
      // env 在入口块写入 alloca；不可达块拿不到有效值，跳过。
      if (UseDecoy && DT && !DT->isReachableFromEntry(BB))
        continue;

      if (applyBCFToBlock(BB, F, UseDecoy, EnvSlot)) {
        Changed = true;
        --MaxBlocks;
      }
    }

    if (Changed) {
      fixStack(&F);
    }

    return Changed;
  }

  // ============================================================
  // 对一个 BasicBlock 注入菱形 BCF 结构（安全，无真实环路）
  //
  // 普通模式（poison）：
  //   OpaqueTrue  -> OrigBB（实际执行路径）
  //   OpaqueFalse -> BogBB（不可达死块，Anti-HexRays SP 扰动）
  //
  // decoy 模式（L1 重汇聚，默认）：
  //   base = 恒真式 && (env == 1)
  //   真机 env=1 -> OrigBB
  //   模拟器 env=0 -> DecoyBB（纯计算噪声）-> OrigBB（重算，语义不变）
  //   极性翻转只作用于 base 并同步交换分支目标，保证 env 因子不被取反。
  //
  // decoy 模式（L3 值污染，需 +bcf_decoy_pollute / decoy_pollute:true）：
  //   诱饵块 = OrigBB 的克隆 + 安全常量变异，直接跳向 OrigBB 的后继，
  //   不回到 OrigBB。模拟器拿到错误的计算结果（真机仍走 OrigBB，零影响）。
  //   站点资格由 buildPollutedClone 的危险链过滤决定，不合格自动回退 L1。
  // ============================================================
  bool applyBCFToBlock(BasicBlock *BB, Function &F, bool UseDecoy,
                       AllocaInst *EnvSlot) {
    LLVMContext &Ctx = F.getContext();

    // 1. 把 BB 从第一条非 PHI 指令处分裂
    BasicBlock *OrigBB =
        BB->splitBasicBlock(BB->getFirstNonPHI(), "bcf.orig");

    // 2. 创建死块 / 诱饵块
    BasicBlock *BogBB = nullptr;
    if (UseDecoy && PolluteLeft > 0)
      BogBB = buildPollutedClone(OrigBB, F);
    if (BogBB) {
      // L3：克隆已自带终止符（与原块相同的后继），不再回到 OrigBB。
      --PolluteLeft;
    } else {
      BogBB = BasicBlock::Create(
          Ctx, UseDecoy ? "bcf.decoy" : "bcf.bogus", &F, OrigBB);
      // 3. 填充载荷，然后跳向 OrigBB
      if (UseDecoy)
        fillDecoyBB(BogBB, F);
      else
        fillBogusBB(BogBB, F);
      IRBuilder<> B(BogBB);
      B.CreateBr(OrigBB);
    }

    // 4. 用"编译期未知的运行时值"构造不透明谓词，替换 EntryBB 原跳转
    Instruction *OldTerm = BB->getTerminator();
    {
      IRBuilder<> B(OldTerm);
      Value *Opaque = B.CreateLoad(B.getInt64Ty(),
                                   getOpaqueGlobal(*F.getParent()),
                                   /*isVolatile=*/true, "bcf.ctr");
      Value *Cond = buildOpaqueCond(B, *F.getParent(), Opaque);
      if (UseDecoy) {
        // env 从函数入口的 alloca 读取（入口已 getenv 一次）。
        Value *Env =
            B.CreateLoad(Type::getInt32Ty(Ctx), EnvSlot, "bcf.env");
        Value *EnvOk = B.CreateICmpEQ(Env, B.getInt32(1), "bcf.envok");
        Value *Base = B.CreateAnd(Cond, EnvOk, "bcf.base");
        const bool Pol = cryptoutils->get_uint32_t() & 1;
        Value *Final = Pol ? B.CreateNot(Base, "bcf.pol") : Base;
        B.CreateCondBr(Final, Pol ? BogBB : OrigBB, Pol ? OrigBB : BogBB);
      } else if (cryptoutils->get_uint32_t() & 1) {
        // 极性翻转：恒假谓词 + 分支方向互换（改变静态识别形态；
        // 运行时仍恒走 OrigBB）
        B.CreateCondBr(B.CreateNot(Cond, "bcf.pol"), BogBB, OrigBB);
      } else {
        B.CreateCondBr(Cond, OrigBB, BogBB);
      }
    }
    OldTerm->eraseFromParent();

    return true;
  }
};

} // anonymous namespace

char BogusControlFlow::ID = 0;

FunctionPass *llvm::createBogusControlFlowPass(ObfuscationOptions *argsOptions) {
  return new BogusControlFlow(argsOptions);
}
