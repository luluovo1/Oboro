// BcfShared.cpp
// BCF 与 DecoyPass 共享的不透明谓词引擎、命名卫生、毒载荷与站点拓扑。
//
// 从 BogusControlFlow.cpp 拆分而来：两个 pass 必须共用同一套谓词数学与
// CFG 形态，否则分析者能靠"数学式/拓扑差异"区分两类站点。

#include "llvm/Transforms/Obfuscation/BcfShared.h"
#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/SmallVector.h"

// CryptoUtils 最后包含，避免其宏污染上方头文件
#include "llvm/CryptoUtils.h"
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
#include <cstdlib>

using namespace llvm;

namespace llvm {

static cl::opt<unsigned> BCFPred(
    "irobf-bcf_pred", cl::init(0), cl::Hidden,
    cl::desc("Force opaque predicate family (0=random, 1..12). Testing knob."),
    cl::ZeroOrMore);

// 谓词熵源固定为两者都用：1 = 模块级 volatile 全局池，2 = 每函数栈锚点。
// 站点逐个独立选源，单一全局被 patch 时只影响命中它的站点。
// 这是实现细节，不再暴露成命令行选项。
static constexpr unsigned BCFSourcesMask = 3;

static bool useDebugNames() { return obf::debugNames(); }

static cl::opt<unsigned>
    BCFTopo("irobf-bcf_topo", cl::init(0), cl::Hidden,
            cl::desc("Force BCF topology (0=random, 1=diamond, 2=triangle, "
                     "3=switch fan, 4=fused). Testing knob."),
            cl::ZeroOrMore);

static unsigned forcedTopology() {
  if (BCFTopo)
    return BCFTopo;
  static const unsigned Env = []() {
    const char *E = ::getenv("OBORO_BCF_TOPO");
    return E ? static_cast<unsigned>(::atoi(E)) : 0u;
  }();
  return Env;
}

StringRef bcfName(StringRef Tag) {
  return useDebugNames() ? Tag : StringRef();
}

std::string bcfAuxGlobalName(Module &M, StringRef Tag) {
  if (useDebugNames())
    return ("llvm.bcf." + Tag).str();
  // 稳定名由命名层维护（进程内 tag→name 映射），不写 IR 元数据：
  // 产物里没有 "tag → 实体名" 的对照表可供反查。
  return obf::stableName(M, Tag);
}

static Value *bcfRotl(IRBuilder<> &B, Module &M, Value *V, unsigned R) {
  R &= 63;
  if (!R)
    return V;
  return B.CreateCall(
      Intrinsic::getOrInsertDeclaration(&M, Intrinsic::fshl, {V->getType()}),
      {V, V, ConstantInt::get(V->getType(), R)}, bcfName("bcf.r"));
}

static Value *bcfRotr(IRBuilder<> &B, Module &M, Value *V, unsigned R) {
  R &= 63;
  if (!R)
    return V;
  return B.CreateCall(
      Intrinsic::getOrInsertDeclaration(&M, Intrinsic::fshr, {V->getType()}),
      {V, V, ConstantInt::get(V->getType(), R)}, bcfName("bcf.r"));
}

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
          bcfName("bcf.t"));
      break;
    default:
      X = B.CreateAdd(
          X, ConstantInt::get(X->getType(), cryptoutils->get_uint64_t()),
          bcfName("bcf.t"));
      break;
    }
  }
  return X;
}

static constexpr unsigned OpaquePoolSize = 3;

static GlobalVariable *getOpaquePoolGlobal(Module &M, unsigned Index) {
  std::string Tag =
      Index == 0 ? std::string("opaque") : "opaque" + std::to_string(Index);
  std::string Name = bcfAuxGlobalName(M, Tag);
  if (GlobalVariable *G = M.getGlobalVariable(Name, true))
    return G;
  IntegerType *I64Ty = Type::getInt64Ty(M.getContext());
  GlobalVariable *GV = new GlobalVariable(
      M, I64Ty, /*isConstant=*/false, GlobalValue::PrivateLinkage,
      ConstantInt::get(I64Ty, cryptoutils->get_uint64_t()), Name);
  GV->setAlignment(MaybeAlign(8));
  return GV;
}

// 栈锚点只在常规栈 ABI 的函数里使用：naked 没有栈帧、协程有自己的帧
// 布局、personality/funclet 函数跨 EH 边界。这些情况回退到全局源。
static bool canUseStackAnchor(Function &F) {
  if (F.hasPersonalityFn() || F.hasFnAttribute(Attribute::Naked) ||
      F.hasFnAttribute(Attribute::ReturnsTwice) || F.isPresplitCoroutine())
    return false;
  for (const BasicBlock &BB : F)
    for (const Instruction &I : BB)
      if (isa<CatchPadInst>(I) || isa<CleanupPadInst>(I) ||
          isa<CatchSwitchInst>(I))
        return false;
  return true;
}

// 每函数一个栈锚点，建在 entry 块。名字与其它实体一样来自模块盐，
// 不额外写元数据；重复调用按名字复用，不会每站点新建 alloca。
static Value *getStackAnchor(IRBuilder<> &B, Function &F) {
  Module &M = *F.getParent();
  const std::string Name = bcfAuxGlobalName(M, "anchor");
  BasicBlock &Entry = F.getEntryBlock();
  AllocaInst *Anchor = nullptr;
  for (Instruction &I : Entry) {
    auto *AI = dyn_cast<AllocaInst>(&I);
    if (AI && AI->hasName() && AI->getName() == Name) {
      Anchor = AI;
      break;
    }
  }
  if (!Anchor) {
    IRBuilder<> EB(&Entry, Entry.getFirstInsertionPt());
    Anchor = EB.CreateAlloca(Type::getInt8Ty(F.getContext()), nullptr, Name);
    Anchor->setAlignment(Align(8));
  }
  // 指针宽度从 DataLayout 取，统一零扩展到 64 位：32 位目标同样成立。
  Value *Addr = B.CreatePtrToInt(
      Anchor, B.getIntPtrTy(M.getDataLayout()), bcfName("bcf.ctr"));
  if (Addr->getType() != B.getInt64Ty())
    Addr = B.CreateZExt(Addr, B.getInt64Ty(), bcfName("bcf.ctr"));
  return Addr;
}

Value *bcfGetOpaqueSource(IRBuilder<> &B, Function &F) {
  Module &M = *F.getParent();
  unsigned Mask = BCFSourcesMask & 3u;
  if (Mask == 0)
    Mask = 3;

  SmallVector<unsigned, 4> Choices;
  if (Mask & 1u)
    for (unsigned I = 0; I < OpaquePoolSize; ++I)
      Choices.push_back(I);
  if ((Mask & 2u) && canUseStackAnchor(F))
    Choices.push_back(OpaquePoolSize);
  if (Choices.empty())
    Choices.push_back(0);

  unsigned Pick = Choices[cryptoutils->get_uint32_t() % Choices.size()];
  if (Pick == OpaquePoolSize)
    return getStackAnchor(B, F);
  return B.CreateLoad(B.getInt64Ty(), getOpaquePoolGlobal(M, Pick),
                      /*isVolatile=*/true, bcfName("bcf.ctr"));
}

static Value *bcfConsecProduct(IRBuilder<> &B, Value *X, unsigned K,
                               uint64_t Mask) {
  Type *I64 = B.getInt64Ty();
  uint64_t A = cryptoutils->get_uint64_t();
  Value *T = B.CreateAdd(X, ConstantInt::get(I64, A), bcfName("bcf.t"));
  Value *P = T;
  for (unsigned i = 1; i < K; ++i) {
    Value *Ti = B.CreateAdd(T, ConstantInt::get(I64, i), bcfName("bcf.t"));
    P = B.CreateMul(P, Ti, bcfName("bcf.p"));
  }
  return B.CreateICmpEQ(B.CreateAnd(P, ConstantInt::get(I64, Mask), bcfName("bcf.b")),
                        ConstantInt::get(I64, 0), bcfName("bcf.c"));
}

static unsigned bcfPickKind() {
  if (unsigned Forced = BCFPred.getValue())
    return Forced;
  //              1  2  3  4  5  6  7  8  9 10 11 12
  static const unsigned Weights[12] = {0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 2, 2};
  unsigned R = cryptoutils->get_uint32_t() % 10;
  for (unsigned i = 0; i < 12; ++i) {
    if (R < Weights[i])
      return i + 1;
    R -= Weights[i];
  }
  return 5;
}

static Value *bcfBuildFamily(IRBuilder<> &B, Function &F, Value *X,
                             unsigned Kind) {
  Module &M = *F.getParent();
  Type *I64 = B.getInt64Ty();
  auto C = [&](uint64_t V) { return ConstantInt::get(I64, V); };
  // 双变量族的第二个操作数：独立选源 + 独立变换，与 X 不共享熵源。
  auto DeriveY = [&]() {
    return bcfTransformInput(B, M, bcfGetOpaqueSource(B, F));
  };

  switch (Kind) {
  case 1: { // x*~x：bit0(x)·bit0(~x) = b·(1-b) = 0
    Value *P = B.CreateMul(X, B.CreateNot(X, bcfName("bcf.n")), bcfName("bcf.p"));
    return B.CreateICmpEQ(B.CreateAnd(P, C(1), bcfName("bcf.b")), C(0), bcfName("bcf.c"));
  }
  case 2: { // x*(x+1)：连续数之积恒偶
    Value *P = B.CreateMul(X, B.CreateAdd(X, C(1), bcfName("bcf.a")), bcfName("bcf.p"));
    return B.CreateICmpEQ(B.CreateAnd(P, C(1), bcfName("bcf.b")), C(0), bcfName("bcf.c"));
  }
  case 3: { // x^4 mod 16 ∈ {0,1}：偶数 → 0，奇数 → 1
    Value *X2 = B.CreateMul(X, X, bcfName("bcf.s"));
    Value *X4 = B.CreateMul(X2, X2, bcfName("bcf.q"));
    return B.CreateICmpEQ(B.CreateAnd(X4, C(14), bcfName("bcf.b")), C(0), bcfName("bcf.c"));
  }
  case 4: { // bit0(x+y) == bit0(x)^bit0(y)（bit0 无进位入）
    Value *Y = DeriveY();
    Value *L = B.CreateAnd(B.CreateAdd(X, Y, bcfName("bcf.s")), C(1), bcfName("bcf.b"));
    Value *R = B.CreateXor(B.CreateAnd(X, C(1), bcfName("bcf.b")),
                           B.CreateAnd(Y, C(1), bcfName("bcf.b")), bcfName("bcf.bx"));
    return B.CreateICmpEQ(L, R, bcfName("bcf.c"));
  }
  case 5: { // 4/5 连续数之积 & 7 == 0
    unsigned K = (cryptoutils->get_uint32_t() & 1) ? 4 : 5;
    return bcfConsecProduct(B, X, K, 7);
  }
  case 6: { // (x-y) == (x^y) - ((~x&y)<<1)（减法借位恒等式）
    Value *Y = DeriveY();
    Value *D = B.CreateSub(X, Y, bcfName("bcf.d"));
    Value *XO = B.CreateXor(X, Y, bcfName("bcf.x"));
    Value *NAY = B.CreateAnd(B.CreateNot(X, bcfName("bcf.n")), Y, bcfName("bcf.na"));
    Value *SH = B.CreateShl(NAY, C(1), bcfName("bcf.sh"));
    return B.CreateICmpEQ(D, B.CreateSub(XO, SH, bcfName("bcf.r")), bcfName("bcf.c"));
  }
  case 7: { // bit0(x*y) == bit0(x)&bit0(y)
    Value *Y = DeriveY();
    Value *L = B.CreateAnd(B.CreateMul(X, Y, bcfName("bcf.p")), C(1), bcfName("bcf.b"));
    Value *R = B.CreateAnd(B.CreateAnd(X, C(1), bcfName("bcf.b")),
                           B.CreateAnd(Y, C(1), bcfName("bcf.b")), bcfName("bcf.ba"));
    return B.CreateICmpEQ(L, R, bcfName("bcf.c"));
  }
  case 8: // 6 连续数之积 & 15 == 0
    return bcfConsecProduct(B, X, 6, 15);
  case 9: { // popcount(x)+popcount(~x) == 64（每个 bit 恰贡献 1）
    Function *Ctpop =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::ctpop, {I64});
    Value *P1 = B.CreateCall(Ctpop, {X}, bcfName("bcf.pc"));
    Value *P2 = B.CreateCall(Ctpop, {B.CreateNot(X, bcfName("bcf.n"))}, bcfName("bcf.pc"));
    return B.CreateICmpEQ(B.CreateAdd(P1, P2, bcfName("bcf.s")), C(64), bcfName("bcf.c"));
  }
  case 10: { // (x^y)+2*(x&y) == x+y（进位恒等式）
    Value *Y = DeriveY();
    Value *XO = B.CreateXor(X, Y, bcfName("bcf.x"));
    Value *A2 = B.CreateShl(B.CreateAnd(X, Y, bcfName("bcf.a")), C(1), bcfName("bcf.a2"));
    Value *L = B.CreateAdd(XO, A2, bcfName("bcf.l"));
    return B.CreateICmpEQ(L, B.CreateAdd(X, Y, bcfName("bcf.r")), bcfName("bcf.c"));
  }
  case 11: { // popcount(x|y)+popcount(x&y) == popcount(x)+popcount(y)
    Value *Y = DeriveY();
    Function *Ctpop =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::ctpop, {I64});
    Value *PO = B.CreateCall(Ctpop, {B.CreateOr(X, Y, bcfName("bcf.o"))}, bcfName("bcf.pc"));
    Value *PA = B.CreateCall(Ctpop, {B.CreateAnd(X, Y, bcfName("bcf.a"))}, bcfName("bcf.pc"));
    Value *PX = B.CreateCall(Ctpop, {X}, bcfName("bcf.pc"));
    Value *PY = B.CreateCall(Ctpop, {Y}, bcfName("bcf.pc"));
    return B.CreateICmpEQ(B.CreateAdd(PO, PA, bcfName("bcf.l")),
                          B.CreateAdd(PX, PY, bcfName("bcf.r")), bcfName("bcf.c"));
  }
  case 12: // 8 连续数之积 & 127 == 0（v2(8!)=7；O2 下 SLP 会向量化成 reduce.mul）
    return bcfConsecProduct(B, X, 8, 127);
  default: { // 兜底：族 2
    Value *P = B.CreateMul(X, B.CreateAdd(X, C(1), bcfName("bcf.a")), bcfName("bcf.p"));
    return B.CreateICmpEQ(B.CreateAnd(P, C(1), bcfName("bcf.b")), C(0), bcfName("bcf.c"));
  }
  }
}

Value *bcfBuildOpaqueCond(IRBuilder<> &B, Function &F, Value *Src) {
  Module &M = *F.getParent();
  Value *X = bcfTransformInput(B, M, Src);
  unsigned Kind = bcfPickKind();
  Value *Cond = bcfBuildFamily(B, F, X, Kind);
  // 概率 1/5：双族 AND 组合（两族都被证伪才会折叠；强制测试时不组合）
  if (!BCFPred.getValue() && (cryptoutils->get_uint32_t() % 5 == 0)) {
    unsigned Kind2 = bcfPickKind();
    if (Kind2 == Kind)
      Kind2 = (Kind % 12) + 1;
    Value *C2 = bcfBuildFamily(B, F, bcfTransformInput(B, M, Src), Kind2);
    Cond = B.CreateAnd(Cond, C2, bcfName("bcf.c2"));
  }
  return Cond;
}

static GlobalVariable *bcfGetOrCreateBogusBlob(Module &M) {
  std::string Name = bcfAuxGlobalName(M, "bogus_blob");
  if (GlobalVariable *G = M.getGlobalVariable(Name, true))
    return G;
  LLVMContext &Ctx = M.getContext();
  const unsigned BlobSize = 64;
  std::vector<uint8_t> Bytes(BlobSize);
  for (auto &Byte : Bytes)
    Byte = static_cast<uint8_t>(cryptoutils->get_uint32_t());
  Constant *Init = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(Bytes));
  auto *Blob = new GlobalVariable(M, Init->getType(), /*isConstant=*/true,
                                  GlobalValue::PrivateLinkage, Init, Name);
  Blob->setAlignment(MaybeAlign(4));
  // ELF/COFF 下并入 .text 输出段（可执行）：内容并非合法函数序言，
  // 反汇编器强行解码会产生垃圾指令流。其他 object format 没有等价
  // 的扁平代码节区，交给 LLVM 默认节区，保持 IR 可移植。
  StringRef Section = obf::sectionName(M);
  if (!Section.empty())
    Blob->setSection(Section);
  return Blob;
}

static GlobalVariable *bcfGetOrCreateBogusTargetPtr(Module &M) {
  std::string Name = bcfAuxGlobalName(M, "bogus_target");
  if (GlobalVariable *G = M.getGlobalVariable(Name, true))
    return G;
  LLVMContext &Ctx = M.getContext();
  GlobalVariable *Blob = bcfGetOrCreateBogusBlob(M);
  Constant *Idx[] = {ConstantInt::get(Type::getInt64Ty(Ctx), 0),
                     ConstantInt::get(Type::getInt64Ty(Ctx), 17)};
  Constant *TargetAddr = ConstantExpr::getInBoundsGetElementPtr(
      Blob->getValueType(), Blob, Idx);
  auto *Ptr = new GlobalVariable(M, PointerType::getUnqual(Ctx),
                                 /*isConstant=*/true,
                                 GlobalValue::PrivateLinkage, TargetAddr, Name);
  Ptr->setAlignment(MaybeAlign(8));
  return Ptr;
}

GlobalVariable *bcfGetBogusSink(Module &M) {
  std::string Name = bcfAuxGlobalName(M, "sink");
  if (GlobalVariable *G = M.getGlobalVariable(Name, true))
    return G;
  LLVMContext &Ctx = M.getContext();
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  auto *GV = new GlobalVariable(M, I64Ty, /*isConstant=*/false,
                                GlobalValue::PrivateLinkage,
                                ConstantInt::get(I64Ty, cryptoutils->get_uint64_t()),
                                Name);
  GV->setAlignment(MaybeAlign(8));
  return GV;
}

static std::string bcfBuildX86PoisonAsm(bool Is64) {
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

void bcfFillBogusBB(BasicBlock *BogBB, Function &F) {
  LLVMContext &Ctx = F.getContext();
  Module *M = F.getParent();
  IRBuilder<> B(BogBB);
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);

  // 1. 真实副作用的垃圾读改写（volatile load → 随机运算 → volatile store，
  //    无法被 DCE；运行时永不执行，但静态分析必须处理这段数据流）
  {
    GlobalVariable *Sink = bcfGetBogusSink(*M);
    Value *J = B.CreateLoad(I64Ty, Sink, /*isVolatile=*/true, bcfName("bcf.j"));
    unsigned NOps = 2 + cryptoutils->get_uint32_t() % 2;
    for (unsigned i = 0; i < NOps; ++i) {
      uint64_t C = cryptoutils->get_uint64_t();
      switch (cryptoutils->get_uint32_t() % 4) {
      case 0:
        J = B.CreateXor(J, ConstantInt::get(I64Ty, C), bcfName("bcf.j"));
        break;
      case 1:
        J = B.CreateAdd(J, ConstantInt::get(I64Ty, C), bcfName("bcf.j"));
        break;
      case 2:
        J = B.CreateMul(J, ConstantInt::get(I64Ty, C | 1ull), bcfName("bcf.j"));
        break;
      default:
        J = B.CreateSub(J, ConstantInt::get(I64Ty, C), bcfName("bcf.j"));
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
    std::string Ops = bcfBuildX86PoisonAsm(/*Is64=*/true);
    InlineAsm *IA = InlineAsm::get(AsmFTy, Ops, "", true);
    B.CreateCall(IA, {});
  } else if (TargetTriple.isX86()) {
    // x86 (32-bit)：同上
    std::string Ops = bcfBuildX86PoisonAsm(/*Is64=*/false);
    InlineAsm *IA = InlineAsm::get(AsmFTy, Ops, "", true);
    B.CreateCall(IA, {});
  } else if ((TargetTriple.isAArch64() ||
              TargetTriple.getArch() == Triple::aarch64) &&
             TargetTriple.isOSBinFormatELF()) {
    // 仅 ELF 目标（Android/Linux 等）：SP 内联汇编在 COFF/Mach-O 上的
    // unwind/SEH 语义未验证，这些目标回退到上面的通用 sink 载荷。
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
    GlobalVariable *TargetPtr = bcfGetOrCreateBogusTargetPtr(*M);
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

static bool bcfApplyDiamond(BasicBlock *BB, Function &F) {
    LLVMContext &Ctx = F.getContext();

    // 1. 把 BB 从第一条非 PHI 指令处分裂
    BasicBlock *OrigBB =
        BB->splitBasicBlock(BB->getFirstNonPHIIt(), bcfName("bcf.orig"));

    // 2. 创建死块并填充毒载荷，然后跳向 OrigBB
    BasicBlock *BogBB =
        BasicBlock::Create(Ctx, bcfName("bcf.bogus"), &F, OrigBB);
    bcfFillBogusBB(BogBB, F);
    IRBuilder<> B(BogBB);
    B.CreateBr(OrigBB);

    // 4. 用"编译期未知的运行时值"构造不透明谓词，替换 EntryBB 原跳转
    Instruction *OldTerm = BB->getTerminator();
    {
      IRBuilder<> B(OldTerm);
      Value *Opaque = bcfGetOpaqueSource(B, F);
      Value *Cond = bcfBuildOpaqueCond(B, F, Opaque);
      if (cryptoutils->get_uint32_t() & 1) {
        // 极性翻转：恒假谓词 + 分支方向互换（改变静态识别形态；
        // 运行时仍恒走 OrigBB）
        B.CreateCondBr(B.CreateNot(Cond, bcfName("bcf.pol")), BogBB, OrigBB);
      } else {
        B.CreateCondBr(Cond, OrigBB, BogBB);
      }
    }
    OldTerm->eraseFromParent();

    return true;
  }

static bool bcfApplyTriangle(BasicBlock *BB, Function &F) {
    LLVMContext &Ctx = F.getContext();
    BasicBlock *OrigBB =
        BB->splitBasicBlock(BB->getFirstNonPHIIt(), bcfName("bcf.orig"));

    BasicBlock *BogBB =
        BasicBlock::Create(Ctx, bcfName("bcf.bogus"), &F, OrigBB);
    bcfFillBogusBB(BogBB, F);
    new UnreachableInst(Ctx, BogBB);

    Instruction *OldTerm = BB->getTerminator();
    {
      IRBuilder<> B(OldTerm);
      Value *Opaque = bcfGetOpaqueSource(B, F);
      Value *Cond = bcfBuildOpaqueCond(B, F, Opaque);
      if (cryptoutils->get_uint32_t() & 1)
        B.CreateCondBr(B.CreateNot(Cond, bcfName("bcf.pol")), BogBB, OrigBB);
      else
        B.CreateCondBr(Cond, OrigBB, BogBB);
    }
    OldTerm->eraseFromParent();
    return true;
  }

static bool bcfApplySwitchFan(BasicBlock *BB, Function &F) {
    LLVMContext &Ctx = F.getContext();
    BasicBlock *OrigBB =
        BB->splitBasicBlock(BB->getFirstNonPHIIt(), bcfName("bcf.orig"));

    unsigned NumDead = 2 + cryptoutils->get_uint32_t() % 3;
    SmallVector<BasicBlock *, 4> Dead;
    for (unsigned I = 0; I < NumDead; ++I) {
      BasicBlock *D =
          BasicBlock::Create(Ctx, bcfName("bcf.bogus"), &F, OrigBB);
      bcfFillBogusBB(D, F);
      IRBuilder<> DB(D);
      DB.CreateBr(OrigBB);
      Dead.push_back(D);
    }

    Instruction *OldTerm = BB->getTerminator();
    {
      IRBuilder<> B(OldTerm);
      Value *Opaque = bcfGetOpaqueSource(B, F);
      Value *Cond = bcfBuildOpaqueCond(B, F, Opaque);

      // Real/Fake 都取低 30 位，NumDead <= 4，case 值不会回绕冲突。
      uint32_t Real = (cryptoutils->get_uint32_t() & 0x3FFFFFFFu) | 1u;
      uint32_t Fake = Real + 1u + cryptoutils->get_uint32_t() % 0x1000u;

      Value *V = B.CreateSelect(Cond, B.getInt32(Real), B.getInt32(Fake),
                                bcfName("bcf.v"));
      SwitchInst *SI = B.CreateSwitch(V, Dead[0], NumDead);
      SI->addCase(B.getInt32(Real), OrigBB);
      for (unsigned I = 0; I < NumDead; ++I)
        SI->addCase(B.getInt32(Fake + I), Dead[I]);
    }
    OldTerm->eraseFromParent();
    return true;
  }

static bool bcfApplyFused(BasicBlock *BB, Function &F) {
    BasicBlock *Succ = BB->getSingleSuccessor();
    if (!Succ || !Succ->phis().empty())
      return false;

    LLVMContext &Ctx = F.getContext();
    BasicBlock *BogBB =
        BasicBlock::Create(Ctx, bcfName("bcf.bogus"), &F, Succ);
    bcfFillBogusBB(BogBB, F);
    {
      IRBuilder<> DB(BogBB);
      DB.CreateBr(Succ);
    }

    Instruction *OldTerm = BB->getTerminator();
    {
      IRBuilder<> B(OldTerm);
      Value *Opaque = bcfGetOpaqueSource(B, F);
      Value *Cond = bcfBuildOpaqueCond(B, F, Opaque);
      if (cryptoutils->get_uint32_t() & 1)
        B.CreateCondBr(B.CreateNot(Cond, bcfName("bcf.pol")), BogBB, Succ);
      else
        B.CreateCondBr(Cond, Succ, BogBB);
    }
    OldTerm->eraseFromParent();
    return true;
  }

bool bcfApplyTopology(BasicBlock *BB, Function &F) {
    unsigned Topo = forcedTopology();
    if (!Topo) {
      unsigned R = cryptoutils->get_uint32_t() % 100;
      Topo = R < 30 ? 1u : (R < 50 ? 2u : (R < 75 ? 3u : 4u));
    }
    switch (Topo) {
    case 2:
      return bcfApplyTriangle(BB, F);
    case 3:
      return bcfApplySwitchFan(BB, F);
    case 4:
      // 多后继或后继带 PHI：融合不安全，退回菱形。
      return bcfApplyFused(BB, F) ? true : bcfApplyDiamond(BB, F);
    default:
      return bcfApplyDiamond(BB, F);
    }
  }


} // namespace llvm
