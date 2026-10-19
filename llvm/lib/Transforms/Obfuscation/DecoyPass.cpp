// DecoyPass.cpp
// 运行时误导机制（独立于 BCF）：
//   probe 判据 + L1 重汇聚诱饵 + L3 值污染 + 运行时双 share 硬化。
//
// 从 BogusControlFlow.cpp 拆分而来。与 BCF 共用谓词/拓扑/命名（BcfShared.h），
// 让位规则保证同一函数不会被两个 pass 重复插桩（见 BCF runOnFunction）。

#include "llvm/Transforms/Obfuscation/DecoyPass.h"
#include "llvm/Transforms/Obfuscation/BcfShared.h"
#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/EHPersonalities.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

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
#include <memory>
#include <string>
#include <vector>

using namespace llvm;

static cl::opt<std::string>
    BCFProbeSymbol("irobf-probe-symbol", cl::init("__oboro_probe"),
                   cl::NotHidden,
                   cl::desc("Symbol name of the project-provided decoy probe "
                            "(default: __oboro_probe)."),
                   cl::ZeroOrMore);

static cl::opt<bool>
    BCFForceDecoy("irobf-force-decoy", cl::init(false), cl::Hidden,
                  cl::desc("Force decoy env=0 for testing."), cl::ZeroOrMore);

static cl::opt<bool>
    BCFForceReal("irobf-force-real", cl::init(false), cl::Hidden,
                 cl::desc("Force decoy env=1 for testing/CI."), cl::ZeroOrMore);

static Function *getOrCreateDecoyRuntime(Module &M) {
  LLVMContext &Ctx = M.getContext();
  // 类型不匹配的 probe 声明会让 CreateCall 生成非法 IR（verifier abort）。
  // 一旦发现，禁用本模块的 decoy 并留下标记，避免每个函数重复告警。
  const std::string DisabledTag = obf::metaName(M, "disabled");
  if (M.getNamedMetadata(DisabledTag))
    return nullptr;
  const std::string GetEnvName = obf::stableName(M, "oboro.getenv");
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
    M.getOrInsertNamedMetadata(DisabledTag);
    return nullptr;
  }
  auto EmitDefaultProbeBody = [&](Function *F) {
    F->setLinkage(GlobalValue::WeakAnyLinkage);
    F->setVisibility(GlobalValue::HiddenVisibility);
    F->addFnAttr(Attribute::NoInline);
    F->addFnAttr(Attribute::OptimizeNone);
    obf::markRuntimeFunction(M, *F);
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
    IRBuilder<> B(BB);
    const std::string DefaultEnvName = obf::stableName(M, "oboro.default_env");
    GlobalVariable *DefaultEnv = M.getNamedGlobal(DefaultEnvName);
    if (!DefaultEnv) {
      DefaultEnv = new GlobalVariable(
          M, I32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
          ConstantInt::get(I32, 1), DefaultEnvName);
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
    obf::markRuntimeFunction(M, *F);
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
    IRBuilder<> B(BB);
    B.CreateRet(B.getInt32(Value));
    return F;
  };
  Function *A0 = GetOrCreateAnchor(obf::freshName(M, "oboro.anchor0"),
                                   cryptoutils->get_uint32_t() & ~1u);
  Function *A1 = GetOrCreateAnchor(obf::freshName(M, "oboro.anchor1"),
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
  GlobalVariable *S1 =
      GetOrCreateI32Global(obf::freshName(M, "oboro.s1"), 0);
  GlobalVariable *S2 =
      GetOrCreateI32Global(obf::freshName(M, "oboro.s2"), 0);
  GlobalVariable *Inited =
      GetOrCreateI32Global(obf::freshName(M, "oboro.inited"), 0);
  GlobalVariable *Tampered =
      GetOrCreateI32Global(obf::freshName(M, "oboro.tampered"), TamperKey);

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
                                    obf::freshName(M, "oboro.init"), M);
  Init->addFnAttr(Attribute::NoInline);
  Init->addFnAttr(Attribute::OptimizeNone);
  Init->addMetadata(obf::metaName(M, "noobf"), *MDNode::get(Ctx, {}));
  obf::markRuntimeFunction(M, *Init);
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
  GetEnv->addMetadata(obf::metaName(M, "noobf"), *MDNode::get(Ctx, {}));
  obf::markRuntimeFunction(M, *GetEnv);
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

  // ---- constructor：低优先级区间内随机，尽早初始化 ----
  Function *Ctor = Function::Create(FunctionType::get(Void, false),
                                    GlobalValue::InternalLinkage,
                                    obf::freshName(M, "oboro.ctor"), M);
  Ctor->addFnAttr(Attribute::NoInline);
  Ctor->addFnAttr(Attribute::OptimizeNone);
  Ctor->addMetadata(obf::metaName(M, "noobf"), *MDNode::get(Ctx, {}));
  obf::markRuntimeFunction(M, *Ctor);
  BasicBlock *CB = BasicBlock::Create(Ctx, "entry", Ctor);
  IRBuilder<> CIB(CB);
  CIB.CreateCall(Init, {});
  CIB.CreateRetVoid();
  // 优先级随机化：固定的 .init_array.101 本身就是可扫描特征。
  appendToGlobalCtors(M, Ctor, 101 + cryptoutils->get_uint32_t() % 800);

  return GetEnv;
}

// ============================================================
// L1 重汇聚诱饵块：
static void fillDecoyBB(BasicBlock *DecoyBB, Function &F) {
  LLVMContext &Ctx = F.getContext();
  Module *M = F.getParent();
  IRBuilder<> B(DecoyBB);
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  const unsigned PtrBits = M->getDataLayout().getPointerSizeInBits();
  IntegerType *Ty = IntegerType::get(Ctx, PtrBits);
  const uint64_t Mask =
      PtrBits >= 64 ? ~0ull : ((1ull << PtrBits) - 1ull);

  GlobalVariable *Sink = bcfGetBogusSink(*M);
  Value *J = B.CreateLoad(I64Ty, Sink, /*isVolatile=*/true, bcfName("bcf.d"));
  if (PtrBits < 64)
    J = B.CreateTrunc(J, Ty);

  unsigned NOps = 2 + cryptoutils->get_uint32_t() % 3;
  for (unsigned i = 0; i < NOps; ++i) {
    uint64_t C = cryptoutils->get_uint64_t() & Mask;
    switch (cryptoutils->get_uint32_t() % 3) {
    case 0:
      J = B.CreateXor(J, ConstantInt::get(Ty, C), bcfName("bcf.d"));
      break;
    case 1:
      J = B.CreateAdd(J, ConstantInt::get(Ty, C), bcfName("bcf.d"));
      break;
    default:
      J = B.CreateMul(J, ConstantInt::get(Ty, C | 1ull), bcfName("bcf.d"));
      break;
    }
  }

  // 空内联汇编 + 输入寄存器 + sideeffect：强制保留 J 的计算，不产生
  // 任何内存访问/函数调用/异常路径。
  FunctionType *FTy = FunctionType::get(Type::getVoidTy(Ctx), {Ty}, false);
  InlineAsm *IA = InlineAsm::get(FTy, "", "r", /*hasSideEffects=*/true);
  B.CreateCall(IA, {J});
}

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


// ===========================================================================
// DecoyPass：运行时误导机制（独立于 BCF 的静态虚假控制流）。
//
// 判据来源：App 提供的 probe 符号（非 0 = 真实路径，0 = 诱饵路径）。
// 工具链不做任何环境检测。资格门：只有函数注解 +bcf_decoy / ^bcf_decoy=N
// 或 config pattern 的 "decoy":N 能启用；CLI 无法开启。
//
// 与 BCF 的让位规则：decoy>0 的函数由本 pass 全权处理（BCF 跳过），
// 内部按 DecoyPct 概率混入纯 poison 菱形（复用共享拓扑），保持形态混合。
// ===========================================================================

namespace {

struct DecoyPass : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  unsigned PolluteLeft = 0; // 每函数 L3 站点预算

  DecoyPass(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->ArgsOptions = argsOptions;
  }

  StringRef getPassName() const override { return "DecoyPass"; }

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

  // decoy 菱形：条件 = 恒真式 && (env == 1)。极性翻转只作用于 base 并同步
  // 交换分支目标，保证 env 因子不被取反。诱饵块可选 L3（克隆+污染）或
  // L1（噪声重汇聚）。
  static bool applyDecoyDiamond(BasicBlock *BB, Function &F, unsigned &Pollute,
                                AllocaInst *EnvSlot) {
    LLVMContext &Ctx = F.getContext();
    BasicBlock *OrigBB =
        BB->splitBasicBlock(BB->getFirstNonPHIIt(), bcfName("bcf.orig"));

    BasicBlock *DecoyBB = nullptr;
    if (Pollute > 0)
      DecoyBB = buildPollutedClone(OrigBB, F);
    if (DecoyBB) {
      // L3：克隆已自带终止符（与原块相同的后继），不再回到 OrigBB。
      --Pollute;
    } else {
      DecoyBB = BasicBlock::Create(Ctx, bcfName("bcf.decoy"), &F, OrigBB);
      fillDecoyBB(DecoyBB, F);
      IRBuilder<> B(DecoyBB);
      B.CreateBr(OrigBB);
    }

    Instruction *OldTerm = BB->getTerminator();
    {
      IRBuilder<> B(OldTerm);
      Value *Opaque = B.CreateLoad(B.getInt64Ty(),
                                   bcfGetOpaqueGlobal(*F.getParent()),
                                   /*isVolatile=*/true, bcfName("bcf.ctr"));
      Value *Cond = bcfBuildOpaqueCond(B, *F.getParent(), Opaque);
      // env 从函数入口的 alloca 读取（入口已 getenv 一次）。
      Value *Env =
          B.CreateLoad(Type::getInt32Ty(Ctx), EnvSlot, bcfName("bcf.env"));
      Value *EnvOk = B.CreateICmpEQ(Env, B.getInt32(1), bcfName("bcf.envok"));
      Value *Base = B.CreateAnd(Cond, EnvOk, bcfName("bcf.base"));
      const bool Pol = cryptoutils->get_uint32_t() & 1;
      Value *Final = Pol ? B.CreateNot(Base, bcfName("bcf.pol")) : Base;
      B.CreateCondBr(Final, Pol ? DecoyBB : OrigBB, Pol ? OrigBB : DecoyBB);
    }
    OldTerm->eraseFromParent();
    return true;
  }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration() || F.isIntrinsic())
      return false;

    // 工具链自己的运行时函数绝不参与混淆（防递归/自污染）。
    Module *M = F.getParent();
    if (F.getMetadata(obf::metaName(*M, "noobf")) ||
        obf::isRuntimeFunction(*M, F))
      return false;
    // 项目提供的 probe 是策略入口，绝不能反过来被插桩
    // （否则 probe -> getenv -> probe 递归）。
    if (F.getName() == BCFProbeSymbol.getValue())
      return false;

    // 特殊函数：改动它们会破坏 ABI/异常/协程/尾调用语义。
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

    // scoped EH（WinEH / Wasm funclets）整体跳过；Itanium EH 正常参与。
    if (F.hasPersonalityFn() &&
        isScopedEHPersonality(classifyEHPersonality(F.getPersonalityFn())))
      return false;

    // 资格：只有 decoy>0 的函数由本 pass 处理（BCF 已让位）。
    auto Opt = ArgsOptions->toObfuscate(ArgsOptions->bcfOpt(), &F);
    if (!Opt.isEnabled())
      return false;
    unsigned DecoyPct = std::min(100u, Opt.decoy());
    if (DecoyPct == 0)
      return false;

    LLVMContext &Ctx = F.getContext();
    PolluteLeft = Opt.decoyPollute() ? 4 : 0;

    Function *GetEnv = getOrCreateDecoyRuntime(*F.getParent());
    // probe 类型不兼容等（getOrCreateDecoyRuntime 返回 null 并留下
    // oboro.disabled 标记）：本函数退回纯 poison 模式。注意 BCF 已让位，
    // 若这里直接 return，decoy 资格函数将零保护——所以必须自己补插
    // poison（与拆分前"同循环概率分流"的行为一致）。
    const bool FallbackPoison = (GetEnv == nullptr);
    std::unique_ptr<DominatorTree> DT;
    AllocaInst *EnvSlot = nullptr;
    if (!FallbackPoison) {
      DT = std::make_unique<DominatorTree>(F);
      IRBuilder<> EB(&F.getEntryBlock(),
                     F.getEntryBlock().getFirstInsertionPt());
      EnvSlot = EB.CreateAlloca(Type::getInt32Ty(Ctx), nullptr,
                                bcfName("bcf.env.slot"));
      Value *Env = EB.CreateCall(GetEnv, {}, bcfName("bcf.env"));
      EB.CreateStore(Env, EnvSlot);
    }

    bool Changed = false;
    SmallVector<BasicBlock *, 16> Targets;
    for (BasicBlock &BB : F) {
      if (BB.isLandingPad() || BB.isEHPad())
        continue;
      if (BB.size() < 2)
        continue;
      Instruction *Term = BB.getTerminator();
      if (isa<ReturnInst>(Term) || isa<BranchInst>(Term) ||
          isa<SwitchInst>(Term))
        Targets.push_back(&BB);
    }

    // 随机采样：与 BCF 一致，先洗牌再按概率过滤，避免"前 16 块"
    // 的固定空间分布成为指纹。
    for (unsigned I = Targets.size(); I > 1; --I) {
      unsigned J = cryptoutils->get_uint32_t() % I;
      std::swap(Targets[I - 1], Targets[J]);
    }

    // 每函数 16 个站点（与 BCF 相同的体积控制）。
    unsigned MaxBlocks = 16;
    for (BasicBlock *BB : Targets) {
      if (MaxBlocks == 0)
        break;
      // env alloca 位于入口块；若入口块被 split，alloca 会被移到 OrigBB，
      // 不再支配入口 shell 里的 env load。跳过入口块。
      if (BB == &F.getEntryBlock())
        continue;
      bool UseDecoy =
          !FallbackPoison && (cryptoutils->get_uint32_t() % 100) < DecoyPct;
      // env 在入口块写入 alloca；不可达块拿不到有效值，跳过。
      if (UseDecoy && !DT->isReachableFromEntry(BB))
        continue;
      bool Ok = UseDecoy ? applyDecoyDiamond(BB, F, PolluteLeft, EnvSlot)
                         : bcfApplyTopology(BB, F);
      if (Ok) {
        Changed = true;
        --MaxBlocks;
      }
    }

    if (Changed) {
      fixStack(&F);
    }
    return Changed;
  }
};

} // namespace

char DecoyPass::ID = 0;

FunctionPass *llvm::createDecoyPass(ObfuscationOptions *argsOptions) {
  return new DecoyPass(argsOptions);
}

StringRef llvm::getDecoyProbeSymbol() { return BCFProbeSymbol.getValue(); }
