#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscation/IndirectBranch.h"
#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/CryptoUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"

#include <random>

#define DEBUG_TYPE "indbr"

// 全边间接化：除条件分支外，无条件 br 也走加密页表。默认关。
static cl::opt<bool> IndBrFull(
    "irobf-indbr_full", cl::init(false), cl::NotHidden,
    cl::desc("Indirect unconditional branches as well (full CFG edge "
             "indirection). Off by default."),
    cl::ZeroOrMore);

// 间接化之前把基本块拆到最多 N 条指令（0 = 不拆）。默认关。
static cl::opt<unsigned> IndBrSplit(
    "irobf-indbr_split", cl::init(0), cl::NotHidden,
    cl::desc("Split basic blocks to at most N instructions before "
             "indirection (0 = no splitting). Default: 0"),
    cl::ZeroOrMore);


using namespace llvm;
namespace {
struct IndirectBranch : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  // Dual mode replaces each conditional branch with
  // indirectbr(select(cond, blockaddress(T), blockaddress(F))) and does
  // not build a module page table at all.
  bool Dual = false;

  std::unordered_map<Function *, std::vector<Constant *>> FunctionBBs;
  std::unordered_map<Function *, std::vector<BranchInst *>> FunctionBrs;
  // Dedup only; vectors keep module order (deterministic).
  std::unordered_map<Function *, SmallPtrSet<Constant *, 16>> BBSeen;
  std::unordered_map<Function *, SmallPtrSet<BranchInst *, 16>> BrSeen;

  std::vector<Constant *> BBAddrTargets;
  std::unordered_map<Constant *, unsigned> BBIndex;
  std::unordered_map<Constant *, uint64_t> BBKeys;
  std::vector<GlobalVariable *> BBPageTable;

  // 页表索引的运行时 key（BSS，运行时恒为 0）。静态分析看不到值，
  // 因此无法把 索引 -> 表项地址 -> 跳转目标 求出来。
  GlobalVariable *IndexKeyGV = nullptr;

  uint64_t    PtrEncKey = 0;
  bool RunOnFuncChanged = false;
  // AArch64 PAC: signed counterpart of BBPageTable and its per-table
  // discriminator.  Only populated when at least one rewritten function has
  // the +pauth subtarget feature.
  GlobalVariable *SignedObjects = nullptr;
  uint64_t        PtrAuthDisc = 0;
  bool            UsePtrAuth = false;

  IndirectBranch(ObfuscationOptions *argsOptions, bool Dual)
      : FunctionPass(ID), ArgsOptions(argsOptions), Dual(Dual) {}

  StringRef getPassName() const override { return {"IndirectBranch"}; }

  // 把普通块拆成不超过 MaxInsts 条指令的小块。只做 target-independent
  // 的 CFG 拆分；EH / musttail / callbr 函数整体跳过，避免破坏 ABI 与
  // 异常展开。
  static void splitBlocks(Function &F, unsigned MaxInsts) {
    if (F.isDeclaration() || F.hasPersonalityFn())
      return;
    for (const BasicBlock &BB : F) {
      for (const Instruction &I : BB) {
        if (auto *CI = dyn_cast<CallInst>(&I))
          if (CI->isMustTailCall())
            return;
        if (isa<CallBrInst>(I))
          return;
      }
    }

    SmallVector<BasicBlock *, 32> Work;
    for (BasicBlock &BB : F)
      Work.push_back(&BB);

    // 每函数新增块预算，防止大函数被拆成失控数量。
    unsigned Budget = 256;
    for (BasicBlock *BB : Work) {
      BasicBlock *Cur = BB;
      while (Budget > 0 && Cur->size() > MaxInsts) {
        auto It = Cur->begin();
        unsigned N = 0;
        while (It != Cur->end() && N < MaxInsts) {
          ++It;
          ++N;
        }
        // 拆分点不能是 PHI（必须留在块首）或终结符。
        while (It != Cur->end() &&
               (isa<PHINode>(&*It) || It->isTerminator()))
          ++It;
        if (It == Cur->end())
          break;
        Cur = Cur->splitBasicBlock(It, "");
        --Budget;
      }
    }
  }

  void NumberBasicBlock(Module &M) {
    for (auto &F : M) {
      if (F.empty() || F.isWeakForLinker() ||
          F.getSection() == ".text.startup" ||
          F.isIntrinsic()) {
        continue;
      }
      // Only collect edges from functions this pass will actually rewrite.
      // Taking BlockAddress values from skipped functions keeps their blocks
      // alive and can block later optimizations.
      if (!ArgsOptions->toObfuscate(ArgsOptions->indBrOpt(), &F).isEnabled())
        continue;
      if (IndBrSplit > 0)
        splitBlocks(F, IndBrSplit);
      SplitAllCriticalEdges(F, CriticalEdgeSplittingOptions(nullptr, nullptr));
      uint64_t BBKey = cryptoutils->get_uint64_t();
      for (auto &BB : F) {
        if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator())) {
          if (BI->isConditional() || IndBrFull) {
            if (BrSeen[&F].insert(BI).second)
              FunctionBrs[&F].push_back(BI);
            unsigned N = BI->getNumSuccessors();
            for (unsigned I = 0; I < N; I++) {
              BasicBlock *Successor = BI->getSuccessor(I);
              // A numeric label cannot be referenced by a blockaddress that
              // escapes the function body (the page table is a global).  Real
              // code -- JNI entry points in particular -- is full of
              // unnamed blocks, so give the target a name before taking its
              // address, otherwise the module fails to re-parse with
              // "cannot take address of numeric label after the function is
              // defined".
              if (!Successor->hasName())
                Successor->setName("bb");
              auto BBAddr = BlockAddress::get(Successor);
              if (BBSeen[&F].insert(BBAddr).second)
                FunctionBBs[&F].push_back(BBAddr);
              if (BBKeys.count(BBAddr) == 0) {
                BBAddrTargets.push_back(BBAddr);
                BBKeys[BBAddr] = BBKey;
              }
            }
          }
        }
      }
    }
  }

  bool doInitialization(Module &M) override {
    // 未启用则跳过整个模块级收集与页表构建：否则即使没开 INDBR，
    // NumberBasicBlock 的 SplitAllCriticalEdges 也会无谓修改 CFG，
    // 且页表全局会被无条件塞进产物。
    // Dual mode builds no page table at all.
    if (Dual)
      return false;
    if (!ArgsOptions->mayBeEnabled(ArgsOptions->indBrOpt(), M)) {
      return false;
    }

    BBIndex.clear();
    BBPageTable.clear();
    FunctionBBs.clear();
    FunctionBrs.clear();
    BBSeen.clear();
    BrSeen.clear();
    BBAddrTargets.clear();
    BBKeys.clear();
    SignedObjects = nullptr;

    NumberBasicBlock(M);
    if (BBAddrTargets.empty()) {
      return false;
    }

    UsePtrAuth = false;
    if (ArgsOptions->ptrAuthEnabled()) {
      for (auto &KV : FunctionBBs) {
        if (hasPtrAuth(*KV.first)) {
          UsePtrAuth = true;
          break;
        }
      }
    }
    PtrAuthDisc = cryptoutils->get_uint64_t();

    PtrEncKey = cryptoutils->get_uint64_t();

    CreatePageTableArgs createPageTableArgs;
    createPageTableArgs.CountLoop = 1;
    createPageTableArgs.GVNamePrefix =
        obf::freshName(M, M.getName().str() + "_IndirectBr");
    createPageTableArgs.RandomEngine = &*cryptoutils;
    createPageTableArgs.M = &M;
    createPageTableArgs.Objects = &BBAddrTargets;
    createPageTableArgs.IndexMap = &BBIndex;
    createPageTableArgs.ObjectKeys = &BBKeys;
    createPageTableArgs.OutPageTable = &BBPageTable;
    createPageTableArgs.PtrEncKey = PtrEncKey;
    createPageTableArgs.EnablePtrAuth = UsePtrAuth;
    createPageTableArgs.PtrAuthKey = 0; // IA: indirect branch targets
    createPageTableArgs.PtrAuthDisc = PtrAuthDisc;
    createPageTableArgs.OutSignedObjects = &SignedObjects;

    createPageTable(createPageTableArgs);
    auto *KeyTy = getPageTableIntTy(M);
    IndexKeyGV = new GlobalVariable(
        M, KeyTy, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(KeyTy, 0), obf::freshName(M, "idx_key"));
    IndexKeyGV->setAlignment(Align(8));

    return false;
  }

  bool runOnFunction(Function &Fn) override {
    // 弱符号等红黄区函数的跳过已统一收敛到
    // ObfuscationOptions::toObfuscate()（安全底线），此处不再单独判断。

    const auto opt = ArgsOptions->toObfuscate(ArgsOptions->indBrOpt(), &Fn);
    if (!opt.isEnabled()) {
      return false;
    }

    if (Dual) {
      SmallVector<BranchInst *, 16> Cands;
      for (BasicBlock &BB : Fn)
        if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator()))
          if (BI->isConditional())
            Cands.push_back(BI);

      bool Changed = false;
      for (BranchInst *BI : Cands) {
        BasicBlock *TBB = BI->getSuccessor(0);
        BasicBlock *FBB = BI->getSuccessor(1);
        // The blockaddress escapes into a global, so unnamed targets must get
        // a name first (see the same constraint in NumberBasicBlock).
        for (BasicBlock *Succ : {TBB, FBB})
          if (!Succ->hasName())
            Succ->setName("bb");
        IRBuilder<> IRB(BI);
        Value *Sel = IRB.CreateSelect(BI->getCondition(),
                                      BlockAddress::get(TBB),
                                      BlockAddress::get(FBB));
        auto *IBI = IndirectBrInst::Create(Sel, 2, BI->getIterator());
        IBI->addDestination(TBB);
        IBI->addDestination(FBB);
        BI->eraseFromParent();
        Changed = true;
      }
      RunOnFuncChanged |= Changed;
      return Changed;
    }

    LLVMContext &Ctx = Fn.getContext();
    auto& M = *Fn.getParent();

    if (BBAddrTargets.empty()) {
      return false;
    }

    auto& FuncBBsSet = FunctionBBs[&Fn];
    auto& FuncBrs = FunctionBrs[&Fn];
    if (FuncBBsSet.empty() || FuncBrs.empty()) {
      return false;
    }

    std::vector<Constant *> FuncBBs;
    std::unordered_map<Constant *, uint64_t> FuncKeys;
    auto FuncKey = cryptoutils->get_uint64_t();

    for (auto bb : FuncBBsSet) {
      FuncBBs.push_back(bb);
      FuncKeys[bb] = FuncKey;
    }

    std::vector<GlobalVariable *> FuncBBPageTable;
    std::unordered_map<Constant *, unsigned> FuncBBIndex;

    if (opt.level()) {
      CreatePageTableArgs createPageTableArgs;
      createPageTableArgs.CountLoop = opt.level();
      createPageTableArgs.GVNamePrefix = obf::freshName(
          M, M.getName().str() + Fn.getName().str() + "_IndirectBr");
      createPageTableArgs.RandomEngine = &*cryptoutils;
      createPageTableArgs.M = &M;
      createPageTableArgs.Objects = &FuncBBs;
      createPageTableArgs.IndexMap = &BBIndex;
      createPageTableArgs.ObjectKeys = &FuncKeys;
      createPageTableArgs.OutPageTable = &FuncBBPageTable;
      createPageTableArgs.PtrEncKey = PtrEncKey;

      enhancedPageTable(createPageTableArgs, &FuncBBIndex);
    }

    // 页表索引必须与页表整数宽度一致（getPageTableIntTy = 指针宽度）：
    // 这里曾固定 i32，而页表已改为 i64（x86_64/AArch64），
    // 产生 `add i64 %x, i32 %y` 的非法 IR，导致后端 Post-RA 崩溃
    // （Cannot emit physreg copy instruction；clang 默认
    // -disable-llvm-verifier 放过了非法 IR）。
    auto *IntTy = getPageTableIntTy(M);
    for (auto &BI : FuncBrs) {
      if (!BI)
        continue;
      const bool IsCond = BI->isConditional();
      if (!IsCond && !IndBrFull)
        continue;

      IRBuilder<> IRB(BI);
      BasicBlock *TBB = BI->getSuccessor(0);
      BasicBlock *FBB = IsCond ? BI->getSuccessor(1) : nullptr;
      auto AddrTBB = BlockAddress::get(TBB);
      auto AddrFBB = FBB ? BlockAddress::get(FBB) : nullptr;

      auto IndexFor = [&](Constant *Addr) -> ConstantInt * {
        unsigned Idx = opt.level() ? FuncBBIndex[Addr] : BBIndex[Addr];
        return ConstantInt::get(IntTy, Idx);
      };

      Value *NextIndex =
          IsCond ? IRB.CreateSelect(BI->getCondition(), IndexFor(AddrTBB),
                                    IndexFor(AddrFBB))
                 : IndexFor(AddrTBB);

      // 索引 ^= 运行时 key：key 是 volatile load 的 BSS 全局（恒 0），
      // 运行时索引不变，但静态分析无法把 key 当常量，页表地址与
      // 跳转目标因此不可求值。
      if (IndexKeyGV) {
        Value *IdxKey =
            IRB.CreateLoad(IntTy, IndexKeyGV, /*isVolatile=*/true);
        NextIndex = IRB.CreateXor(NextIndex, IdxKey);
      }

      BuildDecryptArgs buildDecrypt;
      buildDecrypt.FuncLoopCount = opt.level();
      buildDecrypt.NextIndex = 0;
      buildDecrypt.NextIndexValue = NextIndex;
      buildDecrypt.Fn = &Fn;
      buildDecrypt.InsertBefore = BI;
      buildDecrypt.LoadTy = PointerType::getUnqual(Ctx);
      buildDecrypt.ModulePageTable = &BBPageTable;
      buildDecrypt.FuncPageTable = &FuncBBPageTable;
      buildDecrypt.ModuleKey = BBKeys[AddrTBB];
      buildDecrypt.FuncKey = FuncKeys[AddrTBB];
      buildDecrypt.PtrEncKey = PtrEncKey;
      buildDecrypt.SignedObjects = SignedObjects;
      buildDecrypt.PtrAuthKey =
          (UsePtrAuth && hasPtrAuth(Fn)) ? 0 : -1;
      buildDecrypt.PtrAuthDisc = PtrAuthDisc;

      auto TargetPtr = buildPageTableDecryptIR(buildDecrypt);
      IndirectBrInst *IBI =
          IndirectBrInst::Create(TargetPtr, IsCond ? 2 : 1);
      ReplaceInstWithInst(BI, IBI);
      IBI->addDestination(TBB);
      if (FBB)
        IBI->addDestination(FBB);

      RunOnFuncChanged = true;
    }

    return true;
  }

  bool doFinalization(Module &M) override {
    if (!RunOnFuncChanged || BBPageTable.empty()) {
      return false;
    }
    for (auto bbPage : BBPageTable) {
      appendToCompilerUsed(M, {bbPage});
    }
    return true;
  }

};
} // namespace llvm

char IndirectBranch::ID = 0;
FunctionPass *llvm::createIndirectBranchPass(ObfuscationOptions *argsOptions,
                                             bool Dual) {
  return new IndirectBranch(argsOptions, Dual);
}
INITIALIZE_PASS(IndirectBranch, "indbr", "Enable IR Indirect Branch Obfuscation", false, false)
