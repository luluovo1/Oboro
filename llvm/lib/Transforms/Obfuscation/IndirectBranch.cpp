#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscation/IndirectBranch.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/CryptoUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/IR/Module.h"

#include <random>

#define DEBUG_TYPE "indbr"

using namespace llvm;
namespace {
struct IndirectBranch : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;

  std::unordered_map<Function *, std::set<Constant *>> FunctionBBs;
  std::unordered_map<Function *, std::set<BranchInst *>> FunctionBrs;

  std::vector<Constant *> BBAddrTargets;
  std::unordered_map<Constant *, unsigned> BBIndex;
  std::unordered_map<Constant *, uint64_t> BBKeys;
  std::vector<GlobalVariable *> BBPageTable;

  CryptoUtils RandomEngine;
  uint64_t    PtrEncKey = 0;
  bool RunOnFuncChanged = false;

  IndirectBranch(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->ArgsOptions = argsOptions;
  }

  StringRef getPassName() const override { return {"IndirectBranch"}; }

  void NumberBasicBlock(Module &M) {
    for (auto &F : M) {
      if (F.empty() || F.isWeakForLinker() ||
          F.getSection() == ".text.startup" ||
          F.isIntrinsic()) {
        continue;
      }
      SplitAllCriticalEdges(F, CriticalEdgeSplittingOptions(nullptr, nullptr));
      uint64_t BBKey = RandomEngine.get_uint64_t();
      for (auto &BB : F) {
        if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator())) {
          if (BI->isConditional()) {
            FunctionBrs[&F].emplace(BI);
            unsigned N = BI->getNumSuccessors();
            for (unsigned I = 0; I < N; I++) {
              BasicBlock *Successor = BI->getSuccessor(I);
              auto BBAddr = BlockAddress::get(Successor);
              FunctionBBs[&F].emplace(BBAddr);
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
    if (!ArgsOptions->mayBeEnabled(ArgsOptions->indBrOpt(), M)) {
      return false;
    }

    BBIndex.clear();
    BBPageTable.clear();
    FunctionBBs.clear();
    FunctionBrs.clear();
    BBAddrTargets.clear();
    BBKeys.clear();

    NumberBasicBlock(M);
    if (BBAddrTargets.empty()) {
      return false;
    }

    PtrEncKey = RandomEngine.get_uint64_t();

    CreatePageTableArgs createPageTableArgs;
    createPageTableArgs.CountLoop = 1;
    createPageTableArgs.GVNamePrefix = M.getName().str() + "_IndirectBr" ;
    createPageTableArgs.RandomEngine = &RandomEngine;
    createPageTableArgs.M = &M;
    createPageTableArgs.Objects = &BBAddrTargets;
    createPageTableArgs.IndexMap = &BBIndex;
    createPageTableArgs.ObjectKeys = &BBKeys;
    createPageTableArgs.OutPageTable = &BBPageTable;
    createPageTableArgs.PtrEncKey = PtrEncKey;

    createPageTable(createPageTableArgs);
    return false;
  }


  bool runOnFunction(Function &Fn) override {
    // 弱符号等红黄区函数的跳过已统一收敛到
    // ObfuscationOptions::toObfuscate()（安全底线），此处不再单独判断。

    const auto opt = ArgsOptions->toObfuscate(ArgsOptions->indBrOpt(), &Fn);
    if (!opt.isEnabled()) {
      return false;
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
    auto FuncKey = RandomEngine.get_uint64_t();

    for (auto bb : FuncBBsSet) {
      FuncBBs.push_back(bb);
      FuncKeys[bb] = FuncKey;
    }

    std::vector<GlobalVariable *> FuncBBPageTable;
    std::unordered_map<Constant *, unsigned> FuncBBIndex;

    if (opt.level()) {
      CreatePageTableArgs createPageTableArgs;
      createPageTableArgs.CountLoop = opt.level();
      createPageTableArgs.GVNamePrefix = M.getName().str() + Fn.getName().str() + "_IndirectBr" ;
      createPageTableArgs.RandomEngine = &RandomEngine;
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
      if (BI && BI->isConditional()) {
        IRBuilder<> IRB(BI);

        auto Cond = BI->getCondition();

        auto TBB = BI->getSuccessor(0);
        auto FBB = BI->getSuccessor(1);
        auto AddrTBB = BlockAddress::get(TBB);
        auto AddrFBB = BlockAddress::get(FBB);

        auto TIndex = opt.level() ?
                        ConstantInt::get(IntTy, FuncBBIndex[AddrTBB]) :
                        ConstantInt::get(IntTy, BBIndex[AddrTBB]);

        auto FIndex = opt.level() ?
                        ConstantInt::get(IntTy, FuncBBIndex[AddrFBB]) :
                        ConstantInt::get(IntTy, BBIndex[AddrFBB]);

        auto NextIndex = IRB.CreateSelect(Cond, TIndex, FIndex);

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

        auto TargetPtr = buildPageTableDecryptIR(buildDecrypt);
        IndirectBrInst *IBI = IndirectBrInst::Create(TargetPtr, 2);
        ReplaceInstWithInst(BI, IBI);
        IBI->addDestination(TBB);
        IBI->addDestination(FBB);

        RunOnFuncChanged = true;
      }
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
FunctionPass *llvm::createIndirectBranchPass(ObfuscationOptions *argsOptions) {
  return new IndirectBranch(argsOptions);
}
INITIALIZE_PASS(IndirectBranch, "indbr", "Enable IR Indirect Branch Obfuscation", false, false)
