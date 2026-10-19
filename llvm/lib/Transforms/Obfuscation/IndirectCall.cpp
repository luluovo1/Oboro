#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Obfuscation/IndirectCall.h"
#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/CryptoUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/APInt.h"

#include <random>

#define DEBUG_TYPE "icall"

using namespace llvm;
namespace {
struct IndirectCall : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;

  std::unordered_map<Function *, std::vector<CallInst *>> FunctionCallSites;
  std::unordered_map<Function *, std::vector<Function *>> FunctionCallees;
  // Dedup only; vectors keep module order (deterministic).
  std::unordered_map<Function *, SmallPtrSet<CallInst *, 16>> CallSiteSeen;
  std::unordered_map<Function *, SmallPtrSet<Function *, 16>> CalleeSeen;
  // Eligibility is decided once per function (same query the per-function pass
  // uses).  Caching keeps NumberCallees from re-running the config/annotation
  // resolution, which may diagnose, and keeps collection consistent with what
  // runOnFunction will actually rewrite.
  std::unordered_map<const Function *, ObfOpt> FuncOpts;

  std::vector<Constant *> Callees;
  std::unordered_map<Constant *, unsigned> CalleeIndex;
  // 63 - 32====31 - 0
  //  Mask=======Key
  std::unordered_map<Constant *, uint64_t> CalleeKeys;
  std::vector<GlobalVariable *> CalleePageTable;

  uint64_t    PtrEncKey = 0;
  bool RunOnFuncChanged = false;

  IndirectCall(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->ArgsOptions = argsOptions;
  }

  StringRef getPassName() const override { return {"IndirectCall"}; }

  void NumberCallees(Module &M) {
    for (auto &F : M) {
      if (F.isIntrinsic()) {
        continue;
      }
      // Only collect from functions this pass will actually rewrite.  A
      // skipped function keeps its direct calls, so putting its callees in
      // the page table would merely take their address: internal callees
      // then stay alive and cannot be inlined, which can drag special ABI
      // call forms (preallocated/inalloca) into CodeGen that the base build
      // eliminates.  Only the calls we turn indirect need an entry.
      auto OptIt = FuncOpts.find(&F);
      if (OptIt == FuncOpts.end() || !OptIt->second.isEnabled())
        continue;

      for (auto &BB : F) {
        for (auto &I : BB) {
          if (auto CI = dyn_cast<CallInst>(&I)) {
            auto CB = dyn_cast<CallBase>(&I);
            auto Callee = CB->getCalledFunction();
            if (Callee == nullptr) {
              Callee = dyn_cast<Function>(CB->getCalledOperand()->stripPointerCasts());
              if (!Callee) {
                continue;
              }
            }
            if (Callee->isIntrinsic()) {
              continue;
            }

            // COMDAT key functions must keep their direct reference: taking an
            // indirect reference to a comdat member drops the association and
            // the backend then reports "Associative COMDAT symbol ... does not
            // exist".  Keep such calls direct.
            if (Callee->hasComdat()) {
              continue;
            }

            if (CallSiteSeen[&F].insert(CI).second)
              FunctionCallSites[&F].push_back(CI);
            if (CalleeSeen[&F].insert(Callee).second)
              FunctionCallees[&F].push_back(Callee);

            if (CalleeKeys.count(Callee) == 0) {
              Callees.push_back(Callee);
              CalleeKeys[Callee] = cryptoutils->get_uint64_t();
            }
          }
        }
      }
    }
  }

  bool doInitialization(Module &M) override {
    // 未启用则跳过收集与页表构建（同 IndirectBranch，防止未开混淆的
    // 构建被塞入死页表全局）。
    if (!ArgsOptions->mayBeEnabled(ArgsOptions->iCallOpt(), M)) {
      FuncOpts.clear();
      return false;
    }

    CalleeIndex.clear();
    FunctionCallSites.clear();
    FunctionCallees.clear();
    CallSiteSeen.clear();
    CalleeSeen.clear();
    Callees.clear();
    CalleePageTable.clear();
    CalleeKeys.clear();

    FuncOpts.clear();
    for (Function &F : M)
      if (!F.isIntrinsic())
        FuncOpts.emplace(
            &F, ArgsOptions->toObfuscate(ArgsOptions->iCallOpt(), &F));

    NumberCallees(M);
    if (!Callees.size()) {
      return false;
    }

    PtrEncKey = cryptoutils->get_uint64_t();

    CreatePageTableArgs createPageTableArgs;
    createPageTableArgs.CountLoop = 1;
    createPageTableArgs.GVNamePrefix =
        obf::freshName(M, M.getName().str() + "_IndirectCallee");
    createPageTableArgs.RandomEngine = &*cryptoutils;
    createPageTableArgs.M = &M;
    createPageTableArgs.Objects = &Callees;
    createPageTableArgs.IndexMap = &CalleeIndex;
    createPageTableArgs.ObjectKeys = &CalleeKeys;
    createPageTableArgs.OutPageTable = &CalleePageTable;
    createPageTableArgs.PtrEncKey = PtrEncKey;

    createPageTable(createPageTableArgs);
    return false;
  }

  bool runOnFunction(Function &Fn) override {
    auto OptIt = FuncOpts.find(&Fn);
    const auto opt =
        OptIt != FuncOpts.end()
            ? OptIt->second
            : ArgsOptions->toObfuscate(ArgsOptions->iCallOpt(), &Fn);
    if (!opt.isEnabled()) {
      return false;
    }

    auto& M = *Fn.getParent();

    if (Callees.empty()) {
      return false;
    }
    const auto& CallSites = FunctionCallSites[&Fn];
    auto& FuncCalleesSet = FunctionCallees[&Fn];

    if (CallSites.empty() || FuncCalleesSet.empty()) {
      return false;
    }

    std::vector<Constant *> FuncCallees;
    std::unordered_map<Constant *, uint64_t> FuncKeys;
    for (auto callee : FuncCalleesSet) {
      FuncCallees.push_back(callee);
      FuncKeys[callee] = cryptoutils->get_uint64_t();
    }

    std::vector<GlobalVariable *> FuncCalleePageTable;
    std::unordered_map<Constant *, unsigned> FuncCalleeIndex;

    if (opt.level()) {
      CreatePageTableArgs createPageTableArgs;
      createPageTableArgs.CountLoop = opt.level();
      createPageTableArgs.GVNamePrefix = obf::freshName(
          M, M.getName().str() + Fn.getName().str() + "_IndirectCallee");
      createPageTableArgs.RandomEngine = &*cryptoutils;
      createPageTableArgs.M = &M;
      createPageTableArgs.Objects = &FuncCallees;
      createPageTableArgs.IndexMap = &CalleeIndex;
      createPageTableArgs.ObjectKeys = &FuncKeys;
      createPageTableArgs.OutPageTable = &FuncCalleePageTable;
      createPageTableArgs.PtrEncKey = PtrEncKey;

      enhancedPageTable(createPageTableArgs, &FuncCalleeIndex);
    }

    // 统计被调函数出现次数：重复调用的函数在入口统一解密一次
    std::unordered_map<Function *, unsigned> CalleeUseCount;
    SmallVector<Function *, 16> CalleeOrder;
    for (auto CI : CallSites) {
      CallBase *CB = CI;
      Function *Callee = CB->getCalledFunction();
      if (!Callee)
        Callee = dyn_cast<Function>(CB->getCalledOperand()->stripPointerCasts());
      if (Callee) {
        unsigned &Cnt = CalleeUseCount[Callee];
        if (Cnt++ == 0)
          CalleeOrder.push_back(Callee);
      }
    }

    // 重复被调函数在函数入口解密一次并缓存
    std::unordered_map<Function *, AllocaInst *> CalleeDedupCache;
    auto &EntryBB = Fn.getEntryBlock();
    Instruction *AllocaInsertPt = &*EntryBB.begin();
    auto *PtrTy = PointerType::getUnqual(Fn.getContext());
    for (auto *Callee : CalleeOrder) {
      if (CalleeUseCount[Callee] <= 1)
        continue;
      IRBuilder<> AIB(AllocaInsertPt);
      CalleeDedupCache[Callee] = AIB.CreateAlloca(PtrTy, nullptr);
    }

    if (!CalleeDedupCache.empty()) {
      Instruction *DecryptPt = nullptr;
      for (auto &I : EntryBB) {
        if (!isa<AllocaInst>(&I)) {
          DecryptPt = &I;
          break;
        }
      }
      if (!DecryptPt)
        DecryptPt = EntryBB.getTerminator();
      for (auto *Callee : CalleeOrder) {
        auto DedupIt = CalleeDedupCache.find(Callee);
        if (DedupIt == CalleeDedupCache.end())
          continue;
        BuildDecryptArgs buildDecrypt;
        buildDecrypt.FuncLoopCount = opt.level();
        buildDecrypt.NextIndex = opt.level() ?
                                   FuncCalleeIndex[Callee] :
                                   CalleeIndex[Callee];
        buildDecrypt.NextIndexValue = nullptr;
        buildDecrypt.Fn = &Fn;
        buildDecrypt.InsertBefore = DecryptPt;
        buildDecrypt.LoadTy = Callee->getType();
        buildDecrypt.ModulePageTable = &CalleePageTable;
        buildDecrypt.FuncPageTable = &FuncCalleePageTable;
        buildDecrypt.ModuleKey = CalleeKeys[Callee];
        buildDecrypt.FuncKey = FuncKeys[Callee];
        buildDecrypt.PtrEncKey = PtrEncKey;

        auto DecPtr = buildPageTableDecryptIR(buildDecrypt);
        IRBuilder<> SIB(DecryptPt);
        SIB.CreateAlignedStore(DecPtr, DedupIt->second, Align{1}, true);
      }
    }

    for (auto CI : CallSites) {

      CallBase *CB = CI;

      Function *Callee = CB->getCalledFunction();
      if (Callee == nullptr) {
        Callee = dyn_cast<Function>(CB->getCalledOperand()->stripPointerCasts());
        if (!Callee) {
          continue;
        }
      }

      auto CacheIt = CalleeDedupCache.find(Callee);
      if (CacheIt != CalleeDedupCache.end()) {
        IRBuilder<> IRB(CB);
        auto FnPtr = IRB.CreateAlignedLoad(
            Callee->getType(), CacheIt->second, Align{1}, true);
        FnPtr->setName("Call_" + Callee->getName());
        CB->setCalledOperand(FnPtr);
      } else {
        BuildDecryptArgs buildDecrypt;
        buildDecrypt.FuncLoopCount = opt.level();
        buildDecrypt.NextIndex = opt.level() ?
                                   FuncCalleeIndex[Callee] :
                                   CalleeIndex[Callee];
        buildDecrypt.NextIndexValue = nullptr;
        buildDecrypt.Fn = &Fn;
        buildDecrypt.InsertBefore = CB;
        buildDecrypt.LoadTy = Callee->getType();
        buildDecrypt.ModulePageTable = &CalleePageTable;
        buildDecrypt.FuncPageTable = &FuncCalleePageTable;
        buildDecrypt.ModuleKey = CalleeKeys[Callee];
        buildDecrypt.FuncKey = FuncKeys[Callee];
        buildDecrypt.PtrEncKey = PtrEncKey;

        auto FnPtr = buildPageTableDecryptIR(buildDecrypt);
        FnPtr->setName("Call_" + Callee->getName());
        CB->setCalledOperand(FnPtr);
      }
    }

    RunOnFuncChanged = true;
    return true;
  }

  bool doFinalization(Module & M) override {
    if (!RunOnFuncChanged || CalleePageTable.empty()) {
      return false;
    }
    for (auto calleePage : CalleePageTable) {
      appendToCompilerUsed(M, {calleePage});
    }
    return true;
  }

};
} // namespace llvm

char IndirectCall::ID = 0;
FunctionPass *llvm::createIndirectCallPass(ObfuscationOptions *argsOptions) {
  return new IndirectCall(argsOptions);
}

INITIALIZE_PASS(IndirectCall, "icall", "Enable IR Indirect Call Obfuscation", false, false)
