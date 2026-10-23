//===- AuxPasses.cpp - wrapper / block shuffle / block split -------------===//
//
// Three structural passes that make the call graph and the CFG less directly
// readable.  Each one is self-contained and can be enabled alone.
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Obfuscation/AuxPasses.h"
#include "llvm/Transforms/Obfuscation/DecoyPass.h"
#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/CryptoUtils.h"

#include <algorithm>
#include <random>

using namespace llvm;

namespace {

static uint64_t freshSeed() { return cryptoutils->get_uint64_t(); }

static bool unsafeWrapperABI(const Function &F) {
  if (F.isVarArg() || F.isDeclaration() || F.isIntrinsic())
    return true;
  if (F.getName() == "main")
    return true; // entry point must keep its exact body/ABI
  // probe 是 App 提供的策略入口：包装它会在 probe 和混淆代码之间插一层，
  // 破坏 decoy 的"probe -> 混淆函数 -> probe"递归保护。
  if (F.getName() == getDecoyProbeSymbol())
    return true;
  if (F.hasFnAttribute(Attribute::AlwaysInline))
    return true;
  if (F.hasFnAttribute("oboro.wrapper"))
    return true;
  for (const Argument &A : F.args()) {
    if (A.hasAttribute(Attribute::ByVal) ||
        A.hasAttribute(Attribute::StructRet) ||
        A.hasAttribute(Attribute::InAlloca) ||
        A.hasAttribute(Attribute::Preallocated) ||
        A.hasAttribute(Attribute::SwiftSelf) ||
        A.hasAttribute(Attribute::SwiftError) ||
        A.hasAttribute(Attribute::Nest))
      return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Function wrapper: insert an internal forwarding function and retarget direct
// call sites.  Self-recursive calls stay on the original function.
// ---------------------------------------------------------------------------
struct FunctionWrapperPass : public ModulePass {
  static char ID;
  ObfuscationOptions *Options;
  unsigned Probability;

  FunctionWrapperPass(ObfuscationOptions *O, unsigned Probability)
      : ModulePass(ID), Options(O), Probability(Probability) {}

  StringRef getPassName() const override { return "FunctionWrapper"; }

  bool runOnModule(Module &M) override {
    SmallVector<Function *, 16> Work;
    for (Function &F : M) {
      if (unsafeWrapperABI(F))
        continue;
      if (Options->toObfuscate(Options->auxOpt(), &F).isEnabled())
        Work.push_back(&F);
    }

    bool Changed = false;
    for (Function *F : Work) {
      if (Probability < 100 && (cryptoutils->get_uint32_t() % 100) >= Probability)
        continue;

      SmallVector<CallInst *, 16> Sites;
      for (User *U : F->users()) {
        auto *CI = dyn_cast<CallInst>(U);
        if (!CI || CI->getCalledFunction() != F)
          continue;
        if (CI->getParent()->getParent() == F)
          continue; // self recursion
        if (CI->isMustTailCall())
          continue;
        Sites.push_back(CI);
      }

      if (Sites.empty())
        continue; // nothing to retarget; do not emit dead wrappers

      Function *W = Function::Create(F->getFunctionType(),
                                     GlobalValue::InternalLinkage,
                                     obf::freshName(M, "fw"), &M);
      W->copyAttributesFrom(F);
      W->setCallingConv(F->getCallingConv());
      W->setDSOLocal(true);
      W->setVisibility(GlobalValue::DefaultVisibility);
      W->addFnAttr(Attribute::NoInline);
      W->addFnAttr("oboro.wrapper");

      BasicBlock *BB = BasicBlock::Create(M.getContext(), "", W);
      IRBuilder<> B(BB);
      SmallVector<Value *, 8> Args;
      for (Argument &A : W->args())
        Args.push_back(&A);
      CallInst *Call = B.CreateCall(F, Args);
      Call->setCallingConv(F->getCallingConv());
      Call->setAttributes(F->getAttributes());
      if (F->getReturnType()->isVoidTy())
        B.CreateRetVoid();
      else
        B.CreateRet(Call);

      for (CallInst *CI : Sites)
        CI->setCalledFunction(W);
      Changed = true;
    }
    return Changed;
  }
};

// ---------------------------------------------------------------------------
// Shuffle blocks: change the physical order of basic blocks (entry stays
// first).  Layout-based heuristics in disassemblers see a different order.
// ---------------------------------------------------------------------------
struct ShuffleBlocksPass : public FunctionPass {
  static char ID;
  ObfuscationOptions *Options;

  explicit ShuffleBlocksPass(ObfuscationOptions *O)
      : FunctionPass(ID), Options(O) {}

  StringRef getPassName() const override { return "ShuffleBlocks"; }

  bool runOnFunction(Function &F) override {
    if (!Options->toObfuscate(Options->auxOpt(), &F).isEnabled())
      return false;
    if (F.size() < 3)
      return false;

    BasicBlock *Entry = &F.getEntryBlock();
    SmallVector<BasicBlock *, 32> Rest;
    for (BasicBlock &BB : F)
      if (&BB != Entry)
        Rest.push_back(&BB);
    if (Rest.size() < 2)
      return false;

    std::mt19937_64 Rng(freshSeed());
    std::shuffle(Rest.begin(), Rest.end(), Rng);

    for (BasicBlock *BB : Rest)
      BB->removeFromParent();
    Entry->removeFromParent();
    F.insert(F.end(), Entry);
    for (BasicBlock *BB : Rest)
      F.insert(F.end(), BB);
    return true;
  }
};

// ---------------------------------------------------------------------------
// Split blocks: cut a random instruction range into a new block.  Running this
// after the optimizer keeps the splits from being merged back.
// ---------------------------------------------------------------------------
struct SplitBlocksPass : public FunctionPass {
  static char ID;
  ObfuscationOptions *Options;
  unsigned Count;

  SplitBlocksPass(ObfuscationOptions *O, unsigned Count)
      : FunctionPass(ID), Options(O), Count(Count) {}

  StringRef getPassName() const override { return "SplitBlocks"; }

  bool runOnFunction(Function &F) override {
    if (!Options->toObfuscate(Options->auxOpt(), &F).isEnabled())
      return false;
    if (F.size() < 1)
      return false;

    SmallVector<BasicBlock *, 32> Blocks;
    for (BasicBlock &BB : F)
      Blocks.push_back(&BB);
    std::mt19937_64 Rng(freshSeed());
    std::shuffle(Blocks.begin(), Blocks.end(), Rng);

    unsigned Budget = Count;
    bool Changed = false;
    for (BasicBlock *BB : Blocks) {
      if (!Budget)
        break;
      if (BB->isEHPad() || BB->isLandingPad())
        continue;
      SmallVector<Instruction *, 16> Cands;
      for (Instruction &I : *BB) {
        if (isa<PHINode>(I) || I.isTerminator())
          continue;
        if (&I == &BB->front())
          continue;
        Cands.push_back(&I);
      }
      if (Cands.size() < 2)
        continue;
      Instruction *At = Cands.front();
      DominatorTree *DT = nullptr;
      BasicBlock *Cur = BB;
      for (unsigned N = 0; N < Budget; ++N) {
        BasicBlock *New = SplitBlock(Cur, At->getIterator(), DT, nullptr,
                                     nullptr, obf::freshName(*F.getParent(), "sp"));
        // Split the tail again so split_num actually produces N cuts.
        SmallVector<Instruction *, 8> Next;
        for (Instruction &I : *New) {
          if (isa<PHINode>(I) || I.isTerminator())
            continue;
          if (&I == &New->front())
            continue;
          Next.push_back(&I);
        }
        if (Next.size() < 2)
          break;
        At = Next.front();
        Cur = New;
      }
      Budget = 0;
      Changed = true;
    }
    return Changed;
  }
};

} // namespace

char FunctionWrapperPass::ID = 0;
char ShuffleBlocksPass::ID = 0;
char SplitBlocksPass::ID = 0;

ModulePass *llvm::createFunctionWrapperPass(ObfuscationOptions *Options,
                                            unsigned Probability) {
  return new FunctionWrapperPass(Options, Probability);
}

FunctionPass *llvm::createShuffleBlocksPass(ObfuscationOptions *Options) {
  return new ShuffleBlocksPass(Options);
}

FunctionPass *llvm::createSplitBlocksPass(ObfuscationOptions *Options,
                                          unsigned Count) {
  return new SplitBlocksPass(Options, Count);
}
