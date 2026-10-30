//===- VirtualizePass.cpp - ObfOpt/annotation glue for the VMP pass --------===//
//
// The pass itself lives in Virtualize.cpp and is independent of the obfuscation
// configuration machinery so it can also be driven by standalone test tools.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "vmp"

#include "llvm/Transforms/Obfuscation/Virtualize.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include <algorithm>

using namespace llvm;

namespace {

static uint64_t hashSeed(StringRef S) {
  uint64_t H = 0xCBF29CE484222325ULL;
  for (unsigned char C : S) {
    H ^= C;
    H *= 0x100000001B3ULL;
  }
  return H;
}

// Which functions sit on a call cycle, and how many of them this run will
// virtualise.
//
// A virtualised function keeps one interpreter frame per activation, so its
// stack footprint grows with the recursion depth.  The translator sees only
// the function in front of it, which is enough for a direct self-call but not
// for mutual recursion (A -> B -> A): there the cost per level is the sum of
// every member of the cycle, and each member on its own looks harmless.  The
// pass has the whole module, so it computes the strongly connected components
// of the direct call graph once and hands each function the size of its cycle.
//
// The count only includes functions that will actually be virtualised: the
// members that stay native keep their original (small) frames, so charging for
// them would reject cycles that are perfectly safe.
class CallCycles {
public:
  void build(Module &M, ObfuscationOptions *Options) {
    Size.clear();
    DenseMap<Function *, SmallVector<Function *, 4>> Edges;
    SmallVector<Function *, 64> Nodes;

    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      Nodes.push_back(&F);
      auto &Out = Edges[&F];
      for (BasicBlock &BB : F)
        for (Instruction &I : BB) {
          auto *CB = dyn_cast<CallBase>(&I);
          if (!CB)
            continue;
          // A call through a bitcast of a function is still a direct edge.
          auto *Callee =
              dyn_cast<Function>(CB->getCalledOperand()->stripPointerCasts());
          if (!Callee || Callee->isDeclaration())
            continue;
          Out.push_back(Callee);
        }
    }

    // Iterative Tarjan: a module can hold thousands of functions and the
    // compiler's own stack is not the place to recurse over them.
    DenseMap<Function *, unsigned> Index, Low;
    SmallPtrSet<Function *, 32> OnStack;
    SmallVector<Function *, 32> Stack;
    struct Frame {
      Function *F;
      unsigned Next;
    };
    SmallVector<Frame, 32> Work;
    unsigned NextIndex = 0;

    for (Function *Root : Nodes) {
      if (Index.count(Root))
        continue;
      Index[Root] = Low[Root] = NextIndex++;
      Stack.push_back(Root);
      OnStack.insert(Root);
      Work.push_back({Root, 0});

      while (!Work.empty()) {
        Frame &Fr = Work.back();
        auto It = Edges.find(Fr.F);
        unsigned NumEdges = It == Edges.end() ? 0 : (unsigned)It->second.size();
        if (Fr.Next < NumEdges) {
          Function *W = It->second[Fr.Next++];
          auto WI = Index.find(W);
          if (WI == Index.end()) {
            Index[W] = Low[W] = NextIndex++;
            Stack.push_back(W);
            OnStack.insert(W);
            Work.push_back({W, 0});
          } else if (OnStack.count(W)) {
            Low[Fr.F] = std::min(Low[Fr.F], WI->second);
          }
          continue;
        }

        Function *V = Fr.F;
        Work.pop_back();
        if (!Work.empty())
          Low[Work.back().F] = std::min(Low[Work.back().F], Low[V]);
        if (Low[V] != Index[V])
          continue;

        SmallVector<Function *, 8> Scc;
        while (true) {
          Function *W = Stack.back();
          Stack.pop_back();
          OnStack.erase(W);
          Scc.push_back(W);
          if (W == V)
            break;
        }

        bool Cyclic = Scc.size() > 1;
        if (!Cyclic) {
          auto E = Edges.find(Scc[0]);
          if (E != Edges.end())
            for (Function *T : E->second)
              if (T == Scc[0])
                Cyclic = true;
        }
        if (!Cyclic)
          continue;

        unsigned Count = 0;
        for (Function *W : Scc)
          if (Options->toObfuscate(Options->vmpOpt(), W).isEnabled())
            ++Count;
        if (!Count)
          continue;
        for (Function *W : Scc)
          Size[W] = Count;
      }
    }
  }

  // 0 for a function that is not on a cycle.
  unsigned cycleSize(const Function &F) const {
    auto It = Size.find(&F);
    return It == Size.end() ? 0 : It->second;
  }

private:
  DenseMap<const Function *, unsigned> Size;
};

struct VirtualizeLegacy : public FunctionPass {
  static char ID;
  ObfuscationOptions *Options;
  size_t Budget = 0; // functions that existed before this pass started
  size_t Done = 0;
  CallCycles Cycles;

  explicit VirtualizeLegacy(ObfuscationOptions *O)
      : FunctionPass(ID), Options(O) {}

  bool doInitialization(Module &M) override {
    // Every virtualisation replaces one function and adds runtime helpers.
    // Counting against the original population makes a runaway impossible
    // even if some future pass forgets to tag what it emits.
    Budget = M.size();
    Done = 0;
    Cycles.build(M, Options);
    return false;
  }

  bool runOnFunction(Function &F) override {
    if (F.hasFnAttribute("oboro.vmp.generated"))
      return false;
    if (Done >= Budget)
      return false;
    // TEMP bisect hook: OBORO_VMP_SKIP=<substring> leaves matching functions
    // untouched so a failure can be attributed to one function.
    if (const char *Skip = ::getenv("OBORO_VMP_SKIP"))
      if (F.getName().contains(Skip))
        return false;

    ObfOpt Opt = Options->toObfuscate(Options->vmpOpt(), &F);
    if (!Opt.isEnabled())
      return false;

    VirtualizeConfig Cfg;
    Cfg.Enabled = true;
    Cfg.Level = Opt.level() ? Opt.level() : 1;
    StringRef Seed = Options->randomSeed();
    Cfg.Seed = Seed.empty() ? 0 : hashSeed(Seed);
    Cfg.RecursionCycle = Cycles.cycleSize(F);

    std::string Reason;
    bool Changed = false;
    if (!virtualizeFunction(F, Cfg, Reason, &Changed)) {
      LLVM_DEBUG(dbgs() << "vmp: skipped " << F.getName() << ": " << Reason
                        << "\n");
      // The vector-memory retry can rewrite a function it then fails to
      // translate; that rewrite still has to be reported as a change.
      return Changed;
    }
    ++Done;
    return true;
  }
};

} // namespace

char VirtualizeLegacy::ID = 0;

FunctionPass *llvm::createVirtualizePass(ObfuscationOptions *Options) {
  return new VirtualizeLegacy(Options);
}
