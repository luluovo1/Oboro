//===- VirtualizePass.cpp - ObfOpt/annotation glue for the VMP pass --------===//
//
// The pass itself lives in Virtualize.cpp and is independent of the obfuscation
// configuration machinery so it can also be driven by standalone test tools.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "vmp"

#include "llvm/Transforms/Obfuscation/Virtualize.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"

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

struct VirtualizeLegacy : public FunctionPass {
  static char ID;
  ObfuscationOptions *Options;
  size_t Budget = 0; // functions that existed before this pass started
  size_t Done = 0;

  explicit VirtualizeLegacy(ObfuscationOptions *O)
      : FunctionPass(ID), Options(O) {}

  bool doInitialization(Module &M) override {
    // Every virtualisation replaces one function and adds runtime helpers.
    // Counting against the original population makes a runaway impossible
    // even if some future pass forgets to tag what it emits.
    Budget = M.size();
    Done = 0;
    return false;
  }

  bool runOnFunction(Function &F) override {
    if (F.hasFnAttribute("oboro.vmp.generated"))
      return false;
    if (Done >= Budget)
      return false;

    ObfOpt Opt = Options->toObfuscate(Options->vmpOpt(), &F);
    if (!Opt.isEnabled())
      return false;

    VirtualizeConfig Cfg;
    Cfg.Enabled = true;
    Cfg.Level = Opt.level() ? Opt.level() : 1;
    StringRef Seed = Options->randomSeed();
    Cfg.Seed = Seed.empty() ? 0 : hashSeed(Seed);

    std::string Reason;
    if (!virtualizeFunction(F, Cfg, Reason)) {
      LLVM_DEBUG(dbgs() << "vmp: skipped " << F.getName() << ": " << Reason
                        << "\n");
      return false;
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
