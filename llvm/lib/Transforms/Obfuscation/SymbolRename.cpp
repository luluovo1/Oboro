//===- SymbolRename.cpp - rename internal symbols -------------------------===//
//
// Internal functions/globals keep their source names in .symtab, which gives a
// reverse engineer a free map of the program.  This pass assigns opaque names
// to local symbols.  Exported symbols are deliberately left alone: renaming
// them would change the ABI and break other translation units.
//
// Debug info is out of scope: whether a build carries .debug_* is a build
// configuration decision (`-g0`, `strip --strip-debug`), not an obfuscation
// one.  Deleting it here would silently break users who asked for `-g`.
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalIFunc.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/SymbolRename.h"

using namespace llvm;

namespace {

static bool isReservedName(StringRef N) {
  return N == "main" || N.starts_with("llvm.") ||
         N.starts_with("__oboro") || N.starts_with("__cxx") ||
         N.starts_with("__gxx") || N.starts_with("_GLOBAL__") ||
         N.starts_with("__clang") || N.starts_with("__asan") ||
         N.starts_with("__ubsan") || N.starts_with("__sanitizer") ||
         N.starts_with("__emutls");
}

static bool canRename(const GlobalValue &GV) {
  if (GV.isDeclaration())
    return false;
  if (auto *F = dyn_cast<Function>(&GV))
    if (F->isIntrinsic())
      return false;
  if (!GV.hasLocalLinkage())
    return false; // exported ABI
  if (GV.hasComdat())
    return false; // comdat key/section match depends on the symbol
  if (isa<GlobalIFunc>(GV))
    return false; // resolver lookup is by name
  if (isReservedName(GV.getName()))
    return false;
  return true;
}

static std::string pickName(Module &M) {
  for (unsigned I = 0; I < 64; ++I) {
    std::string N = obf::freshName(M, "sym");
    if (!M.getNamedValue(N))
      return N;
  }
  return std::string();
}

struct SymbolRename : public ModulePass {
  static char ID;
  ObfuscationOptions *Options;

  explicit SymbolRename(ObfuscationOptions *O)
      : ModulePass(ID), Options(O) {}

  StringRef getPassName() const override { return "SymbolRename"; }

  bool runOnModule(Module &M) override {
    if (!Options->renameOpt()->isEnabled())
      return false;

    bool Changed = false;

    // Functions first: aliases may point at them.
    for (Function &F : M) {
      if (!canRename(F))
        continue;
      if (!Options->toObfuscate(Options->renameOpt(), &F).isEnabled())
        continue;
      std::string N = pickName(M);
      if (N.empty())
        break;
      F.setName(N);
      Changed = true;
    }

    for (GlobalVariable &GV : M.globals()) {
      if (!canRename(GV))
        continue;
      std::string N = pickName(M);
      if (N.empty())
        break;
      GV.setName(N);
      Changed = true;
    }

    for (GlobalAlias &GA : M.aliases()) {
      if (!canRename(GA))
        continue;
      std::string N = pickName(M);
      if (N.empty())
        break;
      GA.setName(N);
      Changed = true;
    }

    return Changed;
  }
};

} // namespace

char SymbolRename::ID = 0;

ModulePass *llvm::createSymbolRenamePass(ObfuscationOptions *Options) {
  return new SymbolRename(Options);
}
