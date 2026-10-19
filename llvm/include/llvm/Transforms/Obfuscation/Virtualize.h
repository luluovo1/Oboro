//===- Virtualize.h - IR-level code virtualization ------------------------===//
//
// Oboro VMP: translate a function body into a private register-VM bytecode
// stream and replace the body with a wrapper that calls a per-function
// interpreter.  The pass is target independent: the interpreter is emitted as
// IR, so AArch64/ARM/X86 all use the same bytecode format.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_TRANSFORMS_OBFUSCATION_VIRTUALIZE_H
#define LLVM_TRANSFORMS_OBFUSCATION_VIRTUALIZE_H

#include <cstdint>
#include <string>

namespace llvm {
class Function;
class FunctionPass;
class ObfuscationOptions;

struct VirtualizeConfig {
  bool Enabled = false;
  // 1 = baseline, 2 = per-block keys + superinstructions, 3 = maximum
  // diversity (reserved; currently behaves like 2).
  unsigned Level = 1;
  // 0 = derive from time/urandom.
  uint64_t Seed = 0;
};

// Virtualize one function.  On failure the function is left untouched and
// Reason describes the first unsupported construct.  Returns true on success.
bool virtualizeFunction(Function &F, const VirtualizeConfig &Cfg,
                        std::string &Reason);

FunctionPass *createVirtualizePass(ObfuscationOptions *Options);

} // namespace llvm

#endif
