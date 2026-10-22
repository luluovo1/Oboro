#ifndef LLVM_TRANSFORMS_OBFUSCATION_SYMBOLRENAME_H
#define LLVM_TRANSFORMS_OBFUSCATION_SYMBOLRENAME_H

namespace llvm {
class ModulePass;
class ObfuscationOptions;

ModulePass *createSymbolRenamePass(ObfuscationOptions *Options);
} // namespace llvm

#endif
