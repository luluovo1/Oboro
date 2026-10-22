#ifndef LLVM_TRANSFORMS_OBFUSCATION_AUXPASSES_H
#define LLVM_TRANSFORMS_OBFUSCATION_AUXPASSES_H

namespace llvm {
class ModulePass;
class FunctionPass;
class ObfuscationOptions;

ModulePass *createFunctionWrapperPass(ObfuscationOptions *Options,
                                      unsigned Probability);
FunctionPass *createShuffleBlocksPass(ObfuscationOptions *Options);
FunctionPass *createSplitBlocksPass(ObfuscationOptions *Options,
                                    unsigned Count);
} // namespace llvm

#endif
