#ifndef OBFUSCATION_MERGE_FUNCTION_H
#define OBFUSCATION_MERGE_FUNCTION_H

namespace llvm {
  class ModulePass;
  class PassRegistry;
  class ObfuscationOptions;

  ModulePass* createMergeFunctionPass(ObfuscationOptions *argsOptions);
  void initializeMergeFunctionPass(PassRegistry &Registry);
}

#endif
