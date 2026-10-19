#ifndef __DECOY_PASS_OBF__
#define __DECOY_PASS_OBF__

#include "llvm/Pass.h"

namespace llvm {

class ObfuscationOptions;

// 运行时误导机制 pass（独立于 BCF）。资格门：只有注解 +bcf_decoy /
// ^bcf_decoy=N 或 config pattern "decoy":N 能启用。
FunctionPass *createDecoyPass(ObfuscationOptions *argsOptions);

// 当前配置的 probe 符号名（-irobf-probe-symbol，默认 __oboro_probe）。
// BCF 需要用它跳过 probe 函数（防 probe -> getenv -> 混淆函数 -> probe 递归）。
StringRef getDecoyProbeSymbol();

} // namespace llvm

#endif // __DECOY_PASS_OBF__
