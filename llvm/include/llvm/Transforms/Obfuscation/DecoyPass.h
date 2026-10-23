#ifndef __DECOY_PASS_OBF__
#define __DECOY_PASS_OBF__

#include "llvm/Pass.h"

namespace llvm {

class ObfuscationOptions;

// 运行时误导机制 pass（独立功能域，不依赖 BCF）。资格门：注解 +decoy /
// ^decoy=N 或 config "decoy": {"enable": true} 能启用；旧名 +bcf_decoy 仍接受。
FunctionPass *createDecoyPass(ObfuscationOptions *argsOptions);

// 当前配置的 probe 符号名（config "decoy": {"probe": ...}，默认 __oboro_probe）。
// BCF 需要用它跳过 probe 函数（防 probe -> getenv -> 混淆函数 -> probe 递归）。
StringRef getDecoyProbeSymbol();

// 在主管线开头设置 probe 名：FunctionWrapper 比 DecoyPass 先跑，
// 必须提前知道 probe 才能跳过它。
void setDecoyProbeSymbol(StringRef Name);

} // namespace llvm

#endif // __DECOY_PASS_OBF__
