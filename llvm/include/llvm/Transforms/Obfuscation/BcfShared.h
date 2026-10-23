#ifndef __BCF_SHARED_OBF__
#define __BCF_SHARED_OBF__

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"

namespace llvm {

// ---------------------------------------------------------------------------
// BCF 与 DecoyPass 共享的基础设施：命名卫生、不透明谓词引擎、毒载荷与
// 站点拓扑。二者共用同一套谓词数学与 CFG 形态，保证两个 pass 在同一个
// 函数里产出的站点无法靠"数学式/拓扑/命名"区分。
// ---------------------------------------------------------------------------

// 返回用于 IR 的实体名：调试模式（-irobf-debug-names / OBORO_BCF_DEBUG_NAMES）
// 保留语义名，生产模式返回空串（LLVM 自动编号）。
StringRef bcfName(StringRef Tag);

// 模块级共享全局的名字：由 ObfNaming 的模块盐派生（生产模式随机，
// 跨 pass 稳定；调试模式保留 llvm.bcf.* 可读名）。
std::string bcfAuxGlobalName(Module &M, StringRef Tag);

// "编译期未知"的 64 位运行时值来源。每次调用独立选源：
//   模块级 volatile 全局池（多个，各自随机初值）
//   函数栈锚点（entry 块内 alloca 的地址，经 DataLayout 宽度转换）
// 栈锚点在 naked / 协程 / 带 personality 或 funclet 的函数上不可用，
// 自动回退到全局池。来源集合固定为"两者都用"，不暴露成选项。
Value *bcfGetOpaqueSource(IRBuilder<> &B, Function &F);

// 垃圾写回槽（volatile 读-改-写 sink，DCE 无法删除）。
GlobalVariable *bcfGetBogusSink(Module &M);

// 构造恒真不透明谓词（返回 i1）。Src 必须是编译期未知的 64 位值。
// F 用于族 4/6/7 需要的第二个独立熵源。
Value *bcfBuildOpaqueCond(IRBuilder<> &B, Function &F, Value *Src);

// 向死块填充毒载荷（垃圾读改写 + 架构专属 Anti-Decompiler 载荷）。
void bcfFillBogusBB(BasicBlock *BogBB, Function &F);

// 纯 poison 拓扑分派：菱形 / 三角 / 扇形 switch / 融合，按权重随机。
// 返回是否实际注入。decoy 站点不走这里（由 DecoyPass 自行构造）。
bool bcfApplyTopology(BasicBlock *BB, Function &F);

} // namespace llvm

#endif // __BCF_SHARED_OBF__
