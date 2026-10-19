#ifndef __OBF_NAMING_H__
#define __OBF_NAMING_H__

#include "llvm/ADT/StringRef.h"

#include <string>

namespace llvm {

class Function;
class Module;

// ---------------------------------------------------------------------------
// 模块级命名层：所有混淆 pass 产生的全局变量、函数、元数据与节区名都从
// 这里派生。生产模式下每个 Module 一套独立随机盐，实体名之间没有可聚类的
// 共享结构（同一前缀/后缀/计数器都会让脚本一次性定位整族产物）。
//
// 调试模式（-irobf-debug-names 或 OBORO_BCF_DEBUG_NAMES）保留语义名，
// lit 测试依赖这一行为。
// ---------------------------------------------------------------------------
namespace obf {

bool debugNames();

// 派生一个一次性实体名（每次调用都不同）。调试模式返回 Tag。
std::string freshName(Module &M, StringRef Tag);

// 派生一个模块内稳定名（同 Module 同 Tag 返回同名）。调试模式原样
// 返回 Tag，由调用方补可读前缀（BCF: llvm.bcf.* / Decoy: oboro.*）。
std::string stableName(Module &M, StringRef Tag);

// 内部元数据名（noobf / 运行时标记等）。调试模式原样返回 Tag。
std::string metaName(Module &M, StringRef Tag);

// 毒载荷所在节区。调试模式 ".text.aux"；生产模式直接并入 ".text"，
// 不在节区表里留下可扫描的独立条目。
StringRef sectionName(Module &M);

// 判断函数是否为工具链自己生成的运行时函数（防递归/自污染）。
bool isRuntimeFunction(Module &M, const Function &F);

// 给工具链生成的运行时函数打标记。
void markRuntimeFunction(Module &M, Function &F);

} // namespace obf
} // namespace llvm

#endif // __OBF_NAMING_H__
