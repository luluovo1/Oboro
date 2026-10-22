// ObfNaming.cpp
// 模块级随机命名层。所有混淆 pass 的实体名都从这里派生，保证：
//   1. 生产模式零固定特征串（无共享前缀/后缀/计数器）；
//   2. 同一 Module 内跨 pass 稳定（BCF 建的全局 Decoy 能查到）；
//   3. 调试模式完全保留语义名，不影响 lit 断言。
//
// 盐只存在于进程内缓存，不写入任何 IR 元数据——产物里没有任何
// "命名表"可供反查。

#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringMap.h"

// CryptoUtils 最后包含，避免其宏污染上方头文件
#include "llvm/CryptoUtils.h"
#ifdef R
#undef R
#endif
#ifdef S
#undef S
#endif
#ifdef Maj
#undef Maj
#endif
#ifdef Ch
#undef Ch
#endif
#ifdef Sigma0
#undef Sigma0
#endif
#ifdef Sigma1
#undef Sigma1
#endif
#ifdef Gamma0
#undef Gamma0
#endif
#ifdef Gamma1
#undef Gamma1
#endif
#ifdef MIN
#undef MIN
#endif
#ifdef RND
#undef RND
#endif
#ifdef RORc
#undef RORc
#endif

#include <cstdlib>
#include <memory>
#include <mutex>

using namespace llvm;

static cl::opt<bool>
    ObfDebugNames("irobf-debug-names", cl::init(false), cl::Hidden,
                  cl::desc("Keep descriptive bcf.* names in IR. Testing only."),
                  cl::ZeroOrMore);

namespace {

struct ModuleState {
  std::string Identifier;
  StringMap<std::string> Stable;
  StringMap<std::string> Meta;
};

std::mutex StateMu;
DenseMap<const Module *, std::unique_ptr<ModuleState>> States;

// 调用方必须持有 StateMu。
ModuleState &stateFor(Module &M) {
  std::unique_ptr<ModuleState> &Slot = States[&M];
  if (!Slot || Slot->Identifier != M.getModuleIdentifier()) {
    Slot = std::make_unique<ModuleState>();
    Slot->Identifier = M.getModuleIdentifier();
  }
  return *Slot;
}

std::string randomIdent() {
  // 形态上模拟普通源码标识符（字母开头、可变长度），而不是纯 hex：
  // 纯 hex / 固定长度本身就是可脚本化的聚类特征。
  static const char Alpha[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
  static const char Alnum[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
  const unsigned Len = 10 + cryptoutils->get_uint32_t() % 7; // 10..16
  std::string S;
  S.reserve(Len);
  S.push_back(Alpha[cryptoutils->get_uint32_t() % (sizeof(Alpha) - 1)]);
  for (unsigned I = 1; I < Len; ++I)
    S.push_back(Alnum[cryptoutils->get_uint32_t() % (sizeof(Alnum) - 1)]);
  return S;
}

} // namespace

bool obf::debugNames() {
  static const bool Env = ::getenv("OBORO_BCF_DEBUG_NAMES") != nullptr;
  return Env || ObfDebugNames;
}

std::string obf::freshName(Module &M, StringRef Tag) {
  (void)M; // 命名层不持久化模块状态；保留参数以统一 API
  if (debugNames())
    return Tag.str();
  std::lock_guard<std::mutex> L(StateMu);
  return randomIdent();
}

std::string obf::stableName(Module &M, StringRef Tag) {
  // 调试模式原样返回 Tag：调用方（BCF / Decoy）各自维护可读前缀，
  // 这样两族的调试名不会互相串味（bcf.* 与 oboro.*）。
  if (debugNames())
    return Tag.str();

  std::lock_guard<std::mutex> L(StateMu);
  ModuleState &S = stateFor(M);
  auto It = S.Stable.find(Tag);
  if (It != S.Stable.end())
    return It->second;
  std::string Name = randomIdent();
  S.Stable[Tag] = Name;
  return Name;
}

std::string obf::metaName(Module &M, StringRef Tag) {
  if (debugNames())
    return Tag.str();

  std::lock_guard<std::mutex> L(StateMu);
  ModuleState &S = stateFor(M);
  auto It = S.Meta.find(Tag);
  if (It != S.Meta.end())
    return It->second;
  std::string Name = randomIdent();
  S.Meta[Tag] = Name;
  return Name;
}

StringRef obf::sectionName(Module &M) {
  Triple T(M.getTargetTriple());
  // 只有 ELF/COFF 的 ".text" 是可直接寻址的扁平代码节区。Mach-O 使用
  // "segment,section" 命名、Wasm/XCOFF 各有自己的节区模型，硬塞 ".text"
  // 会生成目标不认识的节区。未知 triple（纯 IR 测试）沿用主机构建行为。
  const bool FlatCodeSection = T.getArch() == Triple::UnknownArch ||
                               T.isOSBinFormatELF() || T.isOSBinFormatCOFF();
  if (!FlatCodeSection)
    return StringRef();
  // 生产模式并入主代码段：节区表里没有独立条目可供定位。
  // 调试模式保留独立节区，便于测试观察毒载荷。
  return debugNames() ? StringRef(".text.aux") : StringRef(".text");
}

void obf::markRuntimeFunction(Module &M, Function &F) {
  F.addMetadata(metaName(M, "rt"), *MDNode::get(M.getContext(), {}));
}

bool obf::isRuntimeFunction(Module &M, const Function &F) {
  return F.getMetadata(metaName(M, "rt")) != nullptr;
}
