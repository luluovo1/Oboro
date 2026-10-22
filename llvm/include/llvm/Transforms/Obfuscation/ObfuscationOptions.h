#ifndef OBFUSCATION_OBFUSCATIONOPTIONS_H
#define OBFUSCATION_OBFUSCATIONOPTIONS_H

#include "llvm/Support/YAMLParser.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringMap.h"
#include <optional>
#include <vector>


namespace llvm {

SmallVector<std::string> readAnnotate(Function *f);

// 读取函数上的 decoy 注解（+bcf_decoy / -bcf_decoy / ^bcf_decoy=N）。
// 返回 std::nullopt 表示没有 decoy 注解（该函数不进入 decoy 资格门）。
// 多条 decoy 注解时后写覆盖先写。
std::optional<uint32_t> readDecoyAnnotation(Function *f);
// 读取 L3 值污染注解（+bcf_decoy_pollute / -bcf_decoy_pollute）。
// 只有 decoy>0 的函数才可能真正生效；pollute 本身不构成 decoy 资格。
std::optional<bool> readDecoyPolluteAnnotation(Function *f);

// config "patterns" 段的单条规则（分级策略的中间层）：
//   "match"  —— demangled 函数名 pattern（'*' 不跨 "::"，'**' 跨 "::"；
//                空 = 不做函数名约束）
//   "file"   —— 源文件 basename pattern（空 = 不做文件约束）
//   两个字段可同时出现（AND 语义：都匹配才生效）。
//   其余 key 为 pass 名（bcf/fla/...），值是 {"enable": bool, "level": int}
//   的字段级覆盖——规则只覆盖它显式设置的字段，其余向上层继承。
// 优先级：函数注解 > 含 match 的规则（类/命名空间层）> 纯 file 规则（文件层）
//         > CLI > config 全局 > 内置默认；同层按声明顺序，后写覆盖先写。
struct ConfigPatternRule {
  std::string NamePattern;
  std::string FilePattern;
  struct OptOverride {
    std::optional<bool>     Enable;
    std::optional<uint32_t> Level;
    // decoy 比例（0-100）。只有显式写 "decoy" 的函数才进入 decoy 资格门；
    // 该字段与 Level 一样按字段级级联（未写的层不覆盖上层）。
    std::optional<uint32_t> Decoy;
    // L3 值污染开关（仅对 decoy>0 的函数有效）。缺省 false = 只做 L1。
    std::optional<bool>     DecoyPollute;
    // BCF 每函数毒点上限（0 = 不设绝对上限）。仅 BCF 读取。
    std::optional<uint32_t> Budget;
    // BCF 毒点占可插桩块数的百分比（0-100，0 = 禁用百分比）。
    std::optional<uint32_t> BudgetPct;
  };
  llvm::StringMap<OptOverride> Overrides;
};

class ObfOpt {
protected:
  uint32_t    Enabled : 1;
  uint32_t    Level   : 2;
  // decoy 比例（0-100）：仅 BCF 使用；0 表示该函数不进入 decoy 资格门。
  // 资格只能由函数注解或 config pattern 显式设置，CLI 不能全局打开。
  uint32_t    Decoy   : 7;
  // L3 值污染：仅 decoy>0 时生效；默认关（只做 L1 重汇聚）。
  uint32_t    DecoyPollute : 1;
  // CSE 专用：true = 全模块共用 i8/i16 各一个解密器（体积优先）。
  // 只能由 config 的 "cse": {"shared": true} 打开；没有对应命令行参数，
  // 该取舍属于项目级策略，不应该被散落的编译指令左右。
  uint32_t    SharedDecrypt : 1;
  // BCF 每函数毒点上限（绝对数）：0 = 不设绝对上限。仅在 BudgetPct == 0
  // 时单独生效。其他 pass 不读取该字段。
  uint32_t    Budget = 0;
  // BCF 毒点占可插桩块数的百分比（0-100）：0 = 不用百分比，退回 Budget
  // 绝对上限；若 Budget 也为 0，按默认 20% 处理（0 只表示自动，不放大）。
  // 默认 20% 随函数规模线性增长，避免大函数只保护前几个块。
  uint32_t    BudgetPct = 20;
  std::string AttributeName;

public:
  ObfOpt(bool enable, uint32_t level, const std::string &attributeName) {
    this->Enabled = enable;
    this->Level = std::min<uint32_t>(level, 3);
    this->Decoy = 0;
    this->DecoyPollute = 0;
    this->SharedDecrypt = 0;
    this->AttributeName = attributeName;
  }

  ObfOpt(const std::string &attributeName) {
    this->Enabled = false;
    this->Level = 0;
    this->Decoy = 0;
    this->DecoyPollute = 0;
    this->SharedDecrypt = 0;
    this->AttributeName = attributeName;
  }

  void readOpt(const cl::opt<bool> &enableOpt) {
    if (enableOpt.getNumOccurrences()) {
      Enabled = enableOpt.getValue();
    }
  }

  void readOpt(const cl::opt<bool> &    enableOpt,
               const cl::opt<uint32_t> &levelOpt) {
    readOpt(enableOpt);
    if (levelOpt.getNumOccurrences()) {
      Level = levelOpt.getValue();
    }
  }

  // BCF 专用：每函数毒点上限（绝对数）；0 = 不设绝对上限。
  void readBudgetOpt(const cl::opt<uint32_t> &budgetOpt) {
    if (budgetOpt.getNumOccurrences())
      setBudget(budgetOpt.getValue());
  }

  // BCF 专用：毒点占可插桩块数的百分比；0 = 禁用百分比。
  void readBudgetPctOpt(const cl::opt<uint32_t> &budgetPctOpt) {
    if (budgetPctOpt.getNumOccurrences())
      setBudgetPct(budgetPctOpt.getValue());
  }

  void setEnable(bool enabled) {
    this->Enabled = enabled;
  }

  void setLevel(uint32_t level) {
    this->Level = std::min<uint32_t>(level, 3);
  }

  void setDecoy(uint32_t decoy) {
    this->Decoy = std::min<uint32_t>(decoy, 100);
  }

  void setDecoyPollute(bool pollute) {
    this->DecoyPollute = pollute ? 1 : 0;
  }

  void setBudget(uint32_t budget) {
    this->Budget = std::min<uint32_t>(budget, 4096);
  }

  void setBudgetPct(uint32_t pct) {
    this->BudgetPct = std::min<uint32_t>(pct, 100);
  }

  bool isEnabled() const {
    return this->Enabled;
  }

  uint32_t level() const {
    return this->Level;
  }

  uint32_t decoy() const {
    return this->Decoy;
  }

  bool decoyPollute() const {
    return this->DecoyPollute != 0;
  }

  // CSE 专用：全局共享解密器。只有 config 能设置（见字段注释）。
  void setSharedDecrypt(bool Shared) {
    this->SharedDecrypt = Shared ? 1 : 0;
  }

  bool sharedDecrypt() const {
    return this->SharedDecrypt != 0;
  }

  uint32_t budget() const {
    return this->Budget;
  }

  uint32_t budgetPct() const {
    return this->BudgetPct;
  }

  const std::string &attributeName() const {
    return this->AttributeName;
  }

  ObfOpt none() const {
    return ObfOpt{false, 0, this->attributeName()};
  }

};

class ObfuscationOptions {
protected:
  std::shared_ptr<ObfOpt> IndBrOpt = nullptr;
  std::shared_ptr<ObfOpt> ICallOpt = nullptr;
  std::shared_ptr<ObfOpt> IndGvOpt = nullptr;
  std::shared_ptr<ObfOpt> FlaOpt = nullptr;
  std::shared_ptr<ObfOpt> CseOpt = nullptr;
  std::shared_ptr<ObfOpt> CieOpt = nullptr;
  std::shared_ptr<ObfOpt> CfeOpt = nullptr;
  std::shared_ptr<ObfOpt> RttiOpt = nullptr;
  std::shared_ptr<ObfOpt> PsoOpt  = nullptr;
  std::shared_ptr<ObfOpt> BcfOpt  = nullptr;

  SmallString<32> RandomSeed;
  // AArch64 PAC pointer-table signing is opt-in: it needs a module
  // constructor and the +pauth target feature, so it must never be enabled
  // implicitly by -march=armv8.3-a on platforms we have not validated.
  bool PtrAuthEnabled = false;
  // config "deny" 段：用户自定义红区名单（红区语义，注解也无法解锁），
  // 匹配 demangled 函数名（'*' 不跨 "::"，'**' 跨 "::"）。
  std::vector<std::string> DenyList;

  // config "patterns" 段：分级策略中间层（文件 / 类 / 命名空间级覆盖），
  // 按声明顺序保存；同层后写覆盖先写（字段级）。
  std::vector<ConfigPatternRule> PatternRules;

public:
  SmallVector<std::shared_ptr<ObfOpt>> getAllOpt() const {
    SmallVector<std::shared_ptr<ObfOpt>, 9> allOpt;
    allOpt.push_back(IndBrOpt);
    allOpt.push_back(ICallOpt);
    allOpt.push_back(IndGvOpt);
    allOpt.push_back(FlaOpt);
    allOpt.push_back(CseOpt);
    allOpt.push_back(CieOpt);
    allOpt.push_back(CfeOpt);
    allOpt.push_back(RttiOpt);
    allOpt.push_back(PsoOpt);
    allOpt.push_back(BcfOpt);
    return allOpt;
  }

  ObfuscationOptions(const std::shared_ptr<ObfOpt> &indBrOpt,
                     const std::shared_ptr<ObfOpt> &iCallOpt,
                     const std::shared_ptr<ObfOpt> &indGvOpt,
                     const std::shared_ptr<ObfOpt> &flaOpt,
                     const std::shared_ptr<ObfOpt> &cseOpt,
                     const std::shared_ptr<ObfOpt> &cieOpt,
                     const std::shared_ptr<ObfOpt> &cfeOpt,
                     const std::shared_ptr<ObfOpt> &rttiOpt,
                     const std::shared_ptr<ObfOpt> &psoOpt,
                     const std::shared_ptr<ObfOpt> &bcfOpt) {
    this->IndBrOpt = indBrOpt;
    this->ICallOpt = iCallOpt;
    this->IndGvOpt = indGvOpt;
    this->FlaOpt = flaOpt;
    this->CseOpt = cseOpt;
    this->CieOpt = cieOpt;
    this->CfeOpt = cfeOpt;
    this->RttiOpt = rttiOpt;
    this->PsoOpt  = psoOpt;
    this->BcfOpt  = bcfOpt;
  }

  ObfuscationOptions() : ObfuscationOptions{
                           std::make_shared<ObfOpt>("indbr"),
                           std::make_shared<ObfOpt>("icall"),
                           std::make_shared<ObfOpt>("indgv"),
                           std::make_shared<ObfOpt>("fla"),
                           std::make_shared<ObfOpt>("cse"),
                           std::make_shared<ObfOpt>("cie"),
                           std::shared_ptr<ObfOpt>(new ObfOpt(false, 0, "cfe")),
                           std::shared_ptr<ObfOpt>(new ObfOpt(false, 0, "rtti")),
                           std::shared_ptr<ObfOpt>(new ObfOpt(false, 0, "pso")),
                           std::shared_ptr<ObfOpt>(new ObfOpt(false, 0, "bcf"))
                       } {}

  auto indBrOpt() const {
    return IndBrOpt;
  }

  auto iCallOpt() const {
    return ICallOpt;
  }

  auto indGvOpt() const {
    return IndGvOpt;
  }

  auto flaOpt() const {
    return FlaOpt;
  }

  auto cseOpt() const {
    return CseOpt;
  }

  auto cieOpt() const {
    return CieOpt;
  }

  auto cfeOpt() const {
    return CfeOpt;
  }

  auto rttiOpt() const {
    return RttiOpt;
  }

  auto psoOpt() const { return PsoOpt; }

  auto bcfOpt() const { return BcfOpt; }

  auto &randomSeed() {
    return RandomSeed;
  }

  void setPtrAuthEnabled(bool Enabled) {
    PtrAuthEnabled = Enabled;
  }

  bool ptrAuthEnabled() const {
    return PtrAuthEnabled;
  }

  auto &denyList() {
    return DenyList;
  }

  auto &patternRules() {
    return PatternRules;
  }

  static std::shared_ptr<ObfuscationOptions> readConfigFile(
      const Twine &FileName);

  ObfOpt toObfuscate(const std::shared_ptr<ObfOpt> &option, Function *f);

  // doInitialization 阶段（无 Function 上下文）的"宽判断"：该 pass 是否
  // 可能被任何层面启用——全局开关 / 任一 pattern 规则显式 enable=true /
  // 任一函数的 "+<name>" 注解。Module 级收集与页表构建前用它短路，
  // 避免未启用本 pass 的构建也被塞入页表全局（并避免无谓修改 CFG）。
  bool mayBeEnabled(const std::shared_ptr<ObfOpt> &option, Module &M);

};

}

#endif