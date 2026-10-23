#ifndef OBFUSCATION_OBFUSCATIONOPTIONS_H
#define OBFUSCATION_OBFUSCATIONOPTIONS_H

#include "llvm/Support/YAMLParser.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringMap.h"
#include <algorithm>
#include <optional>
#include <vector>


namespace llvm {

SmallVector<std::string> readAnnotate(Function *f);

// 读取函数上的 decoy 注解（+decoy / -decoy / ^decoy=N；旧名 bcf_decoy 仍接受）。
// 返回 std::nullopt 表示没有 decoy 注解（该函数不进入 decoy 资格门）。
// 多条 decoy 注解时后写覆盖先写。
std::optional<uint32_t> readDecoyAnnotation(Function *f);
// 读取 L3 值污染注解（+decoy_pollute / -decoy_pollute；旧名 bcf_decoy_pollute 仍接受）。
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
    // decoy 域：进入诱饵路径的比例（0-100）与 L3 值污染。
    std::optional<uint32_t> Decoy;
    std::optional<bool>     DecoyPollute;
    // bcf 域：站点概率与每函数上限。
    std::optional<uint32_t> Strength;
    std::optional<uint32_t> Budget;
    std::optional<uint32_t> BudgetPct;
  };
  llvm::StringMap<OptOverride> Overrides;
};

// 每个功能域只接受自己的 config 字段。解析时若写了不属于该域的字段，
// 打印 warning 并忽略——避免 "level" 这种名字在八个 pass 上静默无效。
enum OptField : uint32_t {
  F_Level      = 1u << 0,
  F_Mode       = 1u << 1,
  F_Split      = 1u << 2,
  F_Strength   = 1u << 3,
  F_Budget     = 1u << 4,
  F_BudgetPct  = 1u << 5,
  F_Ratio      = 1u << 6,
  F_Pollute    = 1u << 7,
  F_Probe      = 1u << 8,
  F_Shared     = 1u << 9,
  F_Wrap       = 1u << 10,
  F_Shuffle    = 1u << 11,
};

class ObfOpt {
protected:
  uint32_t    Enabled : 1;
  // 强度档位 0..3。只有声明了 F_Level 的 pass 才读它。
  uint32_t    Level   : 2;
  // indbr 专用：0 = table（默认）, 1 = full（全边）, 2 = dual（双目标）。
  uint32_t    Mode    : 2;
  // bcf 专用：站点命中概率 0..100。
  uint32_t    Strength : 7;
  // decoy 专用：站点中"诱饵菱形"的比例 0..100，其余站点是纯 poison。
  uint32_t    Decoy   : 7;
  // decoy 专用：L3 值污染（仅 Decoy>0 时生效）。
  uint32_t    DecoyPollute : 1;
  // cse 专用：全模块共用一个解密器（体积优先）。
  uint32_t    SharedDecrypt : 1;
  // aux 专用：包装概率 0..100 / 是否乱序 / 每函数最多切几刀。
  uint32_t    Wrap : 7;
  uint32_t    DoShuffle : 1;
  uint32_t    SplitCount : 3;
  // bcf 专用：每函数站点上限与占可插桩块数的百分比。
  uint32_t    Budget = 16;
  uint32_t    BudgetPct = 20;
  // indbr 专用：进入页表前把基本块拆到最多 N 条指令。
  uint32_t    IndBrSplitCount = 0;
  // decoy 专用：App 提供的 probe 符号名。
  std::string Probe;
  std::string AttributeName;

public:
  ObfOpt(bool enable, uint32_t level, const std::string &attributeName) {
    init(enable, level, attributeName);
  }

  ObfOpt(const std::string &attributeName) {
    init(false, 0, attributeName);
  }

  // 该功能域接受哪些 config 字段。未列出的字段写了会被拒绝并告警。
  uint32_t supportedFields() const {
    const std::string &N = AttributeName;
    if (N == "indbr")  return F_Level | F_Mode | F_Split;
    if (N == "icall")  return F_Level;
    if (N == "indgv")  return F_Level;
    if (N == "fla")    return 0;
    if (N == "cse")    return F_Shared;
    if (N == "cie")    return F_Level;
    if (N == "cfe")    return F_Level;
    if (N == "rtti")   return 0;
    if (N == "bcf")    return F_Strength | F_Budget | F_BudgetPct;
    if (N == "decoy")  return F_Ratio | F_Pollute | F_Probe;
    // rename 没有档位：改名就是改名，做一半等于没做（调试信息会泄露原名）。
    if (N == "rename") return 0;
    if (N == "aux")    return F_Wrap | F_Shuffle | F_Split;
    return 0;
  }

  void setMode(uint32_t mode) {
    this->Mode = std::min<uint32_t>(mode, 2);
  }

  uint32_t mode() const {
    return this->Mode;
  }

  void setStrength(uint32_t strength) {
    this->Strength = std::min<uint32_t>(strength, 100);
  }

  uint32_t strength() const {
    return this->Strength;
  }

  void setWrap(uint32_t wrap) {
    this->Wrap = std::min<uint32_t>(wrap, 100);
  }

  uint32_t wrap() const {
    return this->Wrap;
  }

  void setShuffle(bool shuffle) {
    this->DoShuffle = shuffle ? 1 : 0;
  }

  bool shuffle() const {
    return this->DoShuffle != 0;
  }

  void setSplitCount(uint32_t count) {
    this->SplitCount = std::min<uint32_t>(count, 7);
  }

  uint32_t splitCount() const {
    return this->SplitCount;
  }

  void setIndBrSplitCount(uint32_t count) {
    this->IndBrSplitCount = std::min<uint32_t>(count, 4096);
  }

  uint32_t indBrSplitCount() const {
    return this->IndBrSplitCount;
  }

  void setProbe(const std::string &probe) {
    this->Probe = probe;
  }

  const std::string &probe() const {
    return this->Probe;
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
    ObfOpt R{false, 0, this->attributeName()};
    // probe 是模块级策略（App 提供的符号名），不随函数级 enable 级联丢失。
    R.Probe = this->Probe;
    return R;
  }

private:
  void init(bool enable, uint32_t level, const std::string &attributeName) {
    this->Enabled = enable;
    this->Level = std::min<uint32_t>(level, 3);
    // CIE/CFE 的 level 只是加密强度（0 = 一次 sub，2 = 三层混合），
    // 运行时成本几乎相同，默认给 2；显式写 0 仍然尊重。
    // INDBR/ICALL/INDGV 的 level 0 表示"全模块共享页表"，是体积取舍，
    // 所以那几个域保持 0。
    if ((attributeName == "cie" || attributeName == "cfe") && level == 0)
      this->Level = 2;
    this->Mode = 0;
    this->Strength = 70;
    // decoy 域默认 30%：只写 "enable": true 时也应有保护，而不是静默 0。
    this->Decoy = 30;
    this->DecoyPollute = 0;
    this->SharedDecrypt = 0;
    this->Wrap = 100;
    // aux 域默认三项全开，与 `-irobf-aux` 不带值的行为一致。
    this->DoShuffle = 1;
    this->SplitCount = 3;
    this->AttributeName = attributeName;
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
  std::shared_ptr<ObfOpt> BcfOpt  = nullptr;
  // decoy（运行时诱饵）是独立功能域：不再挂在 BCF 上。
  std::shared_ptr<ObfOpt> DecoyOpt = nullptr;
  std::shared_ptr<ObfOpt> RenameOpt = nullptr;
  // 结构性后处理（转发包装 / 块乱序 / 块拆分）合成一个域。
  std::shared_ptr<ObfOpt> AuxOpt = nullptr;

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
    SmallVector<std::shared_ptr<ObfOpt>, 13> allOpt;
    allOpt.push_back(IndBrOpt);
    allOpt.push_back(ICallOpt);
    allOpt.push_back(IndGvOpt);
    allOpt.push_back(FlaOpt);
    allOpt.push_back(CseOpt);
    allOpt.push_back(CieOpt);
    allOpt.push_back(CfeOpt);
    allOpt.push_back(RttiOpt);
    allOpt.push_back(BcfOpt);
    allOpt.push_back(DecoyOpt);
    allOpt.push_back(RenameOpt);
    allOpt.push_back(AuxOpt);
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
                     const std::shared_ptr<ObfOpt> &bcfOpt,
                     const std::shared_ptr<ObfOpt> &decoyOpt,
                     const std::shared_ptr<ObfOpt> &renameOpt,
                     const std::shared_ptr<ObfOpt> &auxOpt) {
    this->IndBrOpt = indBrOpt;
    this->ICallOpt = iCallOpt;
    this->IndGvOpt = indGvOpt;
    this->FlaOpt = flaOpt;
    this->CseOpt = cseOpt;
    this->CieOpt = cieOpt;
    this->CfeOpt = cfeOpt;
    this->RttiOpt = rttiOpt;
    this->BcfOpt  = bcfOpt;
    this->DecoyOpt = decoyOpt;
    this->RenameOpt = renameOpt;
    this->AuxOpt = auxOpt;
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
                           std::shared_ptr<ObfOpt>(new ObfOpt(false, 0, "bcf")),
                           std::shared_ptr<ObfOpt>(new ObfOpt(false, 0, "decoy")),
                           std::shared_ptr<ObfOpt>(new ObfOpt(false, 0, "rename")),
                           std::shared_ptr<ObfOpt>(new ObfOpt(false, 0, "aux"))
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

  auto bcfOpt() const { return BcfOpt; }
  auto decoyOpt() const { return DecoyOpt; }
  auto renameOpt() const { return RenameOpt; }
  auto auxOpt() const { return AuxOpt; }

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