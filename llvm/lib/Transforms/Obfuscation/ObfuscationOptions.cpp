#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/Support/JSON.h"
#include "llvm/Demangle/Demangle.h"
#include <cstdlib>

using namespace llvm;

namespace llvm {

// IR features whose semantics cannot survive CFG rewriting or call-site
// rewriting.  These are not "hardening" choices but correctness gates:
//   - convergence tokens: control flow must stay inside the convergence region
//   - gc.statepoint/result/relocate: stack maps encode exact call sites
//   - coro.*: state machine protos and suspend points
//   - preallocated/inalloca: caller-owned argument storage and ABI
static bool hasObfuscationUnsafeIR(Function *F) {
  for (unsigned i = 0; i < F->arg_size(); ++i)
    if (F->hasParamAttribute(i, Attribute::InAlloca) ||
        F->hasParamAttribute(i, Attribute::Preallocated))
      return true;
  for (Instruction &I : instructions(*F)) {
    auto *CB = dyn_cast<CallBase>(&I);
    if (!CB)
      continue;
    // inalloca is a call-site ABI contract: the caller passes a pointer to
    // caller-owned argument storage.  Rewriting the call (e.g. indirect call
    // promotion) would materialise those arguments in registers.
    for (unsigned i = 0; i < CB->arg_size(); ++i)
      if (CB->paramHasAttr(i, Attribute::InAlloca) ||
          CB->paramHasAttr(i, Attribute::Preallocated))
        return true;
    Function *Callee = CB->getCalledFunction();
    if (!Callee)
      continue;
    StringRef N = Callee->getName();
    if (N.starts_with("llvm.experimental.") ||
        N.starts_with("llvm.coro.") ||
        N.starts_with("llvm.call.preallocated.") ||
        N.starts_with("llvm.type."))
      return true;
  }
  return false;
}


SmallVector<std::string> readAnnotate(Function *f) {
  SmallVector<std::string> annotations;

  auto *Annotations = f->getParent()->getGlobalVariable(
      "llvm.global.annotations");
  auto *C = dyn_cast_or_null<Constant>(Annotations);
  if (!C || C->getNumOperands() != 1)
    return annotations;

  C = cast<Constant>(C->getOperand(0));

  // Iterate over all entries in C and attach !annotation metadata to suitable
  // entries.
  for (auto &Op : C->operands()) {
    // Look at the operands to check if we can use the entry to generate
    // !annotation metadata.
    auto *OpC = dyn_cast<ConstantStruct>(&Op);
    if (!OpC || OpC->getNumOperands() < 2)
      continue;
    auto *Fn = dyn_cast<Function>(OpC->getOperand(0)->stripPointerCasts());
    if (Fn != f)
      continue;
    auto *StrC = dyn_cast<GlobalValue>(OpC->getOperand(1)->stripPointerCasts());
    if (!StrC)
      continue;
    auto *StrData = dyn_cast<ConstantDataSequential>(StrC->getOperand(0));
    if (!StrData)
      continue;
    annotations.emplace_back(StrData->getAsString());
  }
  return annotations;
}

// ============================================================
// 安全底线（safety floor）
//
// 红区（red zone）：永不混淆。这些函数是链接与运行时语义的底座，
//   任何配置（CLI / config / pattern）与函数注解都无法解锁：
//     - 弱符号函数（isWeakForLinker，含 linkonce_odr 模板实例化）：
//       逐 .o 重复出现，混淆会编译爆炸；且链接期可被强符号覆盖。
//     - 运行时胶水（__cxa_ / __gxx_ / _GLOBAL__ / __cxx_global_var_init）。
//     - llvm.global_ctors / llvm.global_dtors 登记的函数
//       （C++ 静态初始化/退出、__attribute__((constructor/destructor))）。
//     - operator new / operator delete（分配器原语）。
// 黄区（yellow zone）：默认跳过，仅函数上的显式启用注解（如 +bcf）
//   可逐函数解锁，全局配置没有这个能力：
//     - 析构函数 / 构造函数（异常展开与静态初始化/退出路径上执行）。
//     - 其余运算符函数（高频原语，如 STL 内部调用 operator=）。
// 用户 deny 列表（config "deny" 段）：红区语义的自定义扩展，
//   匹配 demangled 名字（'*' 不跨 "::"，'**' 跨 "::"）。
// ============================================================

static bool isIdentChar(char C) {
  return C == '_' || (C >= '0' && C <= '9') || (C >= 'a' && C <= 'z') ||
         (C >= 'A' && C <= 'Z');
}

// 规范名字：去掉参数与返回类型的 demangled 形式。
// pattern / deny 匹配一律基于此形式，使重载共享同一名字
// （denied_fn(int) 与 denied_fn(double) 均归一为 "denied_fn"）。
// Itanium 走 ParseParams=false（_Z10denied_fni -> "denied_fn"，
// 模板实例化 _Z8tmpl_fnIiET_S0_ -> "tmpl_fn<int>"，均不含返回类型）；
// 非 Itanium（MSVC ABI）或解析失败时回退通用 demangle 并截断 '(' 之后。
static std::string demangleNoParams(StringRef Mangled) {
  if (char *D = itaniumDemangle(Mangled, /*ParseParams=*/false)) {
    std::string Result(D);
    std::free(D);
    return Result;
  }
  std::string D = llvm::demangle(Mangled.str());
  const size_t Paren = D.find('(');
  return Paren == std::string::npos ? D : D.substr(0, Paren);
}

// 名字中是否含运算符函数 "operator..."（带边界检查，避免误伤
// 名字里恰好含 "operator" 子串的普通函数）
static bool containsOperatorName(StringRef Name) {
  size_t Pos = 0;
  while ((Pos = Name.find("operator", Pos)) != StringRef::npos) {
    const bool LeftOK =
        Pos == 0 || Name[Pos - 1] == ':' || Name[Pos - 1] == ' ';
    const char Next = Pos + 8 < Name.size() ? Name[Pos + 8] : '\0';
    if (LeftOK && !isIdentChar(Next))
      return true;
    Pos += 8;
  }
  return false;
}

// operator new / operator delete（含 [] / nothrow / aligned 变体）
static bool isOperatorNewDelete(StringRef Demangled) {
  return Demangled.contains("operator new") ||
         Demangled.contains("operator delete");
}

// 析构函数（demangle 后形如 Class::~Class()）
static bool isDestructorName(StringRef Demangled) {
  return Demangled.contains("::~");
}

// 取名字的最后一段作用域（MSVC demangle 可能带
// "public: __thiscall " 之类前缀，用空格兜底）
static StringRef lastScopeSegment(StringRef S) {
  const size_t Scope = S.rfind("::");
  if (Scope != StringRef::npos)
    return S.substr(Scope + 2);
  const size_t Space = S.rfind(' ');
  if (Space != StringRef::npos)
    return S.substr(Space + 1);
  return S;
}

// 构造函数（demangle 后形如 ns::Class::Class(...)）：取 '(' 前的
// 名字部分，比较最后两段（剥离模板参数后）是否同名。
// 注意：命名空间里与命名空间同名的普通函数会误判为构造函数
// （保守方向，可通过注解解锁）。
static bool isConstructorName(StringRef Demangled) {
  const size_t Paren = Demangled.find('(');
  StringRef    Name =
      Paren == StringRef::npos ? Demangled : Demangled.substr(0, Paren);
  const size_t Last = Name.rfind("::");
  if (Last == StringRef::npos)
    return false;
  StringRef LastSeg = Name.substr(Last + 2);
  StringRef PrevSeg = lastScopeSegment(Name.substr(0, Last));
  auto StripTemplateArgs = [](StringRef S) {
    const size_t Lt = S.find('<');
    return Lt == StringRef::npos ? S : S.substr(0, Lt);
  };
  return !LastSeg.empty() &&
         StripTemplateArgs(LastSeg) == StripTemplateArgs(PrevSeg);
}

// 运行时胶水 / 编译器生成函数（按名字前缀）
static bool isRuntimeGlueName(StringRef Name) {
  return Name.starts_with("__cxa_") || Name.starts_with("__gxx_") ||
         Name.starts_with("_GLOBAL__") ||
         Name.starts_with("__cxx_global_var_init");
}

// llvm.global_ctors / llvm.global_dtors 登记的函数
static bool isGlobalCtorOrDtor(Function *F) {
  Module *M = F->getParent();
  if (!M)
    return false;
  for (const char *GVName : {"llvm.global_ctors", "llvm.global_dtors"}) {
    GlobalVariable *GV = M->getNamedGlobal(GVName);
    if (!GV || !GV->hasInitializer())
      continue;
    Constant *Init = GV->getInitializer();
    if (!Init || isa<ConstantAggregateZero>(Init))
      continue;
    for (const Use &U : Init->operands()) {
      const auto *CS = dyn_cast<ConstantStruct>(U.get());
      if (!CS || CS->getNumOperands() < 2)
        continue;
      if (dyn_cast<Function>(CS->getOperand(1)->stripPointerCasts()) == F)
        return true;
    }
  }
  return false;
}

// 红区：永不混淆（注解也无法解锁）
static bool isSafetyRedZone(Function *F, StringRef Demangled) {
  if (F->isWeakForLinker())
    return true;
  if (isRuntimeGlueName(F->getName()))
    return true;
  if (isGlobalCtorOrDtor(F))
    return true;
  if (isOperatorNewDelete(Demangled))
    return true;
  return false;
}

// 黄区：默认跳过，仅显式启用注解可解锁
static bool isSafetyYellowZone(StringRef Demangled) {
  if (Demangled.empty())
    return false;
  if (isDestructorName(Demangled))
    return true;
  if (isConstructorName(Demangled))
    return true;
  if (containsOperatorName(Demangled))
    return true;
  return false;
}

// 名称通配匹配：'*' 匹配任意字符但不跨 "::"；'**' 匹配任意字符（含 "::"）。
// "**::" 额外允许匹配"零层作用域"（即全局函数，如 "**::test" 也匹配 "test"）。
static bool matchNamePattern(StringRef Pattern, StringRef Name) {
  while (!Pattern.empty()) {
    if (Pattern.consume_front("**")) {
      if (Pattern.empty())
        return true;
      const bool ScopeOptional = Pattern.starts_with("::");
      for (size_t I = 0; I <= Name.size(); ++I) {
        StringRef Rest = Name.drop_front(I);
        if (matchNamePattern(Pattern, Rest))
          return true;
        if (ScopeOptional && I == 0 &&
            matchNamePattern(Pattern.drop_front(2), Rest))
          return true;
      }
      return false;
    }
    if (Pattern.front() == '*') {
      Pattern = Pattern.drop_front();
      // '*' 不跨 "::"：消费上限 = 名字中（自当前游标起）下一个 "::"
      // 的起点（不含）。必须以"当前游标起"计算，而不是检查游标前的
      // 字符——否则 "Widget::*" 匹配 "Widget::calc" 时，游标恰好落在
      // "::" 之后，会被误判为"已跨 ::" 而提前终止。
      size_t Limit = Name.find("::");
      if (Limit == StringRef::npos)
        Limit = Name.size();
      for (size_t I = 0; I <= Limit; ++I) {
        if (matchNamePattern(Pattern, Name.drop_front(I)))
          return true;
      }
      return false;
    }
    if (Name.empty() || Pattern.front() != Name.front())
      return false;
    Pattern = Pattern.drop_front();
    Name = Name.drop_front();
  }
  return Name.empty();
}

// 注解 token 边界匹配：Annotation 以 Token 开头，且 Token 后不是标识符字符。
// 用于避免 "+bcf_decoy" 被 "+bcf" 前缀误匹配（用户明确要求完整 token 匹配）。
static bool startsWithToken(StringRef Annotation, StringRef Token) {
  Annotation = Annotation.ltrim();
  if (!Annotation.consume_front(Token))
    return false;
  return Annotation.empty() || !isIdentChar(Annotation.front());
}

// 解析 decoy 注解（decoy 是独立功能域，不再借用 bcf 前缀）：
//   +decoy        -> 100
//   -decoy        -> 0
//   ^decoy = N    -> N (0-100)
// 旧名 +bcf_decoy / -bcf_decoy / ^bcf_decoy 仍然接受。
// 注意：+decoy_pollute 不会被这里匹配（'_' 是标识符字符，token 边界不成立）。
static bool parseDecoyAnnotation(StringRef Annotation, uint32_t &Out) {
  Annotation = Annotation.ltrim();
  std::string Buf;
  if (Annotation.contains("bcf_decoy")) {
    Buf = Annotation.str();
    Buf.replace(Buf.find("bcf_decoy"), 9, "decoy");
    Annotation = Buf;
  }
  if (startsWithToken(Annotation, "+decoy")) {
    Out = 100;
    return true;
  }
  if (startsWithToken(Annotation, "-decoy")) {
    Out = 0;
    return true;
  }
  if (!startsWithToken(Annotation, "^decoy"))
    return false;

  StringRef Rest = Annotation.drop_front(StringRef("^decoy").size());
  Rest = Rest.ltrim();
  if (!Rest.consume_front("="))
    return false;
  Rest = Rest.ltrim();

  unsigned Val = 0;
  bool     Any = false;
  for (char C : Rest) {
    if (C == ' ')
      continue;
    if (C < '0' || C > '9')
      return false;
    Val = Val * 10 + static_cast<unsigned>(C - '0');
    if (Val > 1000)
      return false;
    Any = true;
  }
  if (!Any)
    return false;
  Out = std::min(Val, 100u);
  return true;
}

// 黄区解锁：config pattern 必须是精确函数名（不含任何 '*'）。
// 文件级 pattern / 通配 pattern（MyClass::* / **）一律不解锁。
static bool isExactFunctionPattern(const ConfigPatternRule &Rule) {
  return !Rule.NamePattern.empty() &&
         Rule.NamePattern.find('*') == std::string::npos;
}

std::optional<uint32_t> readDecoyAnnotation(Function *F) {
  std::optional<uint32_t> Result;
  for (const std::string &Ann : readAnnotate(F)) {
    uint32_t Decoy = 0;
    if (parseDecoyAnnotation(Ann, Decoy))
      Result = Decoy;
  }
  return Result;
}

// 解析 L3 值污染注解：
//   +decoy_pollute -> true
//   -decoy_pollute -> false
// 旧名 +bcf_decoy_pollute / -bcf_decoy_pollute 仍然接受。
// 只有 decoy>0 的函数才可能真正生效（pollute 不单独构成 decoy 资格）。
std::optional<bool> readDecoyPolluteAnnotation(Function *F) {
  std::optional<bool> Result;
  for (const std::string &Ann : readAnnotate(F)) {
    StringRef A = StringRef(Ann).ltrim();
    std::string Buf;
    if (A.contains("bcf_decoy_pollute")) {
      Buf = A.str();
      Buf.replace(Buf.find("bcf_decoy_pollute"), 17, "decoy_pollute");
      A = Buf;
    }
    if (startsWithToken(A, "+decoy_pollute"))
      Result = true;
    else if (startsWithToken(A, "-decoy_pollute"))
      Result = false;
  }
  return Result;
}

// 字段白名单：每个功能域只接受自己的 config 字段。写错字段时告警并忽略，
// 而不是静默生效失败（旧版 "level" 在 8 个 pass 上就是这样）。
static bool acceptsField(const std::shared_ptr<ObfOpt> &O, uint32_t Field,
                         StringRef Name) {
  if (O->supportedFields() & Field)
    return true;
  llvm::errs() << "warning: \"" << O->attributeName()
               << "\" does not accept \"" << Name << "\"; ignored\n";
  return false;
}

std::shared_ptr<ObfuscationOptions> ObfuscationOptions::readConfigFile(
    const Twine &FileName) {

  std::shared_ptr<ObfuscationOptions> result = std::make_shared<
    ObfuscationOptions>();
  if (FileName.str().empty()) {
    return result;
  }
  if (!sys::fs::exists(FileName)) {
    report_fatal_error("Config file doesn't exist: " + FileName);
  }

  auto BufOrErr = MemoryBuffer::getFileOrSTDIN(FileName);
  if (const auto ErrCode = BufOrErr.getError()) {
    report_fatal_error(
        ("Can not read config file: " + ErrCode.message()).c_str());
  }

  const auto &    buf = *BufOrErr.get();
  llvm::SourceMgr sm;

  auto jsonRoot = json::parse(buf.getBuffer());
  if (!jsonRoot) {
    report_fatal_error(jsonRoot.takeError());
  }
  auto rootObj = jsonRoot->getAsObject();
  if (!rootObj) {
    report_fatal_error("Json root is not an object.");
  }

  static auto procObj = [](const std::shared_ptr<ObfOpt> &obfOpt,
                           const detail::DenseMapPair<
                             json::ObjectKey, json::Value> &
                           obj) ->bool {

    // 字段白名单见 acceptsField()：不属于该功能域的字段告警后忽略。
    static auto procOptValue = [](const std::shared_ptr<ObfOpt> &obfOpt,
                                  const json::Value &            value) {
      if (auto optObj = value.getAsObject()) {
        if (auto enable = optObj->getBoolean("enable")) {
          obfOpt->setEnable(enable.value());
        }
        if (auto level = optObj->getInteger("level")) {
          if (acceptsField(obfOpt, F_Level, "level"))
            obfOpt->setLevel(static_cast<uint32_t>(level.value()));
        }
        // indbr 专用：table | full | dual。split 是独立的块拆分数量。
        if (auto mode = optObj->getString("mode")) {
          if (acceptsField(obfOpt, F_Mode, "mode")) {
            StringRef M = mode.value();
            if (M == "table")
              obfOpt->setMode(0);
            else if (M == "full")
              obfOpt->setMode(1);
            else if (M == "dual")
              obfOpt->setMode(2);
            else
              llvm::errs() << "warning: unknown indbr mode \"" << M
                           << "\" (expected table|full|dual); ignored\n";
          }
        }
        if (auto split = optObj->getInteger("split")) {
          if (acceptsField(obfOpt, F_Split, "split")) {
            uint32_t N = static_cast<uint32_t>(
                std::min<int64_t>(4096, std::max<int64_t>(0, split.value())));
            if (obfOpt->attributeName() == "indbr")
              obfOpt->setIndBrSplitCount(N);
            else
              obfOpt->setSplitCount(N);
          }
        }
        // bcf 专用：站点概率与每函数上限。
        if (auto s = optObj->getInteger("strength")) {
          if (acceptsField(obfOpt, F_Strength, "strength"))
            obfOpt->setStrength(static_cast<uint32_t>(
                std::min<int64_t>(100, std::max<int64_t>(0, s.value()))));
        }
        if (auto budget = optObj->getInteger("budget")) {
          if (acceptsField(obfOpt, F_Budget, "budget"))
            obfOpt->setBudget(static_cast<uint32_t>(std::min<int64_t>(
                4096, std::max<int64_t>(0, budget.value()))));
        }
        if (auto pct = optObj->getInteger("budget_pct")) {
          if (acceptsField(obfOpt, F_BudgetPct, "budget_pct"))
            obfOpt->setBudgetPct(static_cast<uint32_t>(
                std::min<int64_t>(100, std::max<int64_t>(0, pct.value()))));
        }
        // decoy 专用：比例 / 值污染 / probe 符号名。
        if (auto ratio = optObj->getInteger("ratio")) {
          if (acceptsField(obfOpt, F_Ratio, "ratio"))
            obfOpt->setDecoy(static_cast<uint32_t>(
                std::min<int64_t>(100, std::max<int64_t>(0, ratio.value()))));
        }
        if (auto pollute = optObj->getBoolean("pollute")) {
          if (acceptsField(obfOpt, F_Pollute, "pollute"))
            obfOpt->setDecoyPollute(pollute.value());
        }
        if (auto probe = optObj->getString("probe")) {
          if (acceptsField(obfOpt, F_Probe, "probe"))
            obfOpt->setProbe(probe.value().str());
        }
        // cse 专用：全模块共用一个解密器（体积优先）。
        if (auto shared = optObj->getBoolean("shared")) {
          if (acceptsField(obfOpt, F_Shared, "shared"))
            obfOpt->setSharedDecrypt(shared.value());
        }
        // aux 专用：包装概率 / 块乱序 / 块拆分数量。
        if (auto wrap = optObj->getInteger("wrap")) {
          if (acceptsField(obfOpt, F_Wrap, "wrap"))
            obfOpt->setWrap(static_cast<uint32_t>(
                std::min<int64_t>(100, std::max<int64_t>(0, wrap.value()))));
        }
        if (auto shuf = optObj->getBoolean("shuffle")) {
          if (acceptsField(obfOpt, F_Shuffle, "shuffle"))
            obfOpt->setShuffle(shuf.value());
        }
      }
    };

    std::string key = obj.getFirst().str();
    auto &      value = obj.getSecond();

    if (key == obfOpt->attributeName()) {
      procOptValue(obfOpt, value);
      return true;
    }
    return false;
  };

  SmallVector<std::shared_ptr<ObfOpt>> allOpt = result->getAllOpt();
  for (auto &obj : *rootObj) {
    std::string Key = obj.getFirst().str();
    if (Key == "randomSeed" || Key == "seed") {
      // Optional deterministic seed.  Empty (default) keeps the time/urandom
      // seed, so every build differs; a valid 16-byte hex seed makes the
      // obfuscation reproducible for tests, audits and bug reproducers.
      if (auto objStr = obj.getSecond().getAsString()) {
        StringRef SeedStr = objStr.value();
        StringRef Hex = SeedStr;
        bool Valid = SeedStr.size() == 32;
        if (SeedStr.size() == 34 && SeedStr.starts_with_insensitive("0x")) {
          Valid = true;
          Hex = SeedStr.drop_front(2);
        }
        if (Valid) {
          for (char C : Hex) {
            if (!((C >= '0' && C <= '9') || (C >= 'a' && C <= 'f') ||
                  (C >= 'A' && C <= 'F'))) {
              Valid = false;
              break;
            }
          }
        }
        if (Valid)
          result->randomSeed() = SeedStr;
        else
          llvm::errs() << "warning: \"" << Key
                       << "\" must be 32 hex chars (16 bytes, optional 0x "
                          "prefix); ignoring, using a random seed\n";
      } else {
        llvm::errs() << "warning: \"" << Key << "\" must be a string\n";
      }
      continue;
    }
    if (obj.getFirst().str() == "ptrauth") {
      // Opt-in AArch64 pointer authentication.  Accept both
      // "ptrauth": true and "ptrauth": {"enable": true}.
      if (auto b = obj.getSecond().getAsBoolean()) {
        result->setPtrAuthEnabled(b.value());
      } else if (auto o = obj.getSecond().getAsObject()) {
        if (auto b = o->getBoolean("enable"))
          result->setPtrAuthEnabled(b.value());
        else
          llvm::errs() << "warning: \"ptrauth\" object needs \"enable\"\n";
      } else {
        llvm::errs() << "warning: \"ptrauth\" must be a boolean or object\n";
      }
      continue;
    }
    if (obj.getFirst().str() == "deny") {
      if (auto denyArr = obj.getSecond().getAsArray()) {
        for (auto &entry : *denyArr) {
          if (auto pat = entry.getAsString()) {
            result->denyList().push_back(pat.value().str());
          } else {
            llvm::errs() << "warning: non-string entry in \"deny\" list "
                            "ignored\n";
          }
        }
      } else {
        llvm::errs() << "warning: \"deny\" must be an array of strings\n";
      }
      continue;
    }
    if (obj.getFirst().str() == "patterns") {
      auto patArr = obj.getSecond().getAsArray();
      if (!patArr) {
        llvm::errs() << "warning: \"patterns\" must be an array\n";
        continue;
      }
      for (auto &entry : *patArr) {
        auto patObj = entry.getAsObject();
        if (!patObj) {
          llvm::errs() << "warning: pattern entry is not an object, "
                          "ignored\n";
          continue;
        }
        ConfigPatternRule rule;
        if (auto m = patObj->getString("match"))
          rule.NamePattern = m->str();
        if (auto fp = patObj->getString("file"))
          rule.FilePattern = fp->str();
        if (rule.NamePattern.empty() && rule.FilePattern.empty()) {
          llvm::errs() << "warning: pattern entry needs \"match\" or "
                          "\"file\", ignored\n";
          continue;
        }
        for (auto &kv : *patObj) {
          const std::string key = kv.getFirst().str();
          if (key == "match" || key == "file")
            continue;
          bool known = false;
          for (auto &opt : allOpt) {
            if (key != opt->attributeName())
              continue;
            known = true;
            if (auto vo = kv.getSecond().getAsObject()) {
              ConfigPatternRule::OptOverride ov;
              if (auto en = vo->getBoolean("enable"))
                ov.Enable = en.value();
              if (auto lv = vo->getInteger("level"))
                ov.Level = static_cast<uint32_t>(
                    std::min<int64_t>(3, std::max<int64_t>(0, lv.value())));
              // decoy 域：ratio / pollute。
              if (auto dv = vo->getInteger("ratio"))
                ov.Decoy = static_cast<uint32_t>(
                    std::min<int64_t>(100, std::max<int64_t>(0, dv.value())));
              if (auto pv = vo->getBoolean("pollute"))
                ov.DecoyPollute = pv.value();
              // bcf 域：strength / budget / budget_pct。
              if (auto sv = vo->getInteger("strength"))
                ov.Strength = static_cast<uint32_t>(
                    std::min<int64_t>(100, std::max<int64_t>(0, sv.value())));
              if (auto bv = vo->getInteger("budget"))
                ov.Budget = static_cast<uint32_t>(std::min<int64_t>(
                    4096, std::max<int64_t>(0, bv.value())));
              if (auto pv = vo->getInteger("budget_pct"))
                ov.BudgetPct = static_cast<uint32_t>(std::min<int64_t>(
                    100, std::max<int64_t>(0, pv.value())));
              rule.Overrides[key] = ov;
            } else {
              llvm::errs() << "warning: pattern value for \"" << key
                           << "\" must be an object, ignored\n";
            }
            break;
          }
          if (!known)
            llvm::errs() << "warning: unknown pass \"" << key
                         << "\" in pattern entry, ignored\n";
        }
        result->patternRules().push_back(std::move(rule));
      }
      continue;
    }
    bool objHit = false;
    for (auto &opt : allOpt) {
      if ((objHit = procObj(opt, obj))) {
        break;
      }
    }
    if (!objHit) {
      llvm::errs() << "warning: unknown oboro config node: "
        << obj.getFirst().str() << '\n';
    }
  }
  return result;
}

ObfOpt ObfuscationOptions::toObfuscate(const std::shared_ptr<ObfOpt> &option,
                                       Function *                     f) {
  const auto attrEnable = "+" + option->attributeName();
  const auto attrDisable = "-" + option->attributeName();
  const auto attrLevel = "^" + option->attributeName();
  ObfOpt     result = option->none();
  if (f->isDeclaration()) {
    return result;
  }

  // Internal runtime glue (e.g. the PAC table initializer) must never be
  // rewritten by any pass: it runs before the obfuscated tables are usable.
  if (f->getMetadata(obf::metaName(*f->getParent(), "noobf")))
    return result;

  // Coroutines are not ordinary control flow: the split-coroutine CFG carries
  // coro.suspend/coro.end semantics that flattening and block-splitting do not
  // model.  Every pass goes through this gate, so they all stay off coroutine
  // bodies (the frontend lowers them before our pipeline would see a normal
  // function).  Naked/returns_twice functions get the same treatment: their
  // prologue/return contract cannot survive inserted blocks.
  if (f->isPresplitCoroutine() ||
      f->hasFnAttribute(Attribute::Naked) ||
      f->hasFnAttribute(Attribute::ReturnsTwice) ||
      hasObfuscationUnsafeIR(f)) {
    return result;
  }

  if (f->hasAvailableExternallyLinkage() != 0) {
    return result;
  }

  // ---- 安全底线（红区）：永不混淆，注解也无法解锁 ----
  const std::string DemangledName = demangleNoParams(f->getName());
  if (isSafetyRedZone(f, DemangledName)) {
    if (!readAnnotate(f).empty()) {
      f->getContext().diagnose(DiagnosticInfoUnsupported{
          *f,
          "function is in the obfuscation safety red zone (weak symbol / "
          "runtime glue / static ctor-dtor / operator new-delete); "
          "obfuscation is disabled and cannot be enabled by annotation",
          DiagnosticLocation(), DS_Warning});
    }
    return result;
  }

  // ---- 用户 deny 列表（config "deny" 段，红区语义）----
  for (const std::string &Pattern : DenyList) {
    if (matchNamePattern(Pattern, DemangledName)) {
      return result;
    }
  }

  // ---- config patterns 层（分级策略中间层）----
  // 优先级（低→高）：config 全局 / CLI（= option 当前值）→ 纯文件 pattern
  //   → 含 match 的 pattern（类/命名空间层；与 file 同时存在时 AND）。
  // 字段级级联：规则只覆盖它显式设置的字段（enable / level），其余继承上层；
  // 同层按声明顺序，后写覆盖先写。函数注解仍为最高优先级（见下方）。
  bool     patternEnable = option->isEnabled();
  bool     patternEnableExact = false;
  uint32_t patternLevel = option->level();
  // decoy 域的比例/污染随功能域独立级联；bcf 域的 strength 同理。
  uint32_t patternDecoy = option->decoy();
  bool     patternPollute = option->decoyPollute();
  uint32_t patternStrength = option->strength();
  uint32_t patternBudget = option->budget();
  uint32_t patternBudgetPct = option->budgetPct();
  if (!PatternRules.empty()) {
    StringRef FileName;
    if (const Module *M = f->getParent()) {
      StringRef Src = M->getSourceFileName();
      if (!Src.empty())
        FileName = sys::path::filename(Src);
    }
    const std::string &OptName = option->attributeName();
    auto applyRule = [&](const ConfigPatternRule &Rule) {
      auto It = Rule.Overrides.find(OptName);
      if (It == Rule.Overrides.end())
        return;
      if (It->second.Enable) {
        patternEnable = *It->second.Enable;
        // 只有"精确函数名"规则才算显式解锁黄区；通配/文件规则不算。
        patternEnableExact = isExactFunctionPattern(Rule);
      }
      if (It->second.Level)
        patternLevel = *It->second.Level;
      if (It->second.Decoy)
        patternDecoy = *It->second.Decoy;
      if (It->second.DecoyPollute)
        patternPollute = *It->second.DecoyPollute;
      if (It->second.Strength)
        patternStrength = *It->second.Strength;
      if (It->second.Budget)
        patternBudget = *It->second.Budget;
      if (It->second.BudgetPct)
        patternBudgetPct = *It->second.BudgetPct;
    };
    // 第一遍：纯文件 pattern（低优先级）
    for (const ConfigPatternRule &Rule : PatternRules) {
      if (!Rule.NamePattern.empty() || Rule.FilePattern.empty())
        continue;
      if (FileName.empty() || !matchNamePattern(Rule.FilePattern, FileName))
        continue;
      applyRule(Rule);
    }
    // 第二遍：含 match 的规则（高优先级；同时有 file 时为 AND）
    for (const ConfigPatternRule &Rule : PatternRules) {
      if (Rule.NamePattern.empty())
        continue;
      if (!matchNamePattern(Rule.NamePattern, DemangledName))
        continue;
      if (!Rule.FilePattern.empty()) {
        if (FileName.empty() || !matchNamePattern(Rule.FilePattern, FileName))
          continue;
      }
      applyRule(Rule);
    }
  }

  bool annotationEnableFound = false;
  bool annotationDisableFound = false;
  bool decoySet = false;
  bool polluteSet = false;

  auto annotations = readAnnotate(f);
  int  levelSet = 0;
  // decoy 注解只对 decoy 域生效：其他 pass 不该因为函数带 +decoy 而改变。
  const bool IsDecoyOpt = option->attributeName() == "decoy";
  if (!annotations.empty()) {
    if (IsDecoyOpt) {
      if (auto Decoy = readDecoyAnnotation(f)) {
        result.setDecoy(*Decoy);
        decoySet = true;
      }
      if (auto Pollute = readDecoyPolluteAnnotation(f)) {
        result.setDecoyPollute(*Pollute);
        polluteSet = true;
      }
    }
    for (const auto &annotation : annotations) {
      // decoy 注解已单独处理，通用逻辑必须跳过，否则 "+decoy" 会被当成
      // 普通 enable、"^decoy=N" 会被当成 level。
      if (annotation.find("decoy") != std::string::npos)
        continue;
      if (startsWithToken(annotation, attrDisable)) {
        result.setEnable(false);
        annotationDisableFound = true;
      }
      if (startsWithToken(annotation, attrEnable)) {
        result.setEnable(true);
        annotationEnableFound = true;
      }
      if (startsWithToken(annotation, attrLevel)) {
        const auto levelPos = annotation.find(attrLevel);
        if (annotation.find(attrLevel, levelPos + 1) != std::string::npos) {
          f->getContext().diagnose(DiagnosticInfoUnsupported{
              *f,
              f->getName() + " has multiple annotations for setting " + result.
              attributeName() +
              " factors, What are you the fucking want to do?"});
          return result.none();
        }
        int32_t    level = -1;
        const auto equalPos = annotation.find('=', levelPos + 1);
        if (equalPos == std::string::npos) {
          f->getContext().diagnose(DiagnosticInfoUnsupported{
              *f,
              f->getName() + ": " + annotation +
              " missing equal sign, sample: " + attrLevel + " = 0"});
          return result.none();
        }

        for (size_t i = levelPos + attrLevel.length(); i < equalPos; ++i) {
          if (annotation[i] == ' ') {
            continue;
          }
          f->getContext().diagnose(DiagnosticInfoUnsupported{
              *f,
              f->getName() + ": " + annotation +
              " unexpected characters, sample: " + attrLevel + " = 0"});
          return result.none();
        }

        for (size_t i = equalPos + 1; i < annotation.length(); ++i) {
          if (annotation[i] == ' ') {
            continue;
          }
          level = annotation[i] - '0';
          if (level < 0 || level > 9) {
            f->getContext().diagnose(DiagnosticInfoUnsupported{
                *f,
                f->getName() + ": " + annotation +
                " unexpected character: " + std::string{annotation[i]} +
                ", sample: " + attrLevel + " = 0"});
            return result.none();
          }
          break;
        }
        if (level == -1) {
          f->getContext().diagnose(DiagnosticInfoUnsupported{
              *f,
              f->getName() + ": " + annotation +
              " level value not found, sample: " + attrLevel + " = 0"});
          return result.none();
        }

        ++levelSet;
        result.setLevel(level);
      }
    }
  }

  if (annotationDisableFound && annotationEnableFound) {
    f->getContext().diagnose(DiagnosticInfoUnsupported{
        *f,
        f->getName() +
        " having both enable annotation and disable annotation, What are you the fucking want to do?"});
    return result.none();
  }

  if (levelSet > 1) {
    f->getContext().diagnose(DiagnosticInfoUnsupported{
        *f,
        f->getName() + " has multiple annotations for setting " + result.
        attributeName() + " factors, What are you the fucking want to do?"});
    return result.none();
  }

  // ---- 黄区（析构/构造/运算符）：默认跳过 ----
  // 解锁条件：函数注解 "+bcf"，或 config pattern 精确函数名（不含 '*'
  // 且显式 enable:true）。通配 pattern / 纯 file pattern 一律不解锁。
  if (isSafetyYellowZone(DemangledName) && !annotationEnableFound &&
      !(patternEnable && patternEnableExact)) {
    return result.none();
  }

  if (!annotationDisableFound && !annotationEnableFound) {
    result.setEnable(patternEnable);
  }
  if (!levelSet) {
    result.setLevel(patternLevel);
  }
  if (!decoySet) {
    result.setDecoy(patternDecoy);
  } else {
    // "+decoy" / "^decoy=N" 本身即构成启用；"-decoy" / "^decoy=0" 关闭。
    result.setEnable(result.decoy() > 0);
  }
  if (!polluteSet) {
    result.setDecoyPollute(patternPollute);
  }
  result.setStrength(patternStrength);
  // BCF 预算没有函数注解通道，只按 CLI / config / pattern 级联。
  result.setBudget(patternBudget);
  result.setBudgetPct(patternBudgetPct);
  return result;
}

bool ObfuscationOptions::mayBeEnabled(const std::shared_ptr<ObfOpt> &option,
                                      Module &M) {
  // 1) CLI / config 全局开关
  if (option->isEnabled())
    return true;

  // 2) 任一 pattern 规则显式 enable=true
  const std::string &OptName = option->attributeName();
  for (const ConfigPatternRule &Rule : PatternRules) {
    auto It = Rule.Overrides.find(OptName);
    if (It != Rule.Overrides.end() && It->second.Enable && *It->second.Enable)
      return true;
  }

  // 3) 任一函数带 "+<name>" 注解
  const std::string AttrEnable = "+" + OptName;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    for (const std::string &Ann : readAnnotate(&F)) {
      if (startsWithToken(Ann, AttrEnable))
        return true;
    }
  }
  return false;
}

}