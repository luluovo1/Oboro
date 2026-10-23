#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Transforms/Obfuscation/BogusControlFlow.h"
#include "llvm/Transforms/Obfuscation/DecoyPass.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/Transforms/Obfuscation/AuxPasses.h"
#include "llvm/Transforms/Obfuscation/SymbolRename.h"
// CryptoUtils.h defines a function-like macro `R`, which collides with
// std::function template parameters in CommandLine.h if included earlier.
#include "llvm/CryptoUtils.h"
#undef R


#define DEBUG_TYPE "ir-obfuscation"

using namespace llvm;

// ===========================================================================
// 命令行只暴露"功能开关"。每个功能的调参一律走 config 的对应节点，
// 避免实现细节泄漏成产品接口（旧版 37 个选项里有 22 个是调参/变体）。
// ===========================================================================

static cl::opt<std::string>
OboroConfigPath("oboro-cfg", cl::init(std::string{}), cl::NotHidden,
                 cl::desc("Oboro config path."),
                 cl::ZeroOrMore);

static cl::opt<bool>
EnableIRObfuscation("irobf", cl::init(false), cl::NotHidden,
                    cl::desc("Enable IR Code Obfuscation."),
                    cl::ZeroOrMore);

// 全局强度档位 0..3，作为所有支持 level 的功能的默认值；
// config 里各功能自己的 "level" 优先。
static cl::opt<uint32_t>
ObfuscationLevel("irobf-level", cl::init(0), cl::NotHidden,
                 cl::desc("Default strength 0..3 for every pass that has a "
                          "level (config per-pass \"level\" wins)."),
                 cl::ZeroOrMore);

// ---- OLLVM 原有 pass -------------------------------------------------------
static cl::opt<std::string> EnableIndirectBr(
    "irobf-indbr", cl::init(""), cl::ValueOptional, cl::NotHidden,
    cl::desc("Indirect branch obfuscation. Optional value: table (default), "
             "full (all edges), dual (two-target blockaddress)."),
    cl::ZeroOrMore);

static cl::opt<bool>
EnableIndirectCall("irobf-icall", cl::init(false), cl::NotHidden,
                   cl::desc("Enable IR Indirect Call Obfuscation."),
                   cl::ZeroOrMore);

static cl::opt<bool> EnableIndirectGV(
    "irobf-indgv", cl::init(false), cl::NotHidden,
    cl::desc("Enable IR Indirect Global Variable Obfuscation."),
    cl::ZeroOrMore);

static cl::opt<bool> EnableIRFlattening(
    "irobf-fla", cl::init(false), cl::NotHidden,
    cl::desc("Enable IR Control Flow Flattening Obfuscation."), cl::ZeroOrMore);

static cl::opt<bool>
EnableIRStringEncryption("irobf-cse", cl::init(false), cl::NotHidden,
                         cl::desc("Enable IR Constant String Encryption."),
                         cl::ZeroOrMore);

static cl::opt<bool>
EnableIRConstantIntEncryption("irobf-cie", cl::init(false), cl::NotHidden,
                              cl::desc(
                                  "Enable IR Constant Integer Encryption."),
                              cl::ZeroOrMore);

static cl::opt<bool>
EnableIRConstantFPEncryption("irobf-cfe", cl::init(false), cl::NotHidden,
                             cl::desc("Enable IR Constant FP Encryption."),
                             cl::ZeroOrMore);

static cl::opt<bool>
EnableRttiEraser("irobf-rtti", cl::init(false), cl::NotHidden,
  cl::desc("Enable RTTI Eraser."),
  cl::ZeroOrMore);

// ---- 新功能域 --------------------------------------------------------------
// BCF：不带值 = 默认强度 70，带值 = 0..100。
static cl::opt<std::string> EnableBogusControlFlow(
    "irobf-bcf", cl::init(""), cl::ValueOptional, cl::NotHidden,
    cl::desc("Bogus control flow v2. Optional value 0..100 = site strength "
             "(default 70)."),
    cl::ZeroOrMore);

// decoy（运行时诱饵）：独立功能，不依赖 BCF。
static cl::opt<std::string> EnableDecoy(
    "irobf-decoy", cl::init(""), cl::ValueOptional, cl::NotHidden,
    cl::desc("Runtime decoy paths. Optional value 0..100 = share of sites "
             "that become decoy diamonds; the rest are pure poison "
             "(default 30)."),
    cl::ZeroOrMore);

static cl::opt<bool>
EnableSymbolRename("irobf-rename", cl::init(false), cl::NotHidden,
                   cl::desc("Rename internal symbols to opaque names."),
                   cl::ZeroOrMore);

// 结构性后处理：wrap / shuffle / split。不带值 = 三项全开。
static cl::opt<std::string> EnableAux(
    "irobf-aux", cl::init(""), cl::ValueOptional, cl::NotHidden,
    cl::desc("Structural passes. Optional comma list: wrap,shuffle,split "
             "(default: all)."),
    cl::ZeroOrMore);

// 逗号列表里是否含某项；空列表（不带值）视为全开。
static bool auxWants(StringRef List, StringRef Name) {
  if (List.empty())
    return true;
  SmallVector<StringRef, 4> Parts;
  List.split(Parts, ',');
  for (StringRef P : Parts)
    if (P.trim() == Name)
      return true;
  return false;
}

// 带值开关是否出现（出现即启用，空值表示用默认参数）。
template <typename T> static bool isSet(const cl::opt<T> &O) {
  return O.getNumOccurrences() > 0;
}

// 解析 0..100 的强度；空串用 Default。
static uint32_t parseStrength(StringRef S, uint32_t Default) {
  S = S.trim();
  if (S.empty())
    return Default;
  uint32_t V = 0;
  if (S.getAsInteger(10, V)) {
    llvm::errs() << "warning: \"" << S << "\" is not a number; using "
                 << Default << "\n";
    return Default;
  }
  return std::min<uint32_t>(V, 100);
}

namespace llvm {

struct ObfuscationPassManager : public ModulePass {
  static char            ID; // Pass identification
  SmallVector<Pass *, 8> Passes;
  bool                   Late;

  explicit ObfuscationPassManager(bool Late = false)
      : ModulePass(ID), Late(Late) {
    initializeObfuscationPassManagerPass(*PassRegistry::getPassRegistry());
  };

  StringRef getPassName() const override {
    return "Obfuscation Pass Manager";
  }

  bool doFinalization(Module &M) override {
    bool Change = false;
    for (Pass *P : Passes) {
      Change |= P->doFinalization(M);
      delete (P);
    }
    return Change;
  }

  void add(Pass *P) {
    Passes.push_back(P);
  }

  bool run(Module &M) {
    bool Change = false;
    for (Pass *P : Passes) {
      switch (P->getPassKind()) {
      case PassKind::PT_Function:
        Change |= runFunctionPass(M, (FunctionPass *)P);
        break;
      case PassKind::PT_Module:
        Change |= runModulePass(M, (ModulePass *)P);
        break;
      default:
        continue;
      }
    }
    return Change;
  }

  bool runFunctionPass(Module &M, FunctionPass *P) {
    bool Changed = false;
    Changed |= P->doInitialization(M);
    for (Function &F : M) {
      Changed |= P->runOnFunction(F);
    }
    return Changed;
  }

  bool runModulePass(Module &M, ModulePass *P) {
    return P->doInitialization(M) || P->runOnModule(M);
  }

  static std::shared_ptr<ObfuscationOptions> getOptions() {
    // 主管线和末端管线各有一个 manager 实例；config 只解析一次，
    // 否则每条告警（未知节点 / 写错字段）都会打印两遍。
    // -oboro-cfg 是进程级参数，所有模块共用同一份配置，缓存安全。
    static std::shared_ptr<ObfuscationOptions> Cached;
    if (Cached)
      return Cached;

    auto Opt = ObfuscationOptions::readConfigFile(OboroConfigPath);

    // 全局强度：只有用户显式给了 -irobf-level 才覆盖各域自己的 level。
    if (isSet(ObfuscationLevel))
      for (auto &O : Opt->getAllOpt())
        if (O->supportedFields() & F_Level)
          O->setLevel(ObfuscationLevel);

    // indbr：不带值 = table；带值 = table|full|dual。
    if (isSet(EnableIndirectBr)) {
      Opt->indBrOpt()->setEnable(true);
      StringRef M = EnableIndirectBr.getValue();
      if (M.empty() || M == "table")
        Opt->indBrOpt()->setMode(0);
      else if (M == "full")
        Opt->indBrOpt()->setMode(1);
      else if (M == "dual")
        Opt->indBrOpt()->setMode(2);
      else
        llvm::errs() << "warning: unknown -irobf-indbr value \"" << M
                     << "\" (expected table|full|dual); using table\n";
    }

    if (isSet(EnableIndirectCall))
      Opt->iCallOpt()->setEnable(EnableIndirectCall);
    if (isSet(EnableIndirectGV))
      Opt->indGvOpt()->setEnable(EnableIndirectGV);
    if (isSet(EnableIRFlattening))
      Opt->flaOpt()->setEnable(EnableIRFlattening);
    if (isSet(EnableIRStringEncryption))
      Opt->cseOpt()->setEnable(EnableIRStringEncryption);
    if (isSet(EnableIRConstantIntEncryption))
      Opt->cieOpt()->setEnable(EnableIRConstantIntEncryption);
    if (isSet(EnableIRConstantFPEncryption))
      Opt->cfeOpt()->setEnable(EnableIRConstantFPEncryption);
    if (isSet(EnableRttiEraser))
      Opt->rttiOpt()->setEnable(EnableRttiEraser);

    // bcf / decoy：带值开关，空值走默认强度。
    if (isSet(EnableBogusControlFlow)) {
      Opt->bcfOpt()->setEnable(true);
      Opt->bcfOpt()->setStrength(
          parseStrength(EnableBogusControlFlow.getValue(), 70));
    }
    if (isSet(EnableDecoy)) {
      Opt->decoyOpt()->setEnable(true);
      Opt->decoyOpt()->setDecoy(parseStrength(EnableDecoy.getValue(), 30));
    }

    if (isSet(EnableSymbolRename))
      Opt->renameOpt()->setEnable(true);

    // aux：逗号列表控制三项子功能；不带值 = 全开。
    if (isSet(EnableAux)) {
      Opt->auxOpt()->setEnable(true);
      StringRef AuxList = EnableAux.getValue();
      Opt->auxOpt()->setWrap(auxWants(AuxList, "wrap") ? 100 : 0);
      Opt->auxOpt()->setShuffle(auxWants(AuxList, "shuffle"));
      Opt->auxOpt()->setSplitCount(auxWants(AuxList, "split") ? 3 : 0);
    }
    Cached = Opt;
    return Cached;
  }

  bool runOnModule(Module &M) override {
    const auto Options(getOptions());

    if (Late) {
      // 这些 pass 必须看到最终 IR：在 PipelineStart 跑会被优化器折回。
      const bool WantShuffle =
          Options->auxOpt()->isEnabled() && Options->auxOpt()->shuffle();
      const bool WantSplit = Options->auxOpt()->isEnabled() &&
                             Options->auxOpt()->splitCount() > 0;
      const bool WantDual =
          Options->indBrOpt()->isEnabled() && Options->indBrOpt()->mode() == 2;
      if (!WantShuffle && !WantSplit && !WantDual)
        return false;
      if (!Options->randomSeed().empty())
        cryptoutils->prng_seed(std::string(Options->randomSeed()));
      // 先切块再乱序：反过来新插入的块会破坏已随机化的布局。
      if (WantSplit)
        add(llvm::createSplitBlocksPass(Options.get(),
                                        Options->auxOpt()->splitCount()));
      if (WantShuffle)
        add(llvm::createShuffleBlocksPass(Options.get()));
      if (WantDual)
        add(llvm::createIndirectBranchPass(Options.get(), /*Dual=*/true));
      return run(M);
    }

    if (isSet(EnableIndirectBr) || isSet(EnableIndirectCall) ||
        isSet(EnableIndirectGV) || isSet(EnableIRFlattening) ||
        isSet(EnableIRStringEncryption) ||
        isSet(EnableIRConstantIntEncryption) ||
        isSet(EnableIRConstantFPEncryption) || isSet(EnableRttiEraser) ||
        isSet(EnableBogusControlFlow) || isSet(EnableDecoy) ||
        isSet(EnableSymbolRename) || isSet(EnableAux) ||
        !OboroConfigPath.empty()) {
      EnableIRObfuscation = true;
    }

    if (!EnableIRObfuscation) {
      return false;
    }

    // ptrauth 只作用于页表。没有任何页表 pass 时明确告警，而不是静默空转。
    if (Options->ptrAuthEnabled() &&
        !Options->mayBeEnabled(Options->indBrOpt(), M) &&
        !Options->mayBeEnabled(Options->iCallOpt(), M) &&
        !Options->mayBeEnabled(Options->indGvOpt(), M)) {
      llvm::errs() << "warning: \"ptrauth\" is enabled but no pointer-table "
                      "pass (indbr/icall/indgv) is on; it has no effect\n";
    }

    // Reproducible mode (tests / audits / bug reproducers): a config-provided
    // seed fixes the shared AES-CTR stream for every pass in this module.
    // Without it the PRNG seeds itself from time/urandom, so two builds of the
    // same source differ -- which is the intended production behaviour.
    if (!Options->randomSeed().empty()) {
      std::string Seed(Options->randomSeed());
      cryptoutils->prng_seed(Seed);
    }

    // fwrap 在 DecoyPass 之前跑，probe 名必须现在就确定，否则自定义
    // "decoy.probe" 时 wrapper 会把 probe 也包起来。
    setDecoyProbeSymbol(Options->decoyOpt()->probe());

    unsigned pointerSize = M.getDataLayout().getTypeAllocSize(
        PointerType::getUnqual(M.getContext()));

    add(llvm::createConstantIntEncryptionPass(Options.get()));
    add(llvm::createConstantFPEncryptionPass(Options.get()));

    // 字符串加密必须在间接全局变量之前：否则 INDGV 先把字符串全局的
    // 使用点改写成页表对象，CSE 认不出这些常量串，导致 full 组合下明文泄露。
    if (Options->cseOpt()->isEnabled() ||
        Options->mayBeEnabled(Options->cseOpt(), M)) {
      add(llvm::createStringEncryptionPass(Options.get()));
    }

    add(llvm::createIndirectGlobalVariablePass(Options.get()));

    // aux.wrap 必须在 ICALL 之前：调用一旦被间接化，包装器就没有意义了。
    if (Options->auxOpt()->isEnabled() && Options->auxOpt()->wrap() > 0)
      add(llvm::createFunctionWrapperPass(Options.get(),
                                          Options->auxOpt()->wrap()));

    add(llvm::createIndirectCallPass(Options.get()));
    add(llvm::createFlatteningPass(pointerSize, Options.get()));

    // 顺序固定：BCF 在原始 CFG 上 split+fixStack 是线性的；若 indbr 先把
    // 条件分支换成 indirectbr，BCF 再 split 会引发后端寄存器分配/EH 的
    // 组合爆炸（实测编译卡死）。
    if (Options->bcfOpt()->isEnabled() ||
        Options->mayBeEnabled(Options->bcfOpt(), M)) {
      add(llvm::createBogusControlFlowPass(Options.get()));
    }

    // decoy 是独立功能域：只由自己的开关/注解/config 决定，不再依赖 BCF。
    // 它必须在 INDBR 之前 —— 诱饵菱形要在间接跳转改写前建好。
    if (Options->decoyOpt()->isEnabled() ||
        Options->mayBeEnabled(Options->decoyOpt(), M)) {
      add(llvm::createDecoyPass(Options.get()));
    }

    // dual 模式走末端管线，其余模式在这里做。
    if (Options->indBrOpt()->mode() != 2)
      add(llvm::createIndirectBranchPass(Options.get(), /*Dual=*/false));

    if (Options->rttiOpt()->isEnabled() ||
        Options->mayBeEnabled(Options->rttiOpt(), M)) {
      add(llvm::createMsRttiEraserPass(Options.get()));
    }

    if (Options->renameOpt()->isEnabled() ||
        Options->mayBeEnabled(Options->renameOpt(), M)) {
      add(llvm::createSymbolRenamePass(Options.get()));
    }

    bool Changed = run(M);

    return Changed;
  }
};
} // namespace llvm

char ObfuscationPassManager::ID = 0;

ModulePass *llvm::createObfuscationPassManager(bool Late) {
  return new ObfuscationPassManager(Late);
}

// Legacy pass registration name must NOT collide with the cl::opt "irobf"
// above: when opt.exe registers this pass at pipeline time, its PassNameParser
// listener turns the pass arg into a literal option and fatals on the clash
// ("Option 'irobf' registered more than once").  The user-facing switch stays
// -irobf; only the legacy pass name becomes "irobf-pm".
INITIALIZE_PASS_BEGIN(ObfuscationPassManager, "irobf-pm", "Enable IR Obfuscation",
                      false, false)
INITIALIZE_PASS_END(ObfuscationPassManager, "irobf-pm", "Enable IR Obfuscation",
                      false, false)