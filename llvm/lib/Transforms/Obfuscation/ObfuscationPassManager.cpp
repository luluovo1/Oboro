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
  cl::desc("Randomise MSVC RTTI type-descriptor names (structure kept)."),
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

// 结构性后处理：wrap / shuffle / split。裸开关沿用 config（默认只开 wrap）。
// shuffle 与 split 是实验性的：IR 里的块顺序和块切分都不等于最终布局，
// 后端 MachineBlockPlacement / BranchFolding 会重新排块、把单前驱单后继
// 的块合回去，所以这两项的效果无法从 IR 层保证。必须显式写出来才开。
static cl::opt<std::string> EnableAux(
    "irobf-aux", cl::init(""), cl::ValueOptional, cl::NotHidden,
    cl::desc("Structural passes. Optional comma list: wrap,shuffle,split. "
             "No value = wrap only; shuffle and split are experimental and "
             "must be named explicitly."),
    cl::ZeroOrMore);

// 逗号列表里是否含某项。空列表（不带值）不含任何项：wrap 由调用方单独
// 兜底，shuffle/split 必须显式列出。
static bool auxHas(StringRef List, StringRef Name) {
  if (List.empty())
    return false;
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
  if (V > 100) {
    llvm::errs() << "warning: \"" << S << "\" exceeds 100; clamping to 100"
                 << "\n";
    return 100;
  }
  return V;
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

    // 全局强度只是"默认值"：config / 注解里写死的 level 优先。
    // 之前这里无条件覆盖，导致 `-irobf-level=1` 把 config 的 level 3
    // 重置成 1，与 --help 和 USAGE 的说明相反。
    if (isSet(ObfuscationLevel))
      for (auto &O : Opt->getAllOpt())
        if ((O->supportedFields() & F_Level) && !O->levelSet())
          O->setLevel(ObfuscationLevel);

    // indbr：裸开关只启用，保留 config 里的 mode；写了值才改。
    // 否则 `-irobf-indbr` 会把 config 的 mode=full 悄悄降回 table。
    if (isSet(EnableIndirectBr)) {
      Opt->indBrOpt()->setEnable(true);
      StringRef M = EnableIndirectBr.getValue();
      if (!M.empty()) {
        if (M == "table")
          Opt->indBrOpt()->setMode(0);
        else if (M == "full")
          Opt->indBrOpt()->setMode(1);
        else if (M == "dual")
          Opt->indBrOpt()->setMode(2);
        else
          llvm::errs() << "warning: unknown -irobf-indbr value " << M
                       << " (expected table|full|dual); keeping the "
                          "configured mode\n";
      }
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

    // bcf / decoy：带值开关。裸开关只启用，参数沿用 config / 默认值；
    // 只有真的写了值才覆盖——否则 `-irobf-bcf` 会把 config 的 90 重置成 70。
    if (isSet(EnableBogusControlFlow)) {
      StringRef V = EnableBogusControlFlow.getValue();
      if (V.empty()) {
        Opt->bcfOpt()->setEnable(true);
      } else {
        uint32_t S = parseStrength(V, 70);
        Opt->bcfOpt()->setStrength(S);
        // 0 是明确的"关闭"，不能被当成"启用但强度 0"再挂一次 pass。
        Opt->bcfOpt()->setEnable(S > 0);
      }
    }
    if (isSet(EnableDecoy)) {
      StringRef V = EnableDecoy.getValue();
      if (V.empty()) {
        Opt->decoyOpt()->setEnable(true);
      } else {
        uint32_t R = parseStrength(V, 30);
        Opt->decoyOpt()->setDecoy(R);
        Opt->decoyOpt()->setEnable(R > 0);
      }
    }

    // aux：逗号列表控制三项子功能。裸开关只启用，子项沿用 config /
    // 默认值（默认只有 wrap）；写了列表才按列表重设。
    if (isSet(EnableAux)) {
      Opt->auxOpt()->setEnable(true);
      StringRef AuxList = EnableAux.getValue();
      if (!AuxList.empty()) {
        Opt->auxOpt()->setWrap(auxHas(AuxList, "wrap") ? 100 : 0);
        Opt->auxOpt()->setShuffle(auxHas(AuxList, "shuffle"));
        Opt->auxOpt()->setSplitCount(auxHas(AuxList, "split") ? 3 : 0);
      }
    }

    // 显式打开但参数为 0：不会保护任何站点，报出来而不是静默空转。
    if (Opt->bcfOpt()->isEnabled() && Opt->bcfOpt()->strength() == 0)
      llvm::errs() << "warning: \"bcf\" is enabled but strength is 0; "
                      "no site will be protected\n";
    if (Opt->decoyOpt()->isEnabled() && Opt->decoyOpt()->decoy() == 0)
      llvm::errs() << "warning: \"decoy\" is enabled but ratio is 0; "
                      "no site will be protected\n";

    // aux 开了却三项全关：不报会变成静默空转。
    if (Opt->auxOpt()->isEnabled() && Opt->auxOpt()->wrap() == 0 &&
        !Opt->auxOpt()->shuffle() && Opt->auxOpt()->splitCount() == 0) {
      llvm::errs()
          << "warning: \"aux\" is enabled but wrap/shuffle/split are all "
             "off; nothing to do\n";
    }

    // 实验性提示：这两项在 IR 层做了改动，但最终布局由后端和链接器决定，
    // 无法从产物保证效果。用一次告警代替文档里的脚注。
    if (Opt->auxOpt()->isEnabled() &&
        (Opt->auxOpt()->shuffle() || Opt->auxOpt()->splitCount() > 0)) {
      llvm::errs()
          << "warning: aux.shuffle / aux.split are experimental: basic block "
             "order and splits are not preserved by the backend "
             "(MachineBlockPlacement / BranchFolding) or the linker, so the "
             "final binary may not reflect them\n";
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
      // INDBR 的三种模式都必须在这里跑：在 PipelineStart 跑，O1+ 的
      // SimplifyCFG 会把单目标 indirectbr 折回 br、合并块（实测 39 个
      // 分支只剩 13 个），full 模式等于白开。
      const bool WantIndBr =
          Options->mayBeEnabled(Options->indBrOpt(), M);
      const bool WantDual = WantIndBr && Options->indBrOpt()->mode() == 2;
      if (!WantShuffle && !WantSplit && !WantIndBr)
        return false;
      if (!Options->randomSeed().empty())
        cryptoutils->prng_seed(std::string(Options->randomSeed()));
      // 先切块，再做间接化（SplitAllCriticalEdges 也会新增块），最后乱序：
      // 顺序反过来会让新插入的块破坏已随机化的布局。
      if (WantSplit)
        add(llvm::createSplitBlocksPass(Options.get(),
                                        Options->auxOpt()->splitCount()));
      if (WantIndBr)
        add(llvm::createIndirectBranchPass(Options.get(), /*Dual=*/WantDual));
      if (WantShuffle)
        add(llvm::createShuffleBlocksPass(Options.get()));
      return run(M);
    }

    if (isSet(EnableIndirectBr) || isSet(EnableIndirectCall) ||
        isSet(EnableIndirectGV) || isSet(EnableIRFlattening) ||
        isSet(EnableIRStringEncryption) ||
        isSet(EnableIRConstantIntEncryption) ||
        isSet(EnableIRConstantFPEncryption) || isSet(EnableRttiEraser) ||
        isSet(EnableBogusControlFlow) || isSet(EnableDecoy) ||
        isSet(EnableAux) ||
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

    // INDBR 全部模式都在末端管线跑（见 Late 分支）：在 PipelineStart 跑
    // 会被后续 SimplifyCFG 折回。这里只保留 RTTI 这类模块级收尾。

    if (Options->rttiOpt()->isEnabled() ||
        Options->mayBeEnabled(Options->rttiOpt(), M)) {
      add(llvm::createMsRttiEraserPass(Options.get()));
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