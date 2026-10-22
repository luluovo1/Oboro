#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Transforms/Obfuscation/BogusControlFlow.h"
#include "llvm/Transforms/Obfuscation/DecoyPass.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
// CryptoUtils.h defines a function-like macro `R`, which collides with
// std::function template parameters in CommandLine.h if included earlier.
#include "llvm/CryptoUtils.h"
#undef R


#define DEBUG_TYPE "ir-obfuscation"

using namespace llvm;

static cl::opt<bool>
EnableIRObfuscation("irobf", cl::init(false), cl::NotHidden,
                    cl::desc("Enable IR Code Obfuscation."),
                    cl::ZeroOrMore);


static cl::opt<bool>
EnableIndirectBr("irobf-indbr", cl::init(false), cl::NotHidden,
                 cl::desc("Enable IR Indirect Branch Obfuscation."),
                 cl::ZeroOrMore);
static cl::opt<uint32_t>
LevelIndirectBr("level-indbr", cl::init(0), cl::NotHidden,
                cl::desc("Set IR Indirect Branch Obfuscation Level."),
                cl::ZeroOrMore);


static cl::opt<bool>
EnableIndirectCall("irobf-icall", cl::init(false), cl::NotHidden,
                   cl::desc("Enable IR Indirect Call Obfuscation."),
                   cl::ZeroOrMore);
static cl::opt<uint32_t>
LevelIndirectCall("level-icall", cl::init(0), cl::NotHidden,
                  cl::desc("Set IR Indirect Call Obfuscation Level."),
                  cl::ZeroOrMore);


static cl::opt<bool> EnableIndirectGV(
    "irobf-indgv", cl::init(false), cl::NotHidden,
    cl::desc("Enable IR Indirect Global Variable Obfuscation."),
    cl::ZeroOrMore);
static cl::opt<uint32_t> LevelIndirectGV(
    "level-indgv", cl::init(0), cl::NotHidden,
    cl::desc("Set IR Indirect Global Variable Obfuscation Level."),
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
static cl::opt<uint32_t> LevelIRConstantIntEncryption(
    "level-cie", cl::init(0), cl::NotHidden,
    cl::desc("Set IR Constant Integer Encryption Level."),
    cl::ZeroOrMore);


static cl::opt<bool>
EnableIRConstantFPEncryption("irobf-cfe", cl::init(false), cl::NotHidden,
                             cl::desc("Enable IR Constant FP Encryption."),
                             cl::ZeroOrMore);

static cl::opt<uint32_t> LevelIRConstantFPEncryption(
    "level-cfe", cl::init(0), cl::NotHidden,
    cl::desc("Set IR Constant FP Encryption Level."),
    cl::ZeroOrMore);


static cl::opt<bool>
EnableRttiEraser("irobf-rtti", cl::init(false), cl::NotHidden,
  cl::desc("Enable RTTI Eraser."),
  cl::ZeroOrMore);

// BCF 开关（概率参数 irobf-bcf_prob 定义在 BogusControlFlow.cpp，不在此重复）
static cl::opt<bool>
EnableBogusControlFlow("irobf-bcf", cl::init(false), cl::NotHidden,
  cl::desc("Enable Bogus Control Flow (causes IDA optimizations loop too much)."),
  cl::ZeroOrMore);
// 每函数毒点绝对上限。0 = 不设绝对上限；与百分比同时给出时取较小值。
static cl::opt<uint32_t>
BCFBudget("irobf-bcf_budget", cl::init(0), cl::NotHidden,
          cl::desc("Absolute cap on BCF sites per function "
                   "(0 = no absolute cap). Default: 0"),
          cl::ZeroOrMore);

// 每函数毒点占可插桩块的百分比。0 = 不用百分比（退回绝对上限）；
// 与绝对上限都为 0 时按默认 20%，0 只表示自动，不会放大。
static cl::opt<uint32_t>
BCFBudgetPct("irobf-bcf_budget_pct", cl::init(20), cl::NotHidden,
             cl::desc("Percentage of eligible blocks to protect per "
                      "function, 0-100 (0 = auto: absolute cap, or 20%). "
                      "Default: 20"),
             cl::ZeroOrMore);








static cl::opt<std::string>
OboroConfigPath("oboro-cfg", cl::init(std::string{}), cl::NotHidden,
                 cl::desc("Oboro config path."),
                 cl::ZeroOrMore);

namespace llvm {

struct ObfuscationPassManager : public ModulePass {
  static char            ID; // Pass identification
  SmallVector<Pass *, 8> Passes;

  ObfuscationPassManager() : ModulePass(ID) {
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
    auto Opt = ObfuscationOptions::readConfigFile(OboroConfigPath);

    Opt->indBrOpt()->readOpt(EnableIndirectBr, LevelIndirectBr);
    Opt->iCallOpt()->readOpt(EnableIndirectCall, LevelIndirectCall);
    Opt->indGvOpt()->readOpt(EnableIndirectGV, LevelIndirectGV);
    Opt->flaOpt()->readOpt(EnableIRFlattening);
    Opt->cseOpt()->readOpt(EnableIRStringEncryption);
    Opt->cieOpt()->readOpt(EnableIRConstantIntEncryption,
                           LevelIRConstantIntEncryption);
    Opt->cfeOpt()->readOpt(EnableIRConstantFPEncryption,
                           LevelIRConstantFPEncryption);
    Opt->rttiOpt()->readOpt(EnableRttiEraser);

    Opt->bcfOpt()->readOpt(EnableBogusControlFlow);
    Opt->bcfOpt()->readBudgetOpt(BCFBudget);
    Opt->bcfOpt()->readBudgetPctOpt(BCFBudgetPct);
    // CLI is an explicit opt-in; when absent, the config value stands.
    return Opt;
  }

  bool runOnModule(Module &M) override {

    if (EnableIndirectBr || EnableIndirectCall || EnableIndirectGV ||
        EnableIRFlattening || EnableIRStringEncryption ||
        EnableIRConstantIntEncryption || EnableIRConstantFPEncryption ||
        EnableRttiEraser ||
        EnableBogusControlFlow || !OboroConfigPath.empty()) {
      EnableIRObfuscation = true;
    }

    if (!EnableIRObfuscation) {
      return false;
    }

    const auto Options(getOptions());

    // Reproducible mode (tests / audits / bug reproducers): a config-provided
    // seed fixes the shared AES-CTR stream for every pass in this module.
    // Without it the PRNG seeds itself from time/urandom, so two builds of the
    // same source differ -- which is the intended production behaviour.
    if (!Options->randomSeed().empty()) {
      std::string Seed(Options->randomSeed());
      cryptoutils->prng_seed(Seed);
    }

    unsigned   pointerSize = M.getDataLayout().getTypeAllocSize(
        PointerType::getUnqual(M.getContext()));

    add(llvm::createConstantIntEncryptionPass(Options.get()));

    add(llvm::createConstantFPEncryptionPass(Options.get()));

    // 字符串加密必须在间接全局变量之前：否则 INDGV 先把字符串全局的
    // 使用点改写成页表对象，CSE 认不出这些常量串，导致 full 组合下明文泄露。
    if (EnableIRStringEncryption || Options->cseOpt()->isEnabled()) {
      add(llvm::createStringEncryptionPass(Options.get()));
    }

    add(llvm::createIndirectGlobalVariablePass(Options.get()));

    add(llvm::createIndirectCallPass(Options.get()));
    add(llvm::createFlatteningPass(pointerSize, Options.get()));

    // BCF 必须在 IndirectBranch 之前跑：BCF 在原始 CFG 上做 split+fixStack
    // 是线性的；若 indbr 先把条件分支全部换成 indirectbr，BCF 再在其上
    // split 会引发后端寄存器分配/EH 准备的组合爆炸（实测编译卡死）。
    // pattern / 函数注解也可能单独开启 BCF（config 统一管理），
    // 因此用 mayBeEnabled 判断，而不是只看全局开关。
    if (EnableBogusControlFlow ||
        Options->mayBeEnabled(Options->bcfOpt(), M)) {
      add(llvm::createBogusControlFlowPass(Options.get()));
      // DecoyPass 绑定 BCF 开关（用户侧零变化：-irobf-bcf + config decoy
      // 声明即生效）。资格门在 pass 内：无注解/config 声明时空转。
      // 顺序：BCF 先（纯 poison）、Decoy 后（env 菱形 + poison 混合），
      // 两者都在 INDBR 之前 —— 菱形必须在间接跳转改写前建好。
      add(llvm::createDecoyPass(Options.get()));
    }

    add(llvm::createIndirectBranchPass(Options.get()));

    if (EnableRttiEraser || Options->rttiOpt()->isEnabled()) {
      add(llvm::createMsRttiEraserPass(Options.get()));
    }


    bool Changed = run(M);

    return Changed;
  }
};
} // namespace llvm

char ObfuscationPassManager::ID = 0;

ModulePass *llvm::createObfuscationPassManager() {
  return new ObfuscationPassManager();
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