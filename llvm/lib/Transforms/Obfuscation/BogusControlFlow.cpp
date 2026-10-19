// BogusControlFlow.cpp
// BCF (Bogus Control Flow) pass —— 纯静态虚假控制流。
//
// 原理：对每个 BasicBlock 以不透明谓词（永为真，但IDA静态分析无法证伪）为条件
// 制造菱形分支结构：
//
//   EntryBB
//    |        \
//    v         v
//  OrigBB   BogBB（垃圾指令） --> OrigBB
//    |       /
//    v      /
//  [SuccBB]
//
// IDA 静态分析会把 BogBB 当作可达路径，引入大量额外分析节点，
// 触发 Hex-Rays "optimizations loop too much" 或显著降低反编译质量。
//
// 谓词引擎 / 命名卫生 / 毒载荷 / 站点拓扑在 BcfShared.cpp（与 DecoyPass
// 共用）。decoy（运行时误导机制）是独立 pass：decoy>0 的函数由 DecoyPass
// 全权处理，本 pass 让位（见 runOnFunction）。

// ---- 先包含所有 LLVM 头文件，防止 CryptoUtils.h 的宏污染它们 ----
#include "llvm/Transforms/Obfuscation/BogusControlFlow.h"
#include "llvm/Transforms/Obfuscation/BcfShared.h"
#include "llvm/Transforms/Obfuscation/DecoyPass.h"
#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/EHPersonalities.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/ADT/SmallVector.h"

// ---- CryptoUtils 最后包含，避免其 R/S/Maj/Ch 等宏污染上方头文件 ----
#include "llvm/CryptoUtils.h"
// CryptoUtils.h 为 SHA256 定义了大量单字母/短名宏，会与 APInt.h 等冲突，立即清理
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

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

using namespace llvm;

// 混淆概率：0-100，默认 70。用 -mllvm -irobf-bcf_prob=X 覆盖。
static cl::opt<unsigned>
    BCFProb("irobf-bcf_prob", cl::init(70), cl::NotHidden,
            cl::desc("Probability (0-100) that each basic block gets BCF "
                     "applied. Default: 70"),
            cl::ZeroOrMore);

namespace {

struct BogusControlFlow : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;

  BogusControlFlow(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->ArgsOptions = argsOptions;
  }

  StringRef getPassName() const override { return "BogusControlFlow"; }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration() || F.isIntrinsic())
      return false;

    // 工具链自己的运行时函数绝不参与混淆（防递归/自污染）。
    Module *M = F.getParent();
    if (F.getMetadata(obf::metaName(*M, "noobf")) ||
        obf::isRuntimeFunction(*M, F))
      return false;
    // 项目提供的 probe 是 DecoyPass 的策略入口，绝不能反过来被插桩
    // （否则 probe -> getenv -> 混淆函数 -> probe 递归）。
    if (F.getName() == getDecoyProbeSymbol())
      return false;

    // 特殊函数：改动它们会破坏 ABI/异常/协程/尾调用语义。
    // 注意：optnone 不在此列 —— clang -O0 会给所有函数加 optnone，
    // 若跳过它，-O0 构建将完全无法混淆（实测回归）。optnone 只是
    // "优化器不要动"，BCF 插入菱形不依赖优化，语义安全。
    if (F.hasFnAttribute(Attribute::Naked) ||
        F.hasFnAttribute(Attribute::ReturnsTwice) ||
        F.isPresplitCoroutine())
      return false;
    for (Instruction &I : instructions(F)) {
      if (isa<CallBrInst>(I))
        return false;
      if (auto *CI = dyn_cast<CallInst>(&I))
        if (CI->isMustTailCall())
          return false;
    }

    // 弱符号（STL 模板实例化等）/ 运行时胶水 / 静态初始化 / 构造析构 /
    // 运算符等红黄区函数的跳过已统一收敛到
    // ObfuscationOptions::toObfuscate()（安全底线），此处不再单独判断。

    // scoped EH（WinEH / Wasm funclets）仍然整体跳过：funclet 内的调用必须
    // 携带 funclet operand bundle，菱形跨越 funclet 边界的成本与风险不可控。
    // Itanium EH（Android/Linux）只跳过 landingpad/EH pad 块本身，普通块尾部
    // 插入菱形不会修改 unwind 边，也不会改变 LSDA 的 call-site 范围。
    if (F.hasPersonalityFn() &&
        isScopedEHPersonality(classifyEHPersonality(F.getPersonalityFn())))
      return false;

    // 检查是否对此函数应用 BCF
    auto Opt = ArgsOptions->toObfuscate(ArgsOptions->bcfOpt(), &F);
    if (!Opt.isEnabled())
      return false;

    // 让位规则：decoy 资格函数由 DecoyPass 全权处理（decoy 菱形 + 按
    // DecoyPct 混入 poison 形态），本 pass 不碰，避免双重插桩与二次
    // fixStack（同一函数只允许一个 pass 改动 CFG）。
    if (Opt.decoy() > 0)
      return false;

    bool Changed = false;

    // 收集所有合法的目标块（快照，防止迭代时被修改）
    SmallVector<BasicBlock *, 16> Targets;
    for (BasicBlock &BB : F) {
      if (BB.isLandingPad() || BB.isEHPad())
        continue;
      // 只处理有正常终止指令且无 invoke/landingpad 的块
      if (BB.size() < 2)
        continue;
      Instruction *Term = BB.getTerminator();
      if (isa<ReturnInst>(Term) || isa<BranchInst>(Term) ||
          isa<SwitchInst>(Term))
        Targets.push_back(&BB);
    }

    // 随机采样：顺序取前 N 会让大函数只有前部受保护，且"哪些块被选中"
    // 本身是稳定指纹。先洗牌再按概率过滤，站点分布不再与块顺序相关。
    for (unsigned I = Targets.size(); I > 1; --I) {
      unsigned J = cryptoutils->get_uint32_t() % I;
      std::swap(Targets[I - 1], Targets[J]);
    }

    unsigned Prob = BCFProb.getValue();
    if (Prob > 100)
      Prob = 100;

    // 每函数 BCF 处理块数上限：iostream 等展开的巨型函数有几百个块，
    // 全块 BCF + fixStack 全函数 demote 会让编译时间爆炸。每函数 16 个
    // 毒点对 IDA/Hex-Rays 的破坏效果已经足够。
    unsigned MaxBlocks = 16;

    for (BasicBlock *BB : Targets) {
      if (MaxBlocks == 0)
        break;
      if ((cryptoutils->get_uint32_t() % 100) >= Prob)
        continue;
      if (bcfApplyTopology(BB, F)) {
        Changed = true;
        --MaxBlocks;
      }
    }

    if (Changed) {
      fixStack(&F);
    }

    return Changed;
  }
};

} // anonymous namespace

char BogusControlFlow::ID = 0;

FunctionPass *llvm::createBogusControlFlowPass(ObfuscationOptions *argsOptions) {
  return new BogusControlFlow(argsOptions);
}
