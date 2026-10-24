//===- Flattening.cpp - Flattening Obfuscation pass------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the flattening pass
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Transforms/Obfuscation/Flattening.h"
#include "llvm/Transforms/Obfuscation/LegacyLowerSwitch.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/CryptoUtils.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"

#include <memory>
#include <random>

#define DEBUG_TYPE "flattening"

using namespace std;
using namespace llvm;

// Stats
STATISTIC(Flattened, "Functions flattened");

namespace {
struct Flattening : public FunctionPass {
  unsigned    pointerSize;
  static char ID; // Pass identification, replacement for typeid

  ObfuscationOptions *ArgsOptions;

  // 运行时密钥锚点：一个模块内私有全局。它的地址在加载时由 ASLR 决定，
  // 静态分析拿不到，块级密钥因此无法在编译期求值。
  GlobalVariable *Anchor = nullptr;

  Flattening(unsigned            pointerSize,
             ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->pointerSize = pointerSize;
    this->ArgsOptions = argsOptions;
  }

  bool doInitialization(Module &M) override;
  bool runOnFunction(Function &F) override;
  bool flatten(Function *f, const ObfOpt &opt);
};
}

bool Flattening::doInitialization(Module &M) {
  if (Anchor)
    return false;
  // 一个字节的私有全局，只用来提供模块基址。不读写内容，所以不影响行为；
  // 命名走随机层，生产产物里没有固定特征串。
  auto &Ctx = M.getContext();
  Anchor = new GlobalVariable(
      M, Type::getInt8Ty(Ctx), /*isConstant=*/false,
      GlobalValue::InternalLinkage, ConstantInt::get(Type::getInt8Ty(Ctx), 0),
      obf::freshName(M, "anchor"));
  Anchor->setAlignment(Align(1));
  return false;
}

bool Flattening::runOnFunction(Function &F) {
  if (F.isIntrinsic()) {
    return false;
  }
  // setjmp/longjmp 会把寄存器和栈恢复到 setjmp 点。FLA 的 state 变量
  // 在 longjmp 之后回退到旧值，分发器会跳到错误的 case，轻则语义错误，
  // 重则死循环。含 returns_twice 调用的函数必须原样保留。
  if (F.callsFunctionThatReturnsTwice()) {
    return false;
  }
  Function *tmp = &F;
  bool      result = false;
  // Do we obfuscate
  const auto opt = ArgsOptions->toObfuscate(ArgsOptions->flaOpt(), &F);
  if (!opt.isEnabled()) {
    return result;
  }
  if (flatten(tmp, opt)) {
    ++Flattened;
    result = true;
  }

  return result;
}

bool Flattening::flatten(Function *f, const ObfOpt &opt) {
  vector<BasicBlock *> origBB;

  // 平坦化后的代码会让 SLPVectorizer 的组合搜索爆炸：zlib 的 inflate_table
  // 只有 53 块，平坦化后 180 块，O2 下 SLP 卡 40s 以上。
  // 阈值取 50 块：超过这个规模的函数本身就属于"膨胀函数"，平坦化收益低、
  // 编译代价高，直接跳过。
  static constexpr unsigned MaxFlattenBlocks = 50;
  if (f->size() > MaxFlattenBlocks)
    return false;

  // 在 LowerSwitch 之前验证 CFG：lower 会改写函数，即使后续 flatten
  // 失败也不可逆；EH / invoke / callbr / indirectbr 一律拒绝。
  for (BasicBlock &BB : *f) {
    Instruction *Term = BB.getTerminator();
    if (BB.isEHPad() || isa<InvokeInst, CallBrInst, IndirectBrInst>(Term))
      return false;
  }

  // LowerSwitch and the flattening walk assume a reachable CFG.  A function
  // containing an unreachable cycle makes the rewrite non-terminating, so
  // refuse it instead of burning compile time (or hanging the build).
  {
    DominatorTree DT(*f);
    for (BasicBlock &BB : *f)
      if (!DT.isReachableFromEntry(&BB))
        return false;
  }

  // Flattening moves every block into a dispatch loop.  Allocas that are not
  // at the top of the entry block (or that live in other blocks) can end up in
  // a different case than their uses, breaking dominance.  Only flatten when
  // all allocas are the leading instructions of the entry block.
  bool SeenNonAlloca = false;
  for (Instruction &I : f->getEntryBlock()) {
    if (isa<AllocaInst>(I)) {
      if (SeenNonAlloca)
        return false;
    } else {
      SeenNonAlloca = true;
    }
  }
  for (BasicBlock &BB : *f) {
    if (&BB == &f->getEntryBlock())
      continue;
    for (Instruction &I : BB)
      if (isa<AllocaInst>(I))
        return false;
  }

  auto &Ctx = f->getContext();
  auto  intType = Type::getInt32Ty(Ctx);

  if (pointerSize == 8) {
    intType = Type::getInt64Ty(Ctx);
  }
  auto *IntTy = cast<IntegerType>(intType);

  // 随机数源（保留 CryptoUtils 架构）
  auto randWord = [&]() -> uint64_t {
    uint64_t v = cryptoutils->get_uint64_t();
    if (pointerSize != 8)
      v &= 0xffffffffull;
    return v;
  };

  // Lower switch
  auto lower = std::unique_ptr<FunctionPass>(createLegacyLowerSwitchPass());
  lower->runOnFunction(*f);

  // Save all original BB
  for (auto i = f->begin(); i != f->end(); ++i) {
    auto bb = &*i;
    origBB.push_back(bb);
  }

  // Nothing to flatten
  if (origBB.size() <= 1) {
    return false;
  }

  // Remove first BB
  origBB.erase(origBB.begin());

  // Get a pointer on the first BB
  auto insertBlock = &*(f->begin());
  auto splitPos = insertBlock->getFirstNonPHIOrDbgOrAlloca();

  std::mt19937_64 re(cryptoutils->get_uint64_t());
  std::shuffle(origBB.begin(), origBB.end(), re);

  auto bbEndOfEntry = insertBlock->splitBasicBlock(splitPos, "first");
  origBB.insert(origBB.begin(), bbEndOfEntry);

  // 随机 case 表：每块一个非零且唯一的随机 case 值
  DenseSet<uint64_t>                    UsedCases;
  DenseMap<BasicBlock *, ConstantInt *> CaseVal;
  for (BasicBlock *BB : origBB) {
    uint64_t v;
    do {
      v = randWord();
    } while (v == 0 || UsedCases.count(v));
    UsedCases.insert(v);
    CaseVal[BB] = ConstantInt::get(IntTy, v);
  }
  ConstantInt *EntryCase = CaseVal[bbEndOfEntry];

  // Remove jump
  insertBlock->getTerminator()->eraseFromParent();

  // Create switch variable and set as it
  IRBuilder<> IRB{insertBlock};
  const auto  switchVar =
      IRB.CreateAlloca(intType, nullptr, obf::freshName(*f->getParent(), "sv"));

  // 运行时密钥种子 = 模块基址 ^ 栈地址 ^ 函数常量。
  //   - 模块基址：ASLR 决定，静态只有偏移
  //   - 栈地址：每次调用不同
  // 两者都不是编译期常量，所以由它们派生的密钥无法静态求值。
  //
  // 密钥每轮滚动：K_{i+1} = mix(K_i)。密钥全程走 PHI/寄存器，不写内存
  // ——一旦落进 alloca，它就会和密文同时出现在内存里，单次内存快照
  // 就能解出当轮的状态转移，滚动就白做了。
  Value *Key0 = nullptr;
  {
    Value *ModAddr = IRB.CreatePtrToInt(Anchor, intType);
    Value *StkAddr = IRB.CreatePtrToInt(switchVar, intType);
    Key0 = IRB.CreateXor(ModAddr, StkAddr);
    Key0 = IRB.CreateXor(Key0, ConstantInt::get(IntTy, randWord()));
  }

  // init：Encoded = EntryCase ^ Key0
  Value *entryEnc = IRB.CreateXor(EntryCase, Key0);
  IRB.CreateStore(entryEnc, switchVar, true);

  // Create main loop

  auto bbKey = BasicBlock::Create(f->getContext(), "keyHead", f, insertBlock);
  auto bbLoopEntry = BasicBlock::Create(f->getContext(), "loopEntry", f,
                                        insertBlock);
  auto bbLoopEnd = BasicBlock::Create(f->getContext(), "loopEnd", f,
                                      insertBlock);

  // 每轮滚动的混合函数：K_{i+1} = mix(K_i) ^ (C_i * B)。
  // C_i 是当轮的状态值，所以密钥演化绑定在执行路径上——同一把密钥走到
  // 不同分支会得到不同后续，只凭一次抓取无法把整条密钥序列推完。
  // 乘 + 移位 + 异或 + 加，四种展开随机选一种，避免整个产物只有一种
  // 可批量匹配的演化签名。
  //
  // 注意不能写成 mix(K ^ C)：C = enc ^ K，先异或会被折叠成 enc，
  // 密钥就从式子里消失了（实测 InstCombine 会做这个化简）。
  auto buildRoll = [&](IRBuilder<> &B, Value *K, Value *State) -> Value * {
    ConstantInt *Mul = ConstantInt::get(IntTy, randWord() | 1u);
    ConstantInt *Add = ConstantInt::get(IntTy, randWord());
    unsigned     Bits = IntTy->getBitWidth();
    unsigned     Sh = 1 + static_cast<unsigned>(randWord() % (Bits - 2));
    ConstantInt *Shift = ConstantInt::get(IntTy, Sh);
    Value *      Core = nullptr;
    switch (randWord() & 3u) {
    case 0: {
      Value *M = B.CreateMul(K, Mul);
      Value *R = B.CreateLShr(K, Shift);
      Core = B.CreateAdd(B.CreateXor(M, R), Add);
      break;
    }
    case 1: {
      Value *X = B.CreateXor(K, B.CreateLShr(K, Shift));
      Core = B.CreateXor(B.CreateMul(X, Mul), Add);
      break;
    }
    case 2: {
      Value *X = B.CreateXor(K, B.CreateShl(K, Shift));
      Core = B.CreateAdd(B.CreateMul(X, Mul), Add);
      break;
    }
    default: {
      Value *M = B.CreateMul(K, Mul);
      Value *R = B.CreateLShr(M, Shift);
      Core = B.CreateXor(B.CreateAdd(M, Add), R);
      break;
    }
    }
    ConstantInt *Bind = ConstantInt::get(IntTy, randWord() | 1u);
    return B.CreateXor(Core, B.CreateMul(State, Bind));
  };

  // 密钥回边：keyHead 持有当前轮密钥，loopEntry 解码后算出下一轮密钥。
  IRB.SetInsertPoint(bbKey);
  PHINode *KeyPhi = IRB.CreatePHI(intType, 2, "key");
  KeyPhi->addIncoming(Key0, insertBlock);
  IRB.CreateBr(bbLoopEntry);

  IRB.SetInsertPoint(bbLoopEntry);
  Value *enc0 = IRB.CreateLoad(intType, switchVar, "switchVar.enc0");
  Value *switchCondition = IRB.CreateXor(enc0, KeyPhi, "switchCond");
  Value *NextKey = buildRoll(IRB, KeyPhi, switchCondition);

  // 这几个值必须留在寄存器里。fixStack 会把所有跨块 SSA 值降级到栈，
  // 密钥一旦落进 alloca，它就会和密文同时出现在内存中，单次内存快照
  // 就能解出当轮转移。打标记让 fixStack 跳过它们。
  MDNode *KeepInReg = MDNode::get(Ctx, {});
  cast<Instruction>(Key0)->setMetadata("oboro.keep", KeepInReg);
  KeyPhi->setMetadata("oboro.keep", KeepInReg);
  cast<Instruction>(NextKey)->setMetadata("oboro.keep", KeepInReg);

  // Move first BB on top
  insertBlock->moveBefore(bbKey);
  BranchInst::Create(bbKey, insertBlock);

  // loopEnd 回边：把本轮算出的下一把密钥带回 PHI。
  KeyPhi->addIncoming(NextKey, bbLoopEnd);
  BranchInst::Create(bbKey, bbLoopEnd);

  auto swDefault = BasicBlock::Create(f->getContext(), "switchDefault", f,
                                      bbLoopEnd);
  BranchInst::Create(bbLoopEnd, swDefault);

  // Create switch instruction itself and set condition
  auto switchI = SwitchInst::Create(&*f->begin(), swDefault, 0, bbLoopEntry);
  switchI->setCondition(switchCondition);

  // Remove branch jump from 1st BB and make a jump to the while
  f->begin()->getTerminator()->eraseFromParent();

  BranchInst::Create(bbKey, &*f->begin());

  // Put all BB in the switch（case 值使用纯随机表）
  for (auto bi = origBB.begin(); bi != origBB.end(); ++bi) {
    auto bb = *bi;

    // Move the BB inside the switch (only visual, no code logic)
    bb->moveBefore(bbLoopEnd);

    switchI->addCase(CaseVal[bb], bb);
  }

  // Recalculate switchVar
  for (auto bi = origBB.begin(); bi != origBB.end(); ++bi) {
    const auto bb = *bi;

    // Ret BB
    if (bb->getTerminator()->getNumSuccessors() == 0) {
      continue;
    }

    IRB.SetInsertPoint(bb->getTerminator());

    auto writeNextEncoded = [&](Value *NextCaseVal) {
      // 只写密文：NextEnc = NextCase ^ NextKey。密钥不落内存。
      Value *nextEnc = IRB.CreateXor(NextCaseVal, NextKey);

      IRB.CreateStore(nextEnc, switchVar, true);

      IRB.CreateBr(bbLoopEnd);
      bb->getTerminator()->eraseFromParent();
    };

    // If it's a non-conditional jump
    if (bb->getTerminator()->getNumSuccessors() == 1) {
      auto tbb = bb->getTerminator()->getSuccessor(0);

      Value *nextCase = nullptr;
      if (CaseVal.count(tbb)) {
        nextCase = CaseVal[tbb];
      } else {
        nextCase = EntryCase;
      }

      writeNextEncoded(nextCase);
      continue;
    }

    // If it's a conditional jump
    if (bb->getTerminator()->getNumSuccessors() == 2) {
      auto br = cast<BranchInst>(bb->getTerminator());
      auto succT = br->getSuccessor(0);
      auto succF = br->getSuccessor(1);

      Value *caseT = CaseVal.count(succT) ? CaseVal[succT] : EntryCase;
      Value *caseF = CaseVal.count(succF) ? CaseVal[succF] : EntryCase;

      Value *selectedCase =
          IRB.CreateSelect(br->getCondition(), caseT, caseF, "nextCase");

      writeNextEncoded(selectedCase);
      continue;
    }
  }

  fixStack(f);

  lower->runOnFunction(*f);

  return true;
}

char                            Flattening::ID = 0;
static RegisterPass<Flattening> X("flattening", "Call graph flattening");

FunctionPass *llvm::createFlatteningPass(unsigned            pointerSize,
                                         ObfuscationOptions *argsOptions) {
  return new Flattening(pointerSize, argsOptions);
}