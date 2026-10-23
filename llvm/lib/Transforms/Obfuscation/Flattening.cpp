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
#include "llvm/IR/IRBuilder.h"

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

  Flattening(unsigned            pointerSize,
             ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->pointerSize = pointerSize;
    this->ArgsOptions = argsOptions;
  }

  bool runOnFunction(Function &F) override;
  bool flatten(Function *f, const ObfOpt &opt);
};
}

bool Flattening::runOnFunction(Function &F) {
  if (F.isIntrinsic()) {
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

  auto randConst = [&]() -> ConstantInt * {
    return ConstantInt::get(IntTy, randWord());
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
  const auto  switchVar = IRB.CreateAlloca(intType, nullptr, "switchVar");
  const auto  switchXorVar = IRB.CreateAlloca(intType, nullptr, "switchXor");

  // init：Encoded = EntryCase ^ XorKey
  ConstantInt *entryXor = randConst();
  Value *      entryEnc = IRB.CreateXor(EntryCase, entryXor);
  IRB.CreateStore(entryEnc, switchVar, true);
  IRB.CreateStore(entryXor, switchXorVar, true);

  // Create main loop

  auto bbLoopEntry = BasicBlock::Create(f->getContext(), "loopEntry", f,
                                        insertBlock);
  auto bbLoopEnd = BasicBlock::Create(f->getContext(), "loopEnd", f,
                                      insertBlock);
  IRB.SetInsertPoint(bbLoopEntry);
  Value *enc0 = IRB.CreateLoad(intType, switchVar, "switchVar.enc0");
  Value *xor0 = IRB.CreateLoad(intType, switchXorVar, "switchXor.xor0");

  // rolling delta：enc/xor 双变量每轮同时滚动，存储值每轮都在变
  ConstantInt *delta = randConst();
  Value *enc1 = IRB.CreateXor(enc0, delta, "switchVar.enc1");
  Value *xor1 = IRB.CreateXor(xor0, delta, "switchXor.xor1");
  IRB.CreateStore(enc1, switchVar, true);
  IRB.CreateStore(xor1, switchXorVar, true);
  Value *switchCondition = IRB.CreateXor(enc1, xor1, "switchCond");
  // Move first BB on top
  insertBlock->moveBefore(bbLoopEntry);
  BranchInst::Create(bbLoopEntry, insertBlock);

  // loopEnd jump to loopEntry
  BranchInst::Create(bbLoopEntry, bbLoopEnd);

  auto swDefault = BasicBlock::Create(f->getContext(), "switchDefault", f,
                                      bbLoopEnd);
  BranchInst::Create(bbLoopEnd, swDefault);

  // Create switch instruction itself and set condition
  auto switchI = SwitchInst::Create(&*f->begin(), swDefault, 0, bbLoopEntry);
  switchI->setCondition(switchCondition);

  // Remove branch jump from 1st BB and make a jump to the while
  f->begin()->getTerminator()->eraseFromParent();

  BranchInst::Create(bbLoopEntry, &*f->begin());

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
      // NextEnc = NextCase ^ NewXor
      ConstantInt *newXor = randConst();
      Value *      nextEnc = IRB.CreateXor(NextCaseVal, newXor);

      IRB.CreateStore(nextEnc, switchVar, true);
      IRB.CreateStore(newXor, switchXorVar, true);

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