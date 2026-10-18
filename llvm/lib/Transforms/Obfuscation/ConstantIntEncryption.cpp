#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ConstantIntEncryption.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/GlobalStatus.h"
#include "llvm/Transforms/IPO/Attributor.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/CryptoUtils.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <map>
#include <set>
#include <iostream>
#include <algorithm>

#define DEBUG_TYPE "constant-int-encryption"

using namespace llvm;

namespace {

// GEP indices into a struct must stay constant: LLVM's verifier rejects a
// variable index there ("invalid getelementptr indices").  The original
// filter only skipped the pointer operand and the first index, so any
// `p->field` style access (index 2..n into a struct) produced invalid IR that
// crashed later passes.  Walk the indexed type to tell struct indices apart
// from array/vector indices, which may be variable.
static bool isStructGEPIndex(GetElementPtrInst *GEP, unsigned OpIdx) {
  if (OpIdx == 0)
    return false;
  // Operand 1 indexes the pointer itself; the result type is still the source
  // element type.  Operands 2..n walk into that type.
  Type *Ty = GEP->getSourceElementType();
  for (unsigned i = 2; i < OpIdx; ++i) {
    if (auto *ST = dyn_cast<StructType>(Ty)) {
      auto *CI = dyn_cast<ConstantInt>(GEP->getOperand(i));
      if (!CI)
        return true; // Unknown: be conservative and keep the index constant.
      Ty = ST->getElementType(CI->getZExtValue());
    } else if (auto *AT = dyn_cast<ArrayType>(Ty)) {
      Ty = AT->getElementType();
    } else if (auto *VT = dyn_cast<VectorType>(Ty)) {
      Ty = VT->getElementType();
    } else {
      return true;
    }
  }
  return isa<StructType>(Ty);
}

struct ConstantIntEncryption : public FunctionPass {
  static char         ID;
  ObfuscationOptions *ArgsOptions;

  std::unordered_map<Function *, std::vector<Instruction *>> FunctionModifyIRs;
  // Dedup only; iteration always uses the insertion-ordered vector above so
  // output does not depend on pointer addresses (ASLR).
  std::unordered_map<Function *, SmallPtrSet<Instruction *, 16>>
      FunctionModifySeen;


  ConstantIntEncryption(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->ArgsOptions = argsOptions;
  }

  StringRef getPassName() const override {
    return "ConstantIntEncryption";
  }

  bool doInitialization(Module &M) override {
    bool Changed = false;
    for (auto& F : M) {
      const auto opt = ArgsOptions->toObfuscate(ArgsOptions->cieOpt(), &F);
      if (!opt.isEnabled()) {
        continue;
      }
      Changed |= expandConstantExpr(F);
      for (auto& BB : F) {
        for (auto& I : BB) {
          if (I.isEHPad() || isa<AllocaInst>(&I) ||
              isa<IntrinsicInst>(&I) || isa<SwitchInst>(I)||
              I.isAtomic()) {
            continue;
          }
          // Inline asm operands such as "n" require integer constant
          // expressions; replacing them with a decrypted value is rejected by
          // the frontend/verifier.
          if (auto *CB = dyn_cast<CallBase>(&I))
            if (isa<InlineAsm>(CB->getCalledOperand()))
              continue;
          auto CI = dyn_cast<CallInst>(&I);
          auto GEP = dyn_cast<GetElementPtrInst>(&I);
          auto PHI = dyn_cast<PHINode>(&I);

          for (unsigned i = 0; i < (PHI ? PHI->getNumIncomingValues() : I.getNumOperands()); ++i) {
            if (CI && CI->isBundleOperand(i)) {
              continue;
            }
            if (GEP && (i < 2 || GEP->getSourceElementType()->isStructTy())) {
              continue;
            }
            if (PHI && isa<SwitchInst>(PHI->getIncomingBlock(i)->getTerminator())) {
              continue;
            }
            Value* Opr = PHI ? PHI->getIncomingValue(i) : I.getOperand(i);
            auto CTI = dyn_cast<ConstantInt>(Opr);
            if (CTI && CTI->getBitWidth() > 7) {
              if (FunctionModifySeen[&F].insert(&I).second)
                FunctionModifyIRs[&F].push_back(&I);
              break;
            }
          }
        }
      }
    }
    return Changed;
  }

  bool runOnFunction(Function &F) override {
    const auto opt = ArgsOptions->toObfuscate(ArgsOptions->cieOpt(), &F);
    if (!opt.isEnabled()) {
      return false;
    }
    auto& FuncModifyIRs = FunctionModifyIRs[&F];
    if (FuncModifyIRs.empty()) {
      return false;
    }

    // 统计常量出现次数：重复使用的常量在函数入口统一解密一次，
    // 避免每个使用点生成重复的加密全局与解密序列（体积/性能优化）
    std::unordered_map<ConstantInt *, unsigned> ConstUseCount;
    // Deterministic first-use order (module/instruction order), so alloca
    // numbering and PRNG consumption do not depend on hash iteration.
    SmallVector<ConstantInt *, 16> ConstOrder;
    for (auto I : FuncModifyIRs) {
      auto CI = dyn_cast<CallInst>(I);
      auto GEP = dyn_cast<GetElementPtrInst>(I);
      auto PHI = dyn_cast<PHINode>(I);
      for (unsigned i = 0; i < I->getNumOperands(); ++i) {
        if (CI && CI->isBundleOperand(i))
          continue;
        if (GEP && (i < 2 || isStructGEPIndex(GEP, i)))
          continue;
        if (auto CTI = dyn_cast<ConstantInt>(I->getOperand(i))) {
          if (CTI->getBitWidth() < 4)
            continue;
          if (PHI &&
              isa<SwitchInst>(PHI->getIncomingBlock(i)->getTerminator()))
            continue;
          unsigned &Cnt = ConstUseCount[CTI];
          if (Cnt++ == 0)
            ConstOrder.push_back(CTI);
        }
      }
    }

    // 重复常量在函数入口解密一次并缓存
    std::unordered_map<ConstantInt *, AllocaInst *> DedupCache;
    auto &EntryBB = F.getEntryBlock();
    Instruction *AllocaInsertPt = &*EntryBB.begin();
    for (auto *CTI : ConstOrder) {
      if (ConstUseCount[CTI] <= 1)
        continue;
      auto *Ty = CTI->getType();
      auto BitWidth = Ty->getPrimitiveSizeInBits().getFixedValue();
      if (BitWidth < 8)
        continue;
      IRBuilder<NoFolder> AIB(AllocaInsertPt);
      DedupCache[CTI] = AIB.CreateAlloca(Ty, nullptr);
    }

    if (!DedupCache.empty()) {
      Instruction *DecryptPt = nullptr;
      for (auto &I : EntryBB) {
        if (!isa<AllocaInst>(&I)) {
          DecryptPt = &I;
          break;
        }
      }
      if (!DecryptPt)
        DecryptPt = EntryBB.getTerminator();
      for (auto *CTI : ConstOrder) {
        auto CacheIt = DedupCache.find(CTI);
        if (CacheIt == DedupCache.end())
          continue;
        Value *Dec = encryptConstant(CTI, DecryptPt, &*cryptoutils, opt.level());
        IRBuilder<NoFolder> SIB(DecryptPt);
        SIB.CreateAlignedStore(Dec, CacheIt->second, Align{1}, true);
      }
    }

    for (auto I : FuncModifyIRs) {
      auto CI = dyn_cast<CallInst>(I);
      auto GEP = dyn_cast<GetElementPtrInst>(I);
      auto PHI = dyn_cast<PHINode>(I);

      for (unsigned i = 0; i < I->getNumOperands(); ++i) {
        if (CI && CI->isBundleOperand(i)) {
          continue;
        }
        if (GEP && (i < 2 || isStructGEPIndex(GEP, i))) {
          continue;
        }
        Value* Opr = I->getOperand(i);
        if (auto CTI = dyn_cast<ConstantInt>(Opr)) {
          if (CTI->getBitWidth() < 4) {
            continue;
          }
          if (PHI && isa<SwitchInst>(PHI->getIncomingBlock(i)->getTerminator())) {
            continue;
          }

          auto InsertPoint = PHI ?
                               PHI->getIncomingBlock(i)->getTerminator() :
                               I;
          Value *CipherConstant;
          auto CacheIt = DedupCache.find(CTI);
          if (CacheIt != DedupCache.end()) {
            IRBuilder<NoFolder> IRB(InsertPoint);
            CipherConstant = IRB.CreateAlignedLoad(
                CTI->getType(), CacheIt->second, Align{1}, true);
          } else {
            CipherConstant = encryptConstant(CTI, InsertPoint, &*cryptoutils, opt.level());
          }
          if (PHI)
            PHI->setIncomingValue(i, CipherConstant);
          else
            I->setOperand(i, CipherConstant);
        }
      }
    }
    return true;
  }
};
} // namespace llvm

char ConstantIntEncryption::ID = 0;

FunctionPass *llvm::createConstantIntEncryptionPass(
    ObfuscationOptions *argsOptions) {
  return new ConstantIntEncryption(argsOptions);
}

INITIALIZE_PASS(ConstantIntEncryption, "cie",
                "Enable IR Constant Integer Encryption", false, false)