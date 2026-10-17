#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/EHPersonalities.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/CryptoUtils.h"

#include <random>
#include <algorithm>

// Shamefully borrowed from ../Scalar/RegToMem.cpp :(
bool valueEscapes(Instruction *Inst) {
  BasicBlock *BB = Inst->getParent();
  for (Value::use_iterator UI = Inst->use_begin(), E = Inst->use_end(); UI != E;
       ++UI) {
    Instruction *I = cast<Instruction>(*UI);
    if (I->getParent() != BB || isa<PHINode>(I)) {
      return true;
    }
  }
  return false;
}

void fixStack(Function *f) {
  // Try to remove phi node and demote reg to stack
  std::vector<PHINode *>     tmpPhi;
  std::vector<Instruction *> tmpReg;
  BasicBlock *               bbEntry = &*f->begin();

  do {
    tmpPhi.clear();
    tmpReg.clear();

    for (Function::iterator i = f->begin(); i != f->end(); ++i) {

      for (BasicBlock::iterator j = i->begin(); j != i->end(); ++j) {

        if (isa<PHINode>(j)) {
          PHINode *phi = cast<PHINode>(j);
          tmpPhi.push_back(phi);
          continue;
        }
        if (!(isa<AllocaInst>(j) && j->getParent() == bbEntry) &&
            (valueEscapes(&*j) || j->isUsedOutsideOfBlock(&*i))) {
          tmpReg.push_back(&*j);
          continue;
        }
      }
    }
    for (unsigned int i = 0; i != tmpReg.size(); ++i) {
      DemoteRegToStack(*tmpReg.at(i));
    }

    for (unsigned int i = 0; i != tmpPhi.size(); ++i) {
      DemotePHIToStack(tmpPhi.at(i));
    }

  } while (tmpReg.size() != 0 || tmpPhi.size() != 0);
}

CallBase* fixEH(CallBase* CB) {
  const auto BB = CB->getParent();
  if (!BB) {
    return CB;
  }
  const auto Fn = BB->getParent();
  if (!Fn || !Fn->hasPersonalityFn()
    || !isScopedEHPersonality(classifyEHPersonality(Fn->getPersonalityFn()))) {
    return CB;
  }
  const auto BlockColors = colorEHFunclets(*Fn);
  const auto BBColor = BlockColors.find(BB);
  if (BBColor == BlockColors.end()) {
    return CB;
  }
  const auto& ColorVec = BBColor->getSecond();
  assert(ColorVec.size() == 1 && "non-unique color for block!");

  const auto EHBlock = ColorVec.front();
  if (!EHBlock || !EHBlock->isEHPad()) {
    return CB;
  }
  const auto EHPad = EHBlock->getFirstNonPHI();

  const OperandBundleDef OB("funclet", EHPad);
  auto *NewCall = CallBase::addOperandBundle(CB, LLVMContext::OB_funclet, OB, CB);
  NewCall->copyMetadata(*CB);
  CB->replaceAllUsesWith(NewCall);
  CB->eraseFromParent();
  return NewCall;
}

void LowerConstantExpr(Function &F) {
  SmallPtrSet<Instruction *, 8> WorkList;

  for (inst_iterator It = inst_begin(F), E = inst_end(F); It != E; ++It) {
    Instruction *I = &*It;

    if (isa<LandingPadInst>(I) || isa<CatchPadInst>(I) || isa<
          CatchSwitchInst>(I) || isa<CatchReturnInst>(I))
      continue;
    if (auto *II = dyn_cast<IntrinsicInst>(I)) {
      if (II->getIntrinsicID() == Intrinsic::eh_typeid_for) {
        continue;
      }
    }

    for (unsigned int i = 0; i < I->getNumOperands(); ++i) {
      if (isa<ConstantExpr>(I->getOperand(i)))
        WorkList.insert(I);
    }
  }

  while (!WorkList.empty()) {
    auto         It = WorkList.begin();
    Instruction *I = *It;
    WorkList.erase(*It);

    if (PHINode *PHI = dyn_cast<PHINode>(I)) {
      for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
        Instruction *TI = PHI->getIncomingBlock(i)->getTerminator();
        if (ConstantExpr *CE = dyn_cast<
          ConstantExpr>(PHI->getIncomingValue(i))) {
          Instruction *NewInst = CE->getAsInstruction();
          NewInst->insertBefore(TI);
          PHI->setIncomingValue(i, NewInst);
          WorkList.insert(NewInst);
        }
      }
    } else {
      for (unsigned int i = 0; i < I->getNumOperands(); ++i) {
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(I->getOperand(i))) {
          Instruction *NewInst = CE->getAsInstruction();
          NewInst->insertBefore(I);
          I->replaceUsesOfWith(CE, NewInst);
          WorkList.insert(NewInst);
        }
      }
    }
  }
}

bool expandConstantExpr(Function &F) {
  bool                Changed = false;
  LLVMContext &       Ctx = F.getContext();
  IRBuilder<NoFolder> IRB(Ctx);

  for (auto &BB : F) {
    for (auto &I : BB) {
      if (I.isEHPad() || isa<AllocaInst>(&I) || isa<IntrinsicInst>(&I) ||
        isa<SwitchInst>(&I) || I.isAtomic()) {
        continue;
      }
      auto CI = dyn_cast<CallInst>(&I);
      auto GEP = dyn_cast<GetElementPtrInst>(&I);
      auto IsPhi = isa<PHINode>(&I);
      auto InsertPt = IsPhi
        ? F.getEntryBlock().getFirstInsertionPt()
        : I.getIterator();
      for (unsigned i = 0; i < I.getNumOperands(); ++i) {
        if (CI && CI->isBundleOperand(i)) {
          continue;
        }
        if (GEP && (i < 2 || GEP->getSourceElementType()->isStructTy())) {
          continue;
        }
        auto Opr = I.getOperand(i);
        if (auto CEP = dyn_cast<ConstantExpr>(Opr)) {
          IRB.SetInsertPoint(InsertPt);
          auto CEPInst = CEP->getAsInstruction();
          IRB.Insert(CEPInst);
          I.setOperand(i, CEPInst);
          Changed = true;
        }
      }
    }
  }
  return Changed;
}

IntegerType *getPageTableIntTy(Module &M) {
  return IntegerType::get(M.getContext(),
                          M.getDataLayout().getPointerSizeInBits());
}

// 16 种操作的索引加密链（Arkari 23.x 算法）：
// 每种操作对 (objKey, newIndex) 组合产生不同的可逆变换，
// 加密侧与 buildPageTableDecryptIR 的 createDecIndexSwitch 互为逆操作。
void maskCipher(uint8_t mask, APInt &preIndex, uint64_t objKey,
                unsigned newIndex) {
  switch (mask) {
  case 1:
    preIndex = -preIndex;
    break;
  case 2:
    preIndex = preIndex.rotl(static_cast<unsigned>(objKey + newIndex));
    break;
  case 3:
    preIndex = preIndex.byteSwap();
    break;
  case 4:
    preIndex = ~preIndex;
    break;
  case 5:
    preIndex = preIndex.rotr(static_cast<unsigned>(objKey - newIndex));
    break;
  case 6:
    preIndex += objKey;
    break;
  case 7:
    preIndex -= objKey;
    break;
  case 8: {
    // Self-inverse half-swap XOR: (Hi, Lo) -> (Hi, Hi^Lo)
    unsigned Half = preIndex.getBitWidth() / 2;
    APInt    Mask = APInt::getLowBitsSet(preIndex.getBitWidth(), Half);
    APInt    Hi = preIndex.lshr(Half) & Mask;
    APInt    Lo = preIndex & Mask;
    preIndex = (Hi << Half) | (Hi ^ Lo);
    break;
  }
  case 9:
    preIndex ^= (objKey + newIndex);
    break;
  case 10:
    preIndex ^= ~objKey;
    break;
  case 11:
    preIndex ^= (objKey - newIndex);
    break;
  case 12:
    preIndex ^= (objKey * newIndex);
    break;
  case 13:
    preIndex += newIndex;
    break;
  case 14:
    preIndex -= newIndex;
    break;
  case 15:
    preIndex = preIndex.rotl(static_cast<unsigned>(objKey));
    break;
  default:
    preIndex = preIndex ^ objKey;
    break;
  }
}

void createPageTable(const CreatePageTableArgs &args) {
  auto *IntTy = getPageTableIntTy(*args.M);
  const unsigned BitWidth = IntTy->getBitWidth();
  std::mt19937_64 re(args.RandomEngine->get_uint64_t());
  std::shuffle(args.Objects->begin(), args.Objects->end(), re);

  // Objects 数组存加密整数：ptrtoint(Obj) + PtrEncKey（不再存裸指针）
  auto PtrEncKeyConst = ConstantInt::get(IntTy, args.PtrEncKey);
  std::vector<Constant *> GVObjects;
  for (unsigned i = 0; i < args.Objects->size(); ++i) {
    auto Obj = args.Objects->at(i);
    auto PtrInt = ConstantExpr::getPtrToInt(Obj, IntTy);
    GVObjects.push_back(
        ConstantExpr::get(Instruction::Add, PtrInt, PtrEncKeyConst));
    args.IndexMap->insert_or_assign(Obj, i);
  }

  {
    auto GVNameObjects(args.GVNamePrefix + "_objects");
    auto ATy = ArrayType::get(IntTy, GVObjects.size());
    auto CA = ConstantArray::get(ATy, ArrayRef(GVObjects));
    auto GV = new GlobalVariable(*args.M, ATy, false, 
                                 GlobalValue::LinkageTypes::InternalLinkage,
                                 CA, GVNameObjects);
    GV->addMetadata("noobf", *MDNode::get(args.M->getContext(), {}));
    args.OutPageTable->push_back(GV);
  }

  for (unsigned i = 0; i < args.CountLoop; ++i) {
    std::shuffle(args.Objects->begin(), args.Objects->end(), re);

    std::vector<Constant *> ConstantObjectIndex;
    for (unsigned j = 0; j < args.Objects->size(); ++j) {
      const auto Obj = args.Objects->at(j);
      const auto ObjFullKey = args.ObjectKeys->at(Obj);
      const auto ObjMask = static_cast<uint32_t>(ObjFullKey >> 32);

      APInt preIndex(BitWidth, args.IndexMap->at(Obj));
      for (unsigned k = 0; k < 4; ++k) {
        const auto mask = static_cast<uint8_t>(ObjMask >> (k * 4)) % 16u;
        maskCipher(mask, preIndex, ObjFullKey, j);
      }
      auto toWriteData = ConstantInt::get(IntTy, preIndex);
      ConstantObjectIndex.push_back(toWriteData);
      args.IndexMap->insert_or_assign(Obj, j);
    }

    {

      auto GVNameObjPageTable(args.GVNamePrefix + "_page_table_" + std::to_string(i));
      auto IATy = ArrayType::get(IntTy, ConstantObjectIndex.size());
      auto IA = ConstantArray::get(IATy, ArrayRef(ConstantObjectIndex));
      auto GV = new GlobalVariable(*args.M, IATy, false,
                                   GlobalValue::LinkageTypes::InternalLinkage,
                                   IA, GVNameObjPageTable);
      GV->addMetadata("noobf", *MDNode::get(args.M->getContext(), {}));
      args.OutPageTable->push_back(GV);
    }
  }

}

void enhancedPageTable(const CreatePageTableArgs &args, std::unordered_map<Constant *, unsigned> *FuncIndexMap) {
  auto *IntTy = getPageTableIntTy(*args.M);
  const unsigned BitWidth = IntTy->getBitWidth();
  std::mt19937_64 re(args.RandomEngine->get_uint64_t());

  for (unsigned i = 0; i < args.CountLoop; ++i) {
    std::shuffle(args.Objects->begin(), args.Objects->end(), re);
    std::vector<Constant *> ConstantObjectIndex;
    for (unsigned j = 0; j < args.Objects->size(); ++j) {
      auto Obj = args.Objects->at(j);
      const auto ObjFullKey = args.ObjectKeys->at(Obj);
      const auto ObjMask = static_cast<uint32_t>(ObjFullKey >> 32);

      APInt preIndex(BitWidth, FuncIndexMap->find(Obj) == FuncIndexMap->end() ?
                           args.IndexMap->at(Obj) :
                           FuncIndexMap->at(Obj));

      for (unsigned k = 0; k < 2 * args.CountLoop; ++k) {
        const auto mask = static_cast<uint8_t>(ObjMask >> (k * 4)) % 16u;
        maskCipher(mask, preIndex, ObjFullKey, j);
      }
      auto toWriteData = ConstantInt::get(IntTy, preIndex);
      ConstantObjectIndex.push_back(toWriteData);
      FuncIndexMap->insert_or_assign(Obj, j);
    }

    {
      auto GVNameObjPage(args.GVNamePrefix + "_enhanced_page_table_" + std::to_string(i));
      auto IATy = ArrayType::get(IntTy, ConstantObjectIndex.size());
      auto IA = ConstantArray::get(IATy, ArrayRef(ConstantObjectIndex));
      auto GV = new GlobalVariable(*args.M, IATy, false, GlobalValue::LinkageTypes::PrivateLinkage,
        IA, GVNameObjPage);
      GV->addMetadata("noobf", *MDNode::get(args.M->getContext(), {}));
      args.OutPageTable->push_back(GV);
    }
  }
}

Value * buildPageTableDecryptIR(const BuildDecryptArgs &args) {
  auto M = args.Fn->getParent();
  auto& Ctx = args.Fn->getContext();
  auto *IntTy = getPageTableIntTy(*M);
  auto Zero = ConstantInt::getNullValue(IntTy);
  const auto ModuleKey = static_cast<uint32_t>(args.ModuleKey);
  const auto ModuleMask = static_cast<uint32_t>(args.ModuleKey >> 32);
  const auto FuncKey = static_cast<uint32_t>(args.FuncKey);
  const auto FuncMask = static_cast<uint32_t>(args.FuncKey >> 32);
  IRBuilder<> IRB{args.InsertBefore};

  Value *NextIndex = args.NextIndexValue;
  if (!NextIndex) {
    auto GVInitIndex = new GlobalVariable(*M, IntTy, true, GlobalValue::PrivateLinkage,
      ConstantInt::get(IntTy, args.NextIndex), 
      M->getName() + args.Fn->getName() + "_InitIndex" +
      std::to_string(args.NextIndex));
    GVInitIndex->addMetadata("noobf", *MDNode::get(Ctx, {}));
    NextIndex = IRB.CreateAlignedLoad(IntTy, GVInitIndex, Align{1}, true);
  } else if (NextIndex->getType() != IntTy) {
    // 防御：调用方可能传入更窄的整数索引（如 i32），统一到页表整数
    // 宽度，避免 i64/i32 混合的非法 IR（曾导致 x86 后端 Post-RA 崩溃：
    // Cannot emit physreg copy instruction；clang 默认
    // -disable-llvm-verifier 不拦非法 IR）。
    unsigned SrcBits = NextIndex->getType()->getIntegerBitWidth();
    NextIndex = SrcBits < IntTy->getBitWidth()
                    ? IRB.CreateZExt(NextIndex, IntTy, "bcf.idx")
                    : IRB.CreateTrunc(NextIndex, IntTy, "bcf.idx");
  }

  // maskCipher 的 IR 逆操作（与加密侧 16 种操作一一对应）
  auto createDecIndexSwitch = [&IRB, &M](uint8_t mask, Value *NextIndex, Value *PrevIndex, Value* ObjKey) -> Value* {
    switch (mask) {
    case 1:
      // preIndex = -preIndex;
      NextIndex = IRB.CreateNeg(NextIndex);
      break;
    case 2:
      // preIndex = preIndex.rotl(ObjKey + j);
      NextIndex = IRB.CreateCall(
        Intrinsic::getOrInsertDeclaration(M, Intrinsic::fshr, {NextIndex->getType()}),
        {NextIndex, NextIndex, IRB.CreateAdd(ObjKey, PrevIndex)});
      break;
    case 3:
      // preIndex = preIndex.byteSwap();
      NextIndex = IRB.CreateCall(
        Intrinsic::getOrInsertDeclaration(M, Intrinsic::bswap, {NextIndex->getType()}),
        {NextIndex});
      break;
    case 4:
      // preIndex = ~preIndex;
      NextIndex = IRB.CreateNot(NextIndex);
      break;
    case 5:
      // preIndex = preIndex.rotr(ObjKey - j);
      NextIndex = IRB.CreateCall(
        Intrinsic::getOrInsertDeclaration(M, Intrinsic::fshl, {NextIndex->getType()}),
        {NextIndex, NextIndex, IRB.CreateSub(ObjKey, PrevIndex)});
      break;
    case 6:
      // preIndex += objKey;
      NextIndex = IRB.CreateSub(NextIndex, ObjKey);
      break;
    case 7:
      // preIndex -= objKey;
      NextIndex = IRB.CreateAdd(NextIndex, ObjKey);
      break;
    case 8: {
      // Self-inverse half-swap XOR: (Hi, Lo) -> (Hi, Hi^Lo)
      auto *ITy = cast<IntegerType>(NextIndex->getType());
      unsigned Half = ITy->getBitWidth() / 2;
      auto *HalfShift = ConstantInt::get(ITy, Half);
      auto *HalfMask = ConstantInt::get(
          ITy, APInt::getLowBitsSet(ITy->getBitWidth(), Half));
      auto *Hi = IRB.CreateAnd(IRB.CreateLShr(NextIndex, HalfShift), HalfMask);
      auto *Lo = IRB.CreateAnd(NextIndex, HalfMask);
      NextIndex = IRB.CreateOr(IRB.CreateShl(Hi, HalfShift),
                               IRB.CreateXor(Hi, Lo));
      break;
    }
    case 9:
      // preIndex ^= (objKey + newIndex);
      NextIndex = IRB.CreateXor(NextIndex, IRB.CreateAdd(ObjKey, PrevIndex));
      break;
    case 10:
      // preIndex ^= ~objKey;
      NextIndex = IRB.CreateXor(NextIndex, IRB.CreateNot(ObjKey));
      break;
    case 11:
      // preIndex ^= (objKey - newIndex);
      NextIndex = IRB.CreateXor(NextIndex, IRB.CreateSub(ObjKey, PrevIndex));
      break;
    case 12:
      // preIndex ^= (objKey * newIndex);
      NextIndex = IRB.CreateXor(NextIndex, IRB.CreateMul(ObjKey, PrevIndex));
      break;
    case 13:
      // preIndex += newIndex;
      NextIndex = IRB.CreateSub(NextIndex, PrevIndex);
      break;
    case 14:
      // preIndex -= newIndex;
      NextIndex = IRB.CreateAdd(NextIndex, PrevIndex);
      break;
    case 15:
      // preIndex = rotl(preIndex, objKey);
      NextIndex = IRB.CreateCall(
        Intrinsic::getOrInsertDeclaration(M, Intrinsic::fshr, {NextIndex->getType()}),
        {NextIndex, NextIndex, ObjKey});
      break;
    default:
      // preIndex = preIndex ^ ObjKey;
      NextIndex = IRB.CreateXor(NextIndex, ObjKey);
      break;
    }
    return NextIndex;
  };

  if (args.FuncLoopCount && !args.FuncPageTable->empty()) {
    auto ConstantFuncKey = ConstantInt::get(IntTy, args.FuncKey);

    for (int i = args.FuncPageTable->size() - 1; i >= 0; --i) {
      auto TargetPage = args.FuncPageTable->at(i);
      auto PrevIndex = NextIndex;
      Value *GEP = IRB.CreateGEP(
          TargetPage->getValueType(), TargetPage,
          {Zero, NextIndex});
      NextIndex = IRB.CreateLoad(IntTy, GEP);
      std::vector<uint8_t> maskIndex;
      for (unsigned j = 0; j < 2 * args.FuncLoopCount; ++j) {
        auto mask = static_cast<uint8_t>(FuncMask >> (j * 4)) % 16u;
        maskIndex.push_back(mask);
      }
      for (int j = maskIndex.size() - 1; j >= 0; --j) {
        NextIndex = createDecIndexSwitch(maskIndex.at(j), NextIndex, PrevIndex, ConstantFuncKey);
      }
    }
  }

  auto ConstantModuleKey = ConstantInt::get(IntTy, args.ModuleKey);

  for (int i = args.ModulePageTable->size() - 1; i >= 0; --i) {
    auto TargetPage = args.ModulePageTable->at(i);
    auto PrevIndex = NextIndex;
    Value *GEP = IRB.CreateGEP(
      TargetPage->getValueType(), TargetPage,
      {Zero, NextIndex});
    if (i) {
      NextIndex = IRB.CreateLoad(IntTy, GEP);
      std::vector<uint8_t> maskIndex;
      for (unsigned j = 0; j < 4; ++j) {
        auto mask = static_cast<uint8_t>(ModuleMask >> (j * 4)) % 16u;
        maskIndex.push_back(mask);
      }
      for (int j = maskIndex.size() - 1; j >= 0; --j) {
        NextIndex = createDecIndexSwitch(maskIndex.at(j), NextIndex, PrevIndex, ConstantModuleKey);
      }
      continue;
    }
    // Objects 数组存的是加密整数：ptrtoint(Obj) + PtrEncKey
    auto EncInt = IRB.CreateLoad(IntTy, GEP);
    auto DecInt = IRB.CreateSub(EncInt, ConstantInt::get(IntTy, args.PtrEncKey));
    return IRB.CreateIntToPtr(DecInt, args.LoadTy);
  }
  llvm_unreachable("BuildDecryptIR unreachable!!!");
}

// ============================================================
// 高阶 MBA (Mixed Boolean Arithmetic) 递归重写引擎
// 将整数运算利用非线性位运算恒等式进行多层展开，生成大量 EON/ORN/BIC 等指令
// 规则 1: A + B == (A | B) + (A & B) == (A ^ B) + 2*(A & B)
// 规则 2: A - B == (A ^ ~B) + 1 + 2*(A | ~B)
// 规则 3: A ^ B == (A | B) - (A & B) == (A & ~B) | (~A & B)
// ============================================================
static Value *buildMBAAdd(IRBuilder<NoFolder> &IRB, Value *A, Value *B, unsigned Depth, CryptoUtils *RE) {
  if (Depth == 0) {
    return IRB.CreateAdd(A, B);
  }
  // 只保留经 -O2 实测存活的形态（原型见 d:/ollvm/bcf_demo/mba2/add_probe.c）：
  //   R0: A + B = (A ^ B) + 2*(A & B)   -> xor / and / lea
  //   R1: A + B = 2*(A | B) - (A ^ B)   -> or / add / xor / sub
  // 已淘汰（InstCombine 折叠成一条 lea，零混淆收益、纯膨胀）：
  //   (A | B) + (A & B)、A - (~B) - 1、A - (~B + 1)、(A+(A&B))+(B-(A&B))
  unsigned Rule = RE->get_uint32_t() % 2;
  if (Rule == 0) {
    // A + B = (A ^ B) + 2 * (A & B)
    Value *XorVal = IRB.CreateXor(A, B);
    Value *AndVal = IRB.CreateAnd(A, B);
    Value *TwoAnd = IRB.CreateShl(AndVal, ConstantInt::get(A->getType(), 1));
    return buildMBAAdd(IRB, XorVal, TwoAnd, Depth - 1, RE);
  } else {
    // A + B = 2*(A | B) - (A ^ B) = (A | B) + (A | B) - (A ^ B)
    Value *OrVal  = IRB.CreateOr(A, B);
    Value *TwoOr  = IRB.CreateShl(OrVal, ConstantInt::get(A->getType(), 1));
    Value *XorVal = IRB.CreateXor(A, B);
    return IRB.CreateSub(TwoOr, XorVal);
  }
}

static Value *buildMBAXor(IRBuilder<NoFolder> &IRB, Value *A, Value *B, unsigned Depth, CryptoUtils *RE) {
  if (Depth == 0) {
    return IRB.CreateXor(A, B);
  }
  // 只保留经 -O2 实测存活的形态（原型见 d:/ollvm/bcf_demo/mba2/xor_probe*.c）：
  //   R0: A ^ B = (A + B) - 2*(A & B)   -> lea / and / add / sub
  //   R1: A ^ B = (A - B) + 2*(~A & B)  -> sub / not / and / lea
  // 已淘汰（全部被 InstCombine 折叠回一条 xor）：
  //   (A|B)-(A&B)、(A&~B)|(~A&B)、(~A&B)+(A&~B)、(A|B)^(A&B)、(A|B)&~(A&B)、
  //   (A+B)-((A&B)+(A&B))
  unsigned Rule = RE->get_uint32_t() % 2;
  if (Rule == 0) {
    // A ^ B = (A + B) - 2 * (A & B)
    Value *Sum    = IRB.CreateAdd(A, B);
    Value *AndVal = IRB.CreateAnd(A, B);
    Value *TwoAnd = IRB.CreateShl(AndVal, ConstantInt::get(A->getType(), 1));
    return IRB.CreateSub(Sum, TwoAnd);
  } else {
    // A ^ B = (A - B) + 2 * (~A & B)
    Value *Diff  = IRB.CreateSub(A, B);
    Value *NotA  = IRB.CreateNot(A);
    Value *T     = IRB.CreateAnd(NotA, B);
    Value *TwoT  = IRB.CreateShl(T, ConstantInt::get(A->getType(), 1));
    return IRB.CreateAdd(Diff, TwoT);
  }
}

Value * encryptConstant(Constant *plainConstant, Instruction *insertBefore, CryptoUtils *randomEngine, unsigned level) {
  auto& Ctx = insertBefore->getContext();
  auto OriginValTy = plainConstant->getType();
  if (OriginValTy->isStructTy() || OriginValTy->isArrayTy() || OriginValTy->isPointerTy()) {
    return plainConstant;
  }
  auto BitWidth = plainConstant->getType()->getPrimitiveSizeInBits().getFixedValue();
  if (BitWidth < 8) {
    return plainConstant;
  }
  
  const auto Key = ConstantInt::get(
      IntegerType::get(Ctx, BitWidth),
      randomEngine->get_uint64_t());

  const auto ConstantIntVal = ConstantExpr::getBitCast(plainConstant, Key->getType());
  auto Enc = ConstantExpr::getSub(ConstantIntVal, Key);
  Constant *XorKey = nullptr;
  if (level) {
    XorKey = ConstantInt::get(Key->getType(), randomEngine->get_uint64_t());
    Enc = ConstantExpr::getXor(Enc, XorKey);
    if (level > 1) {
      Enc = ConstantExpr::getXor(Enc, ConstantExpr::get(Instruction::Mul, XorKey, Key));
    }
    if (level > 2) {
      Enc = ConstantExpr::getXor(Enc, ConstantExpr::getNeg(XorKey));
    }
  }
  auto EncGV = new GlobalVariable(*insertBefore->getModule(), Enc->getType(), false,
                                  GlobalValue::InternalLinkage, Enc);
  EncGV->addMetadata("noobf", *MDNode::get(Ctx, {}));
  IRBuilder<NoFolder> IRB(insertBefore);
  Value *Load = IRB.CreateAlignedLoad(Enc->getType(), EncGV, Align{1}, true);
  
  // 采用 MBA 高阶展开重构解密链路
  if (level) {
    if (level > 2) {
      Load = buildMBAXor(IRB, Load, IRB.CreateNeg(XorKey), 2, randomEngine);
    }
    if (level > 1) {
      Load = buildMBAXor(IRB, Load, IRB.CreateMul(XorKey, Key), 2, randomEngine);
    }
    Load = buildMBAXor(IRB, Load, XorKey, 2, randomEngine);
  }
  // 使用 MBA 递归加法还原常量
  Load = buildMBAAdd(IRB, Load, Key, 2, randomEngine);
  return IRB.CreateBitCast(Load, OriginValTy);
}
