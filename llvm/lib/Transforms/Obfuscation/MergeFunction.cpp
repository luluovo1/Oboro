// Merge small internal functions into one dispatcher.
//
// Every eligible function loses its own body and its symbol: the body is
// cloned into a shared function, the entry becomes one `switch` case, and every
// call site is rewritten to `merged(id, args...)`.  The original function is
// then erased, so a decompiler's function list and cross-reference graph no
// longer contain it -- unlike the version this is based on, which kept a
// forwarding wrapper per function and therefore left the boundary intact.
//
// Safety comes first: a function is only merged when every use of it is a
// direct `call` (checked by walking users, not just `hasAddressTaken()`), it
// returns void, has no ABI-changing attributes, is not varargs, is not
// recursive, and has no `musttail` call inside.  Anything else is left alone;
// a missed reference here would be a dangling call at runtime.

#include "llvm/Transforms/Obfuscation/MergeFunction.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/CryptoUtils.h"
#undef R

#include <algorithm>

#define DEBUG_TYPE "merge-function"

using namespace llvm;

namespace llvm {
namespace {

// A group has to stay small: every merged function costs one case, and every
// call site pads its argument list up to the widest signature in the group.
constexpr unsigned kMaxFunctionsPerGroup = 32;
constexpr unsigned kMaxArgsPerFunction = 24;
constexpr unsigned kMaxArgsPerGroup = 64;

struct MergeFunction : public ModulePass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  unsigned GroupSeq = 0;

  MergeFunction(ObfuscationOptions *AO) : ModulePass(ID), ArgsOptions(AO) {
    initializeMergeFunctionPass(*PassRegistry::getPassRegistry());
  }

  bool runOnModule(Module &M) override;

private:
  bool isEligible(Function &F);
  bool mergeGroup(Module &M, ArrayRef<Function *> Group);
  static Value *toI64(IRBuilder<> &B, Value *V);
  static Value *fromI64(IRBuilder<> &B, Value *V, Type *T);
};

} // namespace

char MergeFunction::ID = 0;

Value *MergeFunction::toI64(IRBuilder<> &B, Value *V) {
  Type *T = V->getType();
  Type *I64 = B.getInt64Ty();
  if (T->isIntegerTy())
    return B.CreateZExtOrTrunc(V, I64);
  if (T->isPointerTy())
    return B.CreatePtrToInt(V, I64);
  if (T->isFloatTy())
    return B.CreateZExt(B.CreateBitCast(V, B.getInt32Ty()), I64);
  if (T->isDoubleTy())
    return B.CreateBitCast(V, I64);
  return B.CreateZExtOrTrunc(V, I64);
}

Value *MergeFunction::fromI64(IRBuilder<> &B, Value *V, Type *T) {
  if (T->isIntegerTy())
    return B.CreateZExtOrTrunc(V, T);
  if (T->isPointerTy())
    return B.CreateIntToPtr(V, T);
  if (T->isFloatTy())
    return B.CreateBitCast(B.CreateTrunc(V, B.getInt32Ty()), T);
  if (T->isDoubleTy())
    return B.CreateBitCast(V, T);
  return B.CreateZExtOrTrunc(V, T);
}

bool MergeFunction::isEligible(Function &F) {
  if (F.isDeclaration() || F.isIntrinsic())
    return false;
  if (F.isVarArg())
    return false;
  // Only void functions: a non-void result would need an sret pointer per
  // member, which is a second ABI to get wrong.
  if (!F.getReturnType()->isVoidTy())
    return false;
  if (F.hasPersonalityFn() || F.hasPrefixData() || F.hasPrologueData())
    return false;
  if (F.hasFnAttribute(Attribute::Naked) ||
      F.hasFnAttribute(Attribute::AlwaysInline) ||
      F.hasFnAttribute(Attribute::ReturnsTwice) ||
      F.hasFnAttribute(Attribute::OptimizeNone) ||
      F.hasFnAttribute("presplitcoroutine"))
    return false;
  // These either change the dispatcher's ABI/section/GC or would leave a
  // dangling reference to the erased member.  Reject instead of repairing.
  if (F.hasFnAttribute(Attribute::NoReturn) ||
      F.hasFnAttribute(Attribute::NoRecurse) ||
      F.getMetadata(LLVMContext::MD_kcfi_type) ||
      F.hasSection() || F.hasComdat() || F.hasGC())
    return false;
  if (F.getName() == "main")
    return false;
  if (F.arg_size() > kMaxArgsPerFunction)
    return false;

  GlobalValue::LinkageTypes LT = F.getLinkage();
  if (LT != GlobalValue::InternalLinkage && LT != GlobalValue::PrivateLinkage)
    return false;

  for (Argument &A : F.args()) {
    Type *T = A.getType();
    if (!T->isIntegerTy() && !T->isPointerTy() && !T->isFloatTy() &&
        !T->isDoubleTy())
      return false;
    // toI64/fromI64 use ZExtOrTrunc to i64; anything wider would be silently
    // truncated and corrupted.
    if (T->isIntegerTy() && T->getIntegerBitWidth() > 64)
      return false;
    if (A.hasAttribute(Attribute::ByVal) ||
        A.hasAttribute(Attribute::InAlloca) ||
        A.hasAttribute(Attribute::Preallocated) ||
        A.hasAttribute(Attribute::SwiftSelf) ||
        A.hasAttribute(Attribute::SwiftError) ||
        A.hasAttribute(Attribute::Nest) ||
        A.hasAttribute(Attribute::StructRet))
      return false;
  }

  // Walk the actual users.  hasAddressTaken() alone is not enough: an invoke,
  // a callbr or a constant expression referencing the function would also be
  // left dangling once the symbol is erased.
  for (User *U : F.users()) {
    auto *CI = dyn_cast<CallInst>(U);
    if (!CI)
      return false;
    if (CI->getCalledOperand()->stripPointerCasts() != &F)
      return false;
    // Rebuilding the call would drop its operand bundles (WinEH funclet,
    // KCFI, ARC attached-call, ptrauth) and musttail's tail-call guarantee.
    if (CI->hasOperandBundles() || CI->isMustTailCall())
      return false;
  }
  if (F.hasAddressTaken())
    return false;

  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      auto *CB = dyn_cast<CallBase>(&I);
      if (!CB)
        continue;
      // Self recursion is left alone: the merged body would call itself with a
      // different id and the frame size would be that of the dispatcher.
      if (CB->getCalledOperand()->stripPointerCasts() == &F)
        return false;
      // musttail requires the call to be immediately followed by a return of
      // its result; rewriting it into a call to the dispatcher breaks that.
      if (auto *CI = dyn_cast<CallInst>(CB))
        if (CI->isMustTailCall())
          return false;
    }
  }
  return true;
}

bool MergeFunction::mergeGroup(Module &M, ArrayRef<Function *> Group) {
  LLVMContext &Ctx = M.getContext();
  Type *I32 = Type::getInt32Ty(Ctx);
  Type *I64 = Type::getInt64Ty(Ctx);

  unsigned MaxArgs = 0;
  for (Function *F : Group)
    MaxArgs = std::max(MaxArgs, (unsigned)F->arg_size());

  SmallVector<Type *, 8> Params;
  Params.push_back(I32);
  for (unsigned I = 0; I < MaxArgs; ++I)
    Params.push_back(I64);
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), Params, false);
  Function *Merged = Function::Create(
      FT, GlobalValue::InternalLinkage,
      obf::freshName(M, "merged" + std::to_string(GroupSeq++)), M);
  // The whole point is that these bodies stay together; an inliner that
  // undid the merge would also undo the obfuscation.
  Merged->addFnAttr(Attribute::NoInline);
  Merged->setCallingConv(CallingConv::C);
  // CloneFunctionInto copies each member's AttributeList, CC, section,
  // alignment and GC onto Merged, and appends function-level metadata
  // (!dbg/!prof/!kcfi_type).  Save the dispatcher's own state and restore it
  // after every clone.
  AttributeList SavedAttrs = Merged->getAttributes();

  BasicBlock *Dispatch = BasicBlock::Create(Ctx, "dispatch", Merged);
  BasicBlock *TrapBB = BasicBlock::Create(Ctx, "trap", Merged);
  BasicBlock *RetBB = BasicBlock::Create(Ctx, "ret", Merged);

  IRBuilder<> DB(Dispatch);
  SwitchInst *SW = DB.CreateSwitch(Merged->getArg(0), TrapBB, Group.size());

  DenseMap<Function *, unsigned> IdOf;
  unsigned NextId = 0;
  for (Function *F : Group) {
    unsigned Id = NextId++;
    IdOf[F] = Id;

    // One prologue block per member converts the i64 arguments back to the
    // member's own types; the switch jumps straight here.
    BasicBlock *Prologue = BasicBlock::Create(Ctx, "p", Merged);
    IRBuilder<> PB(Prologue);
    ValueToValueMapTy VMap;
    unsigned ArgIdx = 0;
    for (Argument &A : F->args())
      VMap[&A] = fromI64(PB, Merged->getArg(1 + ArgIdx++), A.getType());

    size_t Before = Merged->size();
    SmallVector<ReturnInst *, 8> Returns;
    CloneFunctionInto(Merged, F, VMap, CloneFunctionChangeType::LocalChangesOnly,
                      Returns, "", nullptr, nullptr, nullptr);
    // Restore the dispatcher's own function state.  Section/alignment/GC are
    // not part of AttributeList, and CloneFunctionMetadataInto appends
    // !dbg/!prof/!kcfi_type; all of them must be undone per member.
    Merged->setAttributes(SavedAttrs);
    Merged->setCallingConv(CallingConv::C);
    Merged->addFnAttr(Attribute::NoInline);
    Merged->setSection("");
    Merged->setAlignment(Align());
    Merged->clearGC();
    Merged->clearMetadata();
    auto BI = Merged->begin();
    std::advance(BI, Before);
    for (auto BE = Merged->end(); BI != BE; ++BI)
      for (Instruction &I : *BI)
        I.setDebugLoc(DebugLoc());
    auto It = Merged->begin();
    std::advance(It, Before);
    BasicBlock *NewEntry = &*It;
    // Keep the member's static allocas in the dispatcher entry block; left in
    // NewEntry they would become dynamic stack allocations on every call.
    for (auto II = NewEntry->begin(); II != NewEntry->end();) {
      auto Cur = II++;
      if (auto *AI = dyn_cast<AllocaInst>(&*Cur))
        AI->moveBefore(*Dispatch, Dispatch->getFirstInsertionPt());
    }
    PB.CreateBr(NewEntry);

    for (ReturnInst *RI : Returns)
      ReplaceInstWithInst(RI, BranchInst::Create(RetBB));

    SW->addCase(DB.getInt32(Id), Prologue);
  }

  IRBuilder<> TB(TrapBB);
  TB.CreateCall(Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap));
  TB.CreateUnreachable();

  IRBuilder<> RB(RetBB);
  RB.CreateRetVoid();

  // Rewrite every call site, including the ones inside the merged body: a
  // member may call another member of the same group.
  SmallVector<std::pair<CallInst *, unsigned>, 64> Work;
  for (Function &F : M) {
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI)
          continue;
        Function *Callee = CI->getCalledFunction();
        if (!Callee)
          continue;
        auto It = IdOf.find(Callee);
        if (It == IdOf.end())
          continue;
        Work.push_back({CI, It->second});
      }
    }
  }

  for (auto &P : Work) {
    CallInst *CI = P.first;
    IRBuilder<> CB(CI);
    SmallVector<Value *, 8> Args;
    Args.push_back(CB.getInt32(P.second));
    for (Value *A : CI->args())
      Args.push_back(toI64(CB, A));
    for (unsigned K = CI->arg_size(); K < MaxArgs; ++K)
      Args.push_back(CB.getInt64(0));
    CallInst *New = CB.CreateCall(Merged, Args);
    New->setCallingConv(CallingConv::C);
    if (CI->getDebugLoc())
      New->setDebugLoc(CI->getDebugLoc());
    CI->eraseFromParent();
  }

  for (Function *F : Group)
    F->eraseFromParent();

  return true;
}

bool MergeFunction::runOnModule(Module &M) {
  SmallVector<Function *, 32> Candidates;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    const auto Opt = ArgsOptions->toObfuscate(ArgsOptions->mergeOpt(), &F);
    if (!Opt.isEnabled())
      continue;
    if (!isEligible(F))
      continue;
    Candidates.push_back(&F);
  }
  if (Candidates.size() < 2)
    return false;

  bool Changed = false;
  // Greedy packing: keep both the function-count and total-argument caps,
  // but do not discard a whole 32-function chunk when it exceeds the arg cap.
  SmallVector<Function *, 32> Group;
  unsigned GroupArgs = 0;
  auto Flush = [&]() {
    if (Group.size() >= 2)
      Changed |= mergeGroup(M, Group);
    Group.clear();
    GroupArgs = 0;
  };
  for (Function *F : Candidates) {
    unsigned N = F->arg_size();
    if (!Group.empty() &&
        (Group.size() >= kMaxFunctionsPerGroup ||
         GroupArgs + N > kMaxArgsPerGroup))
      Flush();
    Group.push_back(F);
    GroupArgs += N;
  }
  Flush();
  return Changed;
}

} // namespace llvm

ModulePass *llvm::createMergeFunctionPass(ObfuscationOptions *argsOptions) {
  return new MergeFunction(argsOptions);
}

INITIALIZE_PASS(MergeFunction, "merge-function",
                "Merge internal void functions into one dispatcher", false,
                false)
