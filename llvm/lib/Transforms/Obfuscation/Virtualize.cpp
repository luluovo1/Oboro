//===- Virtualize.cpp - IR-level code virtualization ----------------------===//
//
// The VM is a 64-bit register machine.  Every SSA value that survives
// translation owns one virtual register; registers hold the zero-extended bit
// pattern of the value.  Signed operations sign-extend at use time and
// truncate the result back, so two's-complement semantics match the source.
//
// Bytecode is a sequence of fixed 12-byte records (three i32 words).  Every
// word is XOR-encrypted with a rolling LCG stream keyed by a per-function
// constant.  The interpreter loads code words with `volatile`, so the
// optimizer cannot fold the encrypted program back into the original code.
//
// The interpreter is emitted per function: every virtualized function gets its
// own handler order, opcode permutation and global names.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/Virtualize.h"

namespace {
constexpr const char *kGeneratedAttr = "oboro.vmp.generated";
}

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

using namespace llvm;

namespace {

// ---------------------------------------------------------------------------
// Bytecode definition
// ---------------------------------------------------------------------------

enum VMOp : uint8_t {
  OP_NOP = 0,
  OP_MOV,
  OP_IMM,
  OP_PTR,
  OP_LOAD,
  OP_STORE,
  OP_ADD,
  OP_SUB,
  OP_MUL,
  OP_UDIV,
  OP_SDIV,
  OP_UREM,
  OP_SREM,
  OP_AND,
  OP_OR,
  OP_XOR,
  OP_SHL,
  OP_LSHR,
  OP_ASHR,
  OP_ICMP_EQ,
  OP_ICMP_NE,
  OP_ICMP_UGT,
  OP_ICMP_UGE,
  OP_ICMP_ULT,
  OP_ICMP_ULE,
  OP_ICMP_SGT,
  OP_ICMP_SGE,
  OP_ICMP_SLT,
  OP_ICMP_SLE,
  OP_SELECT,
  OP_ZEXT,
  OP_SEXT,
  OP_TRUNC,
  OP_CTPOP,
  OP_CTLZ,
  OP_CTTZ,
  OP_BSWAP,
  OP_BITREVERSE,
  OP_FADD,
  OP_FSUB,
  OP_FMUL,
  OP_FDIV,
  OP_FREM,
  OP_FNEG,
  OP_FABS,
  OP_FSQRT,
  OP_FMA,
  OP_FCMP,
  OP_FPEXT,
  OP_FPTRUNC,
  OP_FPTOSI,
  OP_FPTOUI,
  OP_SITOFP,
  OP_UITOFP,
  OP_BR,
  OP_CBR,
  OP_RET,
  OP_CALL,
  OP_TRAP,
  OP_COUNT
};

constexpr unsigned kMaxRegs = 235;
constexpr unsigned kArgBase = 240;
constexpr unsigned kRetReg = 239;
constexpr unsigned kTmpReg = 238;
constexpr unsigned kFrameReg = 236; // VM stack frame base (ptrtoint)
constexpr unsigned kMaxCallArgs = 16;

constexpr uint8_t W_I1 = 0, W_I8 = 1, W_I16 = 2, W_I32 = 3, W_I64 = 4,
                  W_PTR = 5;

static bool widthCodeForBits(unsigned Bits, uint8_t &Out) {
  switch (Bits) {
  case 1:  Out = W_I1; return true;
  case 8:  Out = W_I8; return true;
  case 16: Out = W_I16; return true;
  case 32: Out = W_I32; return true;
  case 64: Out = W_I64; return true;
  default: return false;
  }
}

static uint64_t constMask(uint64_t Key, unsigned Index) {
  return Key + (uint64_t)Index * 0x9E3779B97F4A7C15ULL;
}

static uint64_t splitmix64(uint64_t &State) {
  uint64_t Z = (State += 0x9E3779B97F4A7C15ULL);
  Z = (Z ^ (Z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  Z = (Z ^ (Z >> 27)) * 0x94D049BB133111EBULL;
  return Z ^ (Z >> 31);
}

// The keystream parameters are derived from the per-function key so the
// binary never contains a recognisable LCG constant.
static uint64_t streamStride(uint64_t Key) {
  uint64_t S = Key ^ 0x243F6A8885A308D3ULL;
  return splitmix64(S) | 1;
}
static uint64_t streamMul(uint64_t Key) {
  uint64_t S = Key ^ 0x13198A2E03707344ULL;
  return splitmix64(S) | 1;
}
static uint64_t streamInc(uint64_t Key) {
  uint64_t S = Key ^ 0xA4093822299F31D0ULL;
  return splitmix64(S);
}


struct VInst {
  uint8_t Op = 0;
  uint8_t W = 0;
  uint8_t A = 0;
  uint8_t B = 0;
  uint8_t C = 0;
  uint8_t Flags = 0;
  uint32_t Imm = 0;
};

// One entry per call-site shape.  A thunk receives the argument block and an
// optional dynamic callee: direct calls pass null, indirect calls pass the
// function pointer loaded from a virtual register.
struct VMThunk {
  Function *Direct = nullptr;
  FunctionType *SiteFT = nullptr;
  SmallVector<Type *, 8> ArgTys;
  Type *RetTy = nullptr;
};

struct VMProgram {
  std::vector<VInst> Code;
  std::vector<uint64_t> Ints;
  std::vector<Constant *> Ptrs;
  std::vector<VMThunk> Thunks;
  uint32_t EntryPC = 0;
  uint8_t OpMap[OP_COUNT] = {};
  uint64_t Key = 0;
  unsigned Level = 1;
  unsigned ArgCount = 0;
  uint64_t FrameSize = 0;
  uint64_t BodyHash = 0;
};

// ---------------------------------------------------------------------------
// Capability checks
// ---------------------------------------------------------------------------

static bool isSupportedScalar(Type *T, const DataLayout &DL) {
  if (T->isIntegerTy()) {
    unsigned W = T->getIntegerBitWidth();
    return W == 1 || W == 8 || W == 16 || W == 32 || W == 64;
  }
  if (T->isPointerTy())
    return T->getPointerAddressSpace() == 0 &&
           (DL.getPointerSizeInBits(0) == 32 ||
            DL.getPointerSizeInBits(0) == 64);
  // Scalar floating point is carried as its 32/64-bit pattern.
  if (T->isFloatTy() || T->isDoubleTy())
    return true;
  return false;
}

static unsigned bitWidthOf(Type *T, const DataLayout &DL) {
  if (T->isIntegerTy())
    return T->getIntegerBitWidth();
  if (T->isPointerTy())
    return DL.getPointerSizeInBits(T->getPointerAddressSpace());
  if (T->isFloatTy())
    return 32;
  if (T->isDoubleTy())
    return 64;
  return 0;
}

// Storage width of a value: floats use the integer code of the same size,
// because a register holds the bit pattern.
static bool storageWidthCode(Type *T, const DataLayout &DL, uint8_t &Out) {
  return widthCodeForBits(bitWidthOf(T, DL), Out);
}

static bool functionShapeOK(Function &F, const DataLayout &DL,
                            std::string &Reason) {
  if (F.isDeclaration() || F.isIntrinsic()) {
    Reason = "declaration/intrinsic";
    return false;
  }
  if (F.isVarArg()) {
    Reason = "varargs";
    return false;
  }
  if (F.hasAvailableExternallyLinkage()) {
    Reason = "available_externally";
    return false;
  }
  if (F.hasPersonalityFn()) {
    Reason = "personality/EH";
    return false;
  }
  if (F.hasPrefixData() || F.hasPrologueData()) {
    Reason = "prefix/prologue data";
    return false;
  }
  if (F.hasFnAttribute(Attribute::Naked) ||
      F.hasFnAttribute("presplitcoroutine") ||
      F.hasFnAttribute(Attribute::ReturnsTwice)) {
    Reason = "naked/coro/returns_twice";
    return false;
  }
  if (!F.getReturnType()->isVoidTy() &&
      !isSupportedScalar(F.getReturnType(), DL)) {
    Reason = "unsupported return type";
    return false;
  }
  for (Argument &A : F.args()) {
    if (!isSupportedScalar(A.getType(), DL)) {
      Reason = "unsupported argument type";
      return false;
    }
    if (A.hasAttribute(Attribute::ByVal) ||
        A.hasAttribute(Attribute::StructRet) ||
        A.hasAttribute(Attribute::InAlloca) ||
        A.hasAttribute(Attribute::Preallocated) ||
        A.hasAttribute(Attribute::SwiftSelf) ||
        A.hasAttribute(Attribute::SwiftError) ||
        A.hasAttribute(Attribute::Nest)) {
      Reason = "unsupported argument attribute";
      return false;
    }
  }
  if (F.arg_size() > kMaxRegs) {
    Reason = "too many arguments";
    return false;
  }
  for (BasicBlock &BB : F) {
    if (BB.hasAddressTaken()) {
      Reason = "blockaddress taken";
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Translator
// ---------------------------------------------------------------------------

class VMTranslator {
public:
  VMTranslator(Function &F, uint64_t Seed, unsigned Level, std::string &Reason)
      : F(F), M(*F.getParent()), DL(M.getDataLayout()), Seed(Seed),
        Level(Level), Reason(Reason) {}

  bool run();

  VMProgram Program;
  std::string &Reason;

private:
  Function &F;
  Module &M;
  const DataLayout &DL;
  uint64_t Seed;
  unsigned Level;

  DenseMap<Value *, uint8_t> Regs;
  DenseSet<Constant *> ConstSeen;
  std::vector<Constant *> ConstOrder;
  DenseMap<BasicBlock *, uint32_t> BlockPC;
  DenseMap<AllocaInst *, uint64_t> AllocaOff;
  std::vector<AllocaInst *> Allocas;
  uint64_t FrameSize = 0;
  std::vector<std::pair<uint32_t, BasicBlock *>> Fixups;
  uint8_t NextReg = 0;
  uint64_t RngState = 0;
  unsigned PtrBits = 0;
  bool Failed = false;

  bool fail(const Twine &Msg) {
    if (!Failed)
      Reason = Msg.str();
    Failed = true;
    return false;
  }

  uint64_t nextRand() { return splitmix64(RngState); }

  uint8_t allocReg() {
    if (NextReg > kMaxRegs) {
      fail("too many SSA values (register file exhausted)");
      return 0;
    }
    return NextReg++;
  }

  uint8_t regOf(Value *V);
  bool materialize(Value *V, uint8_t Dst, Type *Ty);
  void collectConstant(Value *V);

  void emit(uint8_t Op, uint8_t W, uint8_t A = 0, uint8_t B = 0,
            uint8_t C = 0, uint8_t Flags = 0, uint32_t Imm = 0) {
    Program.Code.push_back(VInst{Op, W, A, B, C, Flags, Imm});
  }

  void emitFixup(uint8_t Op, uint8_t W, uint8_t A, uint8_t B, uint8_t C,
                 uint8_t Flags, BasicBlock *Target) {
    emit(Op, W, A, B, C, Flags, 0);
    Fixups.emplace_back(Program.Code.size() - 1, Target);
  }

  bool translateBlock(BasicBlock &BB);
  bool translateInst(Instruction &I);
  bool translateTerminator(Instruction &I);
  bool translateGEP(GetElementPtrInst &GEP);
  bool translateCall(CallInst &CI);
  bool translateSwitch(SwitchInst &SI);
  bool phiCopiesFor(BasicBlock *From, BasicBlock *To);
  bool callSignatureOK(CallInst &CI, std::string &Why);

  bool hasPhi(BasicBlock *BB) {
    return !BB->empty() && isa<PHINode>(BB->front());
  }

  uint32_t addIntConst(uint64_t V) {
    for (uint32_t I = 0; I < Program.Ints.size(); ++I)
      if (Program.Ints[I] == V)
        return I;
    Program.Ints.push_back(V);
    return (uint32_t)Program.Ints.size() - 1;
  }

  uint32_t addPtrConst(Constant *C) {
    for (uint32_t I = 0; I < Program.Ptrs.size(); ++I)
      if (Program.Ptrs[I] == C)
        return I;
    Program.Ptrs.push_back(C);
    return (uint32_t)Program.Ptrs.size() - 1;
  }

  unsigned thunkForCall(CallInst &CI) {
    Function *Direct = CI.getCalledFunction();
    FunctionType *SiteFT = CI.getFunctionType();
    Type *RetTy = CI.getType();
    SmallVector<Type *, 8> ArgTys;
    for (Value *A : CI.args())
      ArgTys.push_back(A->getType());

    for (unsigned I = 0; I < Program.Thunks.size(); ++I) {
      const VMThunk &T = Program.Thunks[I];
      if (T.Direct != Direct || T.RetTy != RetTy ||
          T.ArgTys.size() != ArgTys.size())
        continue;
      if (!Direct && T.SiteFT != SiteFT)
        continue;
      bool Same = true;
      for (unsigned J = 0; J < ArgTys.size(); ++J)
        if (T.ArgTys[J] != ArgTys[J]) {
          Same = false;
          break;
        }
      if (Same)
        return I;
    }

    VMThunk T;
    T.Direct = Direct;
    T.SiteFT = SiteFT;
    T.RetTy = RetTy;
    T.ArgTys.assign(ArgTys.begin(), ArgTys.end());
    Program.Thunks.push_back(T);
    return (unsigned)Program.Thunks.size() - 1;
  }

  unsigned thunkForFunction(Function *Callee,
                            ArrayRef<Type *> ArgTys) {
    FunctionType *FT = Callee->getFunctionType();
    for (unsigned I = 0; I < Program.Thunks.size(); ++I) {
      const VMThunk &T = Program.Thunks[I];
      if (T.Direct != Callee || T.ArgTys.size() != ArgTys.size())
        continue;
      bool Same = true;
      for (unsigned J = 0; J < ArgTys.size(); ++J)
        if (T.ArgTys[J] != ArgTys[J]) {
          Same = false;
          break;
        }
      if (Same)
        return I;
    }
    VMThunk T;
    T.Direct = Callee;
    T.SiteFT = FT;
    T.RetTy = FT->getReturnType();
    T.ArgTys.assign(ArgTys.begin(), ArgTys.end());
    Program.Thunks.push_back(T);
    return (unsigned)Program.Thunks.size() - 1;
  }
};

void VMTranslator::collectConstant(Value *V) {
  auto *C = dyn_cast<Constant>(V);
  if (!C || ConstSeen.count(C))
    return;
  ConstSeen.insert(C);
  // Operands first: a ConstantExpr may need its base materialised.
  if (isa<ConstantExpr>(C))
    for (Value *Op : C->operands())
      collectConstant(Op);
  ConstOrder.push_back(C);
}

uint8_t VMTranslator::regOf(Value *V) {
  auto It = Regs.find(V);
  if (It != Regs.end())
    return It->second;
  fail("value has no register (constant was not hoisted)");
  return 0;
}

bool VMTranslator::materialize(Value *V, uint8_t Dst, Type *Ty) {
  auto *C = dyn_cast<Constant>(V);
  if (!C)
    return fail("non-constant value has no register");

  unsigned Bits = bitWidthOf(Ty, DL);
  if (!Bits) {
    std::string S;
    raw_string_ostream OS(S);
    Ty->print(OS);
    return fail("unsupported constant type: " + OS.str());
  }
  uint8_t W;
  if (!widthCodeForBits(Bits, W))
    return fail("unsupported constant width: " + Twine(Bits));

  if (auto *CI = dyn_cast<ConstantInt>(C)) {
    if (CI->getBitWidth() > 64)
      return fail("integer constant wider than 64 bits");
    emit(OP_IMM, W, Dst, 0, 0, 0, addIntConst(CI->getZExtValue()));
    return true;
  }

  if (auto *CF = dyn_cast<ConstantFP>(C)) {
    APInt Bits = CF->getValueAPF().bitcastToAPInt();
    if (Bits.getBitWidth() > 64)
      return fail("fp constant wider than 64 bits");
    emit(OP_IMM, W, Dst, 0, 0, 0, addIntConst(Bits.getZExtValue()));
    return true;
  }

  if (isa<ConstantPointerNull>(C) || isa<UndefValue>(C) ||
      isa<PoisonValue>(C) || isa<ConstantAggregateZero>(C)) {
    emit(OP_IMM, W, Dst, 0, 0, 0, addIntConst(0));
    return true;
  }

  if (auto *CE = dyn_cast<ConstantExpr>(C)) {
    switch (CE->getOpcode()) {
    case Instruction::BitCast:
    case Instruction::AddrSpaceCast:
      if (CE->getOperand(0)->getType()->isPointerTy() && Ty->isPointerTy())
        return materialize(CE->getOperand(0), Dst, Ty);
      break;
    case Instruction::PtrToInt: {
      if (!Ty->isIntegerTy())
        break;
      Type *PT = CE->getOperand(0)->getType();
      uint8_t Tmp = Dst;
      if (!materialize(CE->getOperand(0), Tmp, PT))
        return false;
      unsigned PBits = bitWidthOf(PT, DL);
      uint8_t DW, SW;
      if (!widthCodeForBits(Bits, DW) || !widthCodeForBits(PBits, SW))
        return fail("unsupported ptrtoint width");
      if (PBits > Bits)
        emit(OP_TRUNC, DW, Dst, Tmp, 0, SW);
      else if (PBits < Bits)
        emit(OP_ZEXT, DW, Dst, Tmp, 0, SW);
      return true;
    }
    case Instruction::IntToPtr: {
      if (!Ty->isPointerTy())
        break;
      Type *IT = CE->getOperand(0)->getType();
      uint8_t Tmp = Dst;
      if (!materialize(CE->getOperand(0), Tmp, IT))
        return false;
      unsigned IBits = bitWidthOf(IT, DL);
      uint8_t DW, SW;
      if (!widthCodeForBits(Bits, DW) || !widthCodeForBits(IBits, SW))
        return fail("unsupported inttoptr width");
      if (IBits > Bits)
        emit(OP_TRUNC, DW, Dst, Tmp, 0, SW);
      else if (IBits < Bits)
        emit(OP_ZEXT, DW, Dst, Tmp, 0, SW);
      return true;
    }
    case Instruction::GetElementPtr:
      if (Ty->isPointerTy()) {
        emit(OP_PTR, W_PTR, Dst, 0, 0, 0, addPtrConst(CE));
        return true;
      }
      break;
    default:
      break;
    }
    return fail("unsupported constant expression");
  }

  if (Ty->isPointerTy()) {
    emit(OP_PTR, W_PTR, Dst, 0, 0, 0, addPtrConst(C));
    return true;
  }
  std::string S;
  raw_string_ostream OS(S);
  C->print(OS);
  return fail("unsupported constant: " + OS.str());
}

bool VMTranslator::callSignatureOK(CallInst &CI, std::string &Why) {
  if (CI.isInlineAsm()) {
    Why = "inline asm";
    return false;
  }
  if (CI.hasOperandBundles()) {
    Why = "operand bundles";
    return false;
  }
  if (CI.isMustTailCall()) {
    Why = "musttail";
    return false;
  }
  Function *Callee = CI.getCalledFunction();
  if (Callee && Callee->isIntrinsic()) {
    Why = "intrinsic call";
    return false;
  }
  if (!Callee && CI.getFunctionType()->isVarArg()) {
    // The site keeps its concrete argument types, so a thunk can still be
    // generated; nothing to reject here.
  }
  if (!CI.getType()->isVoidTy() && !isSupportedScalar(CI.getType(), DL)) {
    Why = "unsupported call return type";
    return false;
  }
  if (CI.arg_size() > kMaxCallArgs) {
    Why = "too many call arguments";
    return false;
  }
  for (unsigned I = 0; I < CI.arg_size(); ++I) {
    if (!isSupportedScalar(CI.getArgOperand(I)->getType(), DL)) {
      Why = "unsupported call argument type";
      return false;
    }
    if (CI.paramHasAttr(I, Attribute::ByVal) ||
        CI.paramHasAttr(I, Attribute::StructRet) ||
        CI.paramHasAttr(I, Attribute::InAlloca) ||
        CI.paramHasAttr(I, Attribute::Preallocated) ||
        CI.paramHasAttr(I, Attribute::SwiftSelf) ||
        CI.paramHasAttr(I, Attribute::SwiftError) ||
        CI.paramHasAttr(I, Attribute::Nest)) {
      Why = "unsupported callee argument attribute";
      return false;
    }
  }
  return true;
}

bool VMTranslator::translateCall(CallInst &CI) {
  std::string Why;
  if (!callSignatureOK(CI, Why))
    return fail("call: " + Why);

  bool Indirect = (CI.getCalledFunction() == nullptr);
  unsigned Id = thunkForCall(CI);

  uint8_t FnReg = 0;
  if (Indirect) {
    FnReg = regOf(CI.getCalledOperand());
    if (Failed)
      return false;
  }

  for (unsigned I = 0; I < CI.arg_size(); ++I) {
    Value *Arg = CI.getArgOperand(I);
    uint8_t Dst = kArgBase + I;
    uint8_t W;
    if (!widthCodeForBits(bitWidthOf(Arg->getType(), DL), W))
      return fail("call argument width");
    uint8_t Src = regOf(Arg);
    if (Failed)
      return false;
    emit(OP_MOV, W, Dst, Src);
  }

  uint8_t CFlags = (uint8_t)CI.arg_size() | (Indirect ? 0x80 : 0);
  emit(OP_CALL, 0, 0, FnReg, 0, CFlags, Id);

  if (CI.getType()->isVoidTy()) {
    if (CI.doesNotReturn())
      emit(OP_TRAP, 0);
    return true;
  }

  uint8_t W;
  if (!widthCodeForBits(bitWidthOf(CI.getType(), DL), W))
    return fail("call return width");
  uint8_t Dst = allocReg();
  if (Failed)
    return false;
  emit(OP_MOV, W, Dst, kRetReg);
  Regs[&CI] = Dst;
  if (CI.doesNotReturn())
    emit(OP_TRAP, 0);
  return true;
}

bool VMTranslator::translateGEP(GetElementPtrInst &GEP) {
  Type *PtrTy = GEP.getType();
  if (!PtrTy->isPointerTy() || PtrTy->getPointerAddressSpace() != 0)
    return fail("GEP to non-default address space");
  uint8_t PW;
  if (!widthCodeForBits(PtrBits, PW))
    return fail("pointer width");

  uint8_t Base = regOf(GEP.getPointerOperand());
  if (Failed)
    return false;

  int64_t ConstOff = 0;
  struct DynTerm {
    uint8_t Reg;
    int64_t Stride;
  };
  SmallVector<DynTerm, 4> Dyn;

  Type *Cur = GEP.getSourceElementType();
  for (unsigned I = 0; I < GEP.getNumIndices(); ++I) {
    Value *Idx = GEP.getOperand(I + 1);
    int64_t Stride = 0;
    if (I == 0) {
      // The first index steps over the source element type.
      if (!Cur->isSized())
        return fail("GEP of unsized type");
      Stride = (int64_t)DL.getTypeAllocSize(Cur).getFixedValue();
    } else if (Cur->isStructTy()) {
      auto *CI = dyn_cast<ConstantInt>(Idx);
      if (!CI)
        return fail("dynamic struct index");
      auto *ST = cast<StructType>(Cur);
      unsigned Field = (unsigned)CI->getZExtValue();
      if (Field >= ST->getNumElements())
        return fail("struct index out of range");
      ConstOff += (int64_t)DL.getStructLayout(ST)->getElementOffset(Field);
      Cur = ST->getElementType(Field);
      continue;
    } else if (Cur->isArrayTy()) {
      Type *Elem = Cur->getArrayElementType();
      if (!Elem->isSized())
        return fail("unsized array element");
      Stride = (int64_t)DL.getTypeAllocSize(Elem).getFixedValue();
      Cur = Elem;
    } else {
      return fail("GEP into unsupported type");
    }

    if (auto *CI = dyn_cast<ConstantInt>(Idx))
      ConstOff += CI->getSExtValue() * Stride;
    else {
      uint8_t R = regOf(Idx);
      if (Failed)
        return false;
      Dyn.push_back({R, Stride});
    }
  }

  uint8_t Acc = Base;
  bool First = true;
  if (ConstOff != 0) {
    uint8_t CR = allocReg();
    if (Failed)
      return false;
    emit(OP_IMM, W_I64, CR, 0, 0, 0, addIntConst((uint64_t)ConstOff));
    uint8_t NR = allocReg();
    if (Failed)
      return false;
    emit(OP_ADD, W_I64, NR, Base, CR);
    Acc = NR;
    First = false;
  }
  for (const DynTerm &T : Dyn) {
    uint8_t SR = allocReg();
    if (Failed)
      return false;
    emit(OP_IMM, W_I64, SR, 0, 0, 0, addIntConst((uint64_t)T.Stride));
    uint8_t MR = allocReg();
    if (Failed)
      return false;
    emit(OP_MUL, W_I64, MR, T.Reg, SR);
    uint8_t NR = allocReg();
    if (Failed)
      return false;
    emit(OP_ADD, W_I64, NR, First ? Base : Acc, MR);
    Acc = NR;
    First = false;
  }

  uint8_t Dst = allocReg();
  if (Failed)
    return false;
  if (First)
    emit(OP_MOV, W_PTR, Dst, Base);
  else if (PtrBits < 64)
    emit(OP_TRUNC, W_PTR, Dst, Acc, 0, W_I64);
  else
    emit(OP_MOV, W_PTR, Dst, Acc);
  Regs[&GEP] = Dst;
  return true;
}

bool VMTranslator::phiCopiesFor(BasicBlock *From, BasicBlock *To) {
  for (PHINode &PN : To->phis()) {
    auto It = Regs.find(&PN);
    if (It == Regs.end()) {
      uint8_t R = allocReg();
      if (Failed)
        return false;
      Regs[&PN] = R;
      It = Regs.find(&PN);
    }
    uint8_t Dst = It->second;
    Value *Src = PN.getIncomingValueForBlock(From);
    uint8_t W;
    if (!widthCodeForBits(bitWidthOf(PN.getType(), DL), W))
      return fail("phi width");
    uint8_t S = regOf(Src);
    if (Failed)
      return false;
    emit(OP_MOV, W, Dst, S);
  }
  return true;
}

bool VMTranslator::translateSwitch(SwitchInst &SI) {
  Value *Cond = SI.getCondition();
  uint8_t W;
  if (!widthCodeForBits(bitWidthOf(Cond->getType(), DL), W))
    return fail("switch condition width");
  uint8_t CondReg = regOf(Cond);
  if (Failed)
    return false;

  BasicBlock *From = SI.getParent();
  for (auto &Case : SI.cases()) {
    auto *CI = dyn_cast<ConstantInt>(Case.getCaseValue());
    if (!CI)
      return fail("non-constant switch case");
    uint8_t CaseReg = regOf(CI);
    if (Failed)
      return false;
    emit(OP_ICMP_EQ, W, kTmpReg, CondReg, CaseReg);

    BasicBlock *Target = Case.getCaseSuccessor();
    if (hasPhi(Target)) {
      // CBR true -> stub; CBR false -> the BR below, which jumps to the next
      // comparison.  The stub is placed after that BR.
      uint32_t StubPC = (uint32_t)Program.Code.size() + 2;
      emit(OP_CBR, 0, kTmpReg, 0, 0, 0, StubPC);
      uint32_t NextBrIdx = (uint32_t)Program.Code.size();
      emit(OP_BR, 0, 0, 0, 0, 0, 0);
      if (!phiCopiesFor(From, Target))
        return false;
      emitFixup(OP_BR, 0, 0, 0, 0, 0, Target);
      Program.Code[NextBrIdx].Imm = (uint32_t)Program.Code.size();
    } else {
      emitFixup(OP_CBR, 0, kTmpReg, 0, 0, 0, Target);
    }
  }
  emitFixup(OP_BR, 0, 0, 0, 0, 0, SI.getDefaultDest());
  return true;
}

bool VMTranslator::translateTerminator(Instruction &I) {
  BasicBlock *BB = I.getParent();
  if (auto *BI = dyn_cast<BranchInst>(&I)) {
    if (BI->isUnconditional()) {
      BasicBlock *To = BI->getSuccessor(0);
      if (!phiCopiesFor(BB, To))
        return false;
      emitFixup(OP_BR, 0, 0, 0, 0, 0, To);
      return true;
    }
    BasicBlock *T = BI->getSuccessor(0);
    BasicBlock *F = BI->getSuccessor(1);
    uint8_t Cond = regOf(BI->getCondition());
    if (Failed)
      return false;

    bool TPhi = hasPhi(T), FPhi = hasPhi(F);
    if (!TPhi && !FPhi) {
      emitFixup(OP_CBR, 0, Cond, 0, 0, 0, T);
      emitFixup(OP_BR, 0, 0, 0, 0, 0, F);
      return true;
    }

    uint32_t TrueStub = (uint32_t)Program.Code.size() + 2;
    emit(OP_CBR, 0, Cond, 0, 0, 0, TrueStub);
    uint32_t FalseBrIdx = (uint32_t)Program.Code.size();
    emit(OP_BR, 0, 0, 0, 0, 0, 0);
    if (!phiCopiesFor(BB, T))
      return false;
    emitFixup(OP_BR, 0, 0, 0, 0, 0, T);
    Program.Code[FalseBrIdx].Imm = (uint32_t)Program.Code.size();
    if (!phiCopiesFor(BB, F))
      return false;
    emitFixup(OP_BR, 0, 0, 0, 0, 0, F);
    return true;
  }
  if (auto *SI = dyn_cast<SwitchInst>(&I))
    return translateSwitch(*SI);
  if (auto *RI = dyn_cast<ReturnInst>(&I)) {
    if (Value *RV = RI->getReturnValue()) {
      uint8_t W;
      if (!widthCodeForBits(bitWidthOf(RV->getType(), DL), W))
        return fail("return width");
      uint8_t R = regOf(RV);
      if (Failed)
        return false;
      emit(OP_RET, W, R);
    } else {
      emit(OP_RET, 0);
    }
    return true;
  }
  if (isa<UnreachableInst>(&I)) {
    emit(OP_TRAP, 0);
    return true;
  }
  return fail(Twine("unsupported terminator: ") + I.getOpcodeName());
}

bool VMTranslator::translateInst(Instruction &I) {
  if (isa<PHINode>(I))
    return true;
  if (isa<DbgInfoIntrinsic>(I))
    return true;

  if (auto *MI = dyn_cast<MemIntrinsic>(&I)) {
    if (MI->isVolatile())
      return fail("volatile memintrinsic");
    bool IsSet = isa<MemSetInst>(MI);
    const char *Name = IsSet ? "memset"
                             : (isa<MemMoveInst>(MI) ? "memmove" : "memcpy");
    LLVMContext &C = M.getContext();
    Type *Ptr = PointerType::getUnqual(C);
    FunctionType *FT = FunctionType::get(
        Ptr, {Ptr, IsSet ? Type::getInt32Ty(C) : Ptr,
              MI->getLength()->getType()},
        false);
    Function *Fn = cast<Function>(M.getOrInsertFunction(Name, FT).getCallee());
    SmallVector<Type *, 4> MTys = {Ptr, IsSet ? Type::getInt32Ty(C) : Ptr,
                                   MI->getLength()->getType()};
    unsigned Id = thunkForFunction(Fn, MTys);
    uint8_t Dst0 = kArgBase;
    uint8_t Src0 = kArgBase + 1;
    uint8_t Len0 = kArgBase + 2;
    uint8_t W;
    if (!widthCodeForBits(bitWidthOf(Ptr, DL), W))
      return fail("memintrinsic pointer width");
    emit(OP_MOV, W, Dst0, regOf(MI->getRawDest()));
    if (IsSet) {
      uint8_t VW;
      if (!widthCodeForBits(
              bitWidthOf(cast<MemSetInst>(MI)->getValue()->getType(), DL), VW))
        return fail("memset value width");
      emit(OP_MOV, VW, Src0,
           regOf(cast<MemSetInst>(MI)->getValue()));
    } else {
      Value *Src = nullptr;
      if (auto *MC = dyn_cast<MemCpyInst>(MI))
        Src = MC->getRawSource();
      else if (auto *MM = dyn_cast<MemMoveInst>(MI))
        Src = MM->getRawSource();
      if (!Src)
        return fail("memintrinsic source");
      emit(OP_MOV, W, Src0, regOf(Src));
    }
    uint8_t LW;
    if (!widthCodeForBits(bitWidthOf(MI->getLength()->getType(), DL), LW))
      return fail("memintrinsic length width");
    emit(OP_MOV, LW, Len0, regOf(MI->getLength()));
    emit(OP_CALL, 0, 0, 0, 0, 3, Id);
    return true;
  }

  if (auto *UO = dyn_cast<UnaryOperator>(&I)) {
    if (UO->getOpcode() == Instruction::FNeg) {
      uint8_t W;
      if (!storageWidthCode(UO->getType(), DL, W))
        return fail("fneg width");
      uint8_t A = allocReg();
      uint8_t B = regOf(UO->getOperand(0));
      if (Failed)
        return false;
      emit(OP_FNEG, W, A, B);
      Regs[&I] = A;
      return true;
    }
    return fail("unsupported unary operator");
  }

  if (auto *CI = dyn_cast<CallInst>(&I)) {
    Function *Callee = CI->getCalledFunction();
    if (Callee && Callee->isIntrinsic()) {
      switch (Callee->getIntrinsicID()) {
      case Intrinsic::lifetime_start:
      case Intrinsic::lifetime_end:
      case Intrinsic::dbg_declare:
      case Intrinsic::dbg_value:
      case Intrinsic::dbg_label:
      case Intrinsic::dbg_assign:
      case Intrinsic::assume:
      case Intrinsic::experimental_noalias_scope_decl:
      case Intrinsic::prefetch:
        return true;
      case Intrinsic::trap:
        emit(OP_TRAP, 0);
        return true;
      case Intrinsic::expect:
      case Intrinsic::expect_with_probability: {
        uint8_t W;
        if (!storageWidthCode(CI->getType(), DL, W))
          return fail("expect width");
        uint8_t R = regOf(CI->getArgOperand(0));
        if (Failed)
          return false;
        Regs[&I] = R;
        return true;
      }
      case Intrinsic::smax:
      case Intrinsic::smin:
      case Intrinsic::umax:
      case Intrinsic::umin: {
        Value *X = CI->getArgOperand(0);
        Value *Y = CI->getArgOperand(1);
        uint8_t W;
        if (!storageWidthCode(X->getType(), DL, W))
          return fail("min/max width");
        uint8_t Bv = regOf(X);
        uint8_t Cv = regOf(Y);
        uint8_t Cmp = allocReg();
        uint8_t A = allocReg();
        if (Failed)
          return false;
        uint8_t CmpOp;
        switch (Callee->getIntrinsicID()) {
        case Intrinsic::smax: CmpOp = OP_ICMP_SGT; break;
        case Intrinsic::smin: CmpOp = OP_ICMP_SLT; break;
        case Intrinsic::umax: CmpOp = OP_ICMP_UGT; break;
        default:              CmpOp = OP_ICMP_ULT; break;
        }
        emit(CmpOp, W, Cmp, Bv, Cv);
        emit(OP_SELECT, W, A, Cmp, Bv, 0, Cv);
        Regs[&I] = A;
        return true;
      }
      case Intrinsic::fabs:
      case Intrinsic::sqrt:
      case Intrinsic::fmuladd: {
        Type *T = CI->getArgOperand(0)->getType();
        uint8_t W;
        if (!storageWidthCode(T, DL, W))
          return fail("fp intrinsic width");
        uint8_t A = allocReg();
        uint8_t Bv = regOf(CI->getArgOperand(0));
        if (Failed)
          return false;
        if (Callee->getIntrinsicID() == Intrinsic::fmuladd) {
          uint8_t Cv = regOf(CI->getArgOperand(1));
          uint8_t Dv = regOf(CI->getArgOperand(2));
          if (Failed)
            return false;
          emit(OP_FMA, W, A, Bv, Cv, 0, Dv);
        } else {
          emit(Callee->getIntrinsicID() == Intrinsic::fabs ? OP_FABS
                                                           : OP_FSQRT,
               W, A, Bv);
        }
        Regs[&I] = A;
        return true;
      }
      case Intrinsic::ctpop:
      case Intrinsic::ctlz:
      case Intrinsic::cttz:
      case Intrinsic::bswap:
      case Intrinsic::bitreverse: {
        Value *X = CI->getArgOperand(0);
        uint8_t W;
        if (!widthCodeForBits(bitWidthOf(X->getType(), DL), W))
          return fail("bit intrinsic width");
        uint8_t A = allocReg();
        uint8_t Bv = regOf(X);
        if (Failed)
          return false;
        uint8_t Op;
        switch (Callee->getIntrinsicID()) {
        case Intrinsic::ctpop: Op = OP_CTPOP; break;
        case Intrinsic::ctlz: Op = OP_CTLZ; break;
        case Intrinsic::cttz: Op = OP_CTTZ; break;
        case Intrinsic::bswap: Op = OP_BSWAP; break;
        default: Op = OP_BITREVERSE; break;
        }
        emit(Op, W, A, Bv);
        Regs[&I] = A;
        return true;
      }
      default:
        return fail("unsupported intrinsic: " + Callee->getName());
      }
    }
    return translateCall(*CI);
  }

  if (auto *AI = dyn_cast<AllocaInst>(&I)) {
    if (!AllocaOff.count(AI))
      return fail("dynamic/non-entry alloca");
    return true;
  }
  if (isa<LandingPadInst>(I) || isa<ResumeInst>(I) || isa<CatchPadInst>(I) ||
      isa<CleanupPadInst>(I) || isa<CatchSwitchInst>(I) ||
      isa<CatchReturnInst>(I) || isa<CleanupReturnInst>(I))
    return fail("EH instruction");
  if (isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I) ||
      isa<FenceInst>(I))
    return fail("atomic instruction");
  if (isa<VAArgInst>(I))
    return fail("va_arg");

  if (I.isTerminator())
    return translateTerminator(I);

  Type *Ty = I.getType();
  if (!Ty->isVoidTy() && !isSupportedScalar(Ty, DL))
    return fail("unsupported value type");

  if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
    uint8_t W;
    if (!storageWidthCode(BO->getType(), DL, W))
      return fail("binary op width");
    if (!BO->getType()->isIntegerTy()) {
      if (!BO->getType()->isFloatTy() && !BO->getType()->isDoubleTy())
        return fail("unsupported binary operand type");
      uint8_t A = allocReg();
      uint8_t B = regOf(BO->getOperand(0));
      uint8_t C = regOf(BO->getOperand(1));
      if (Failed)
        return false;
      uint8_t Op;
      switch (BO->getOpcode()) {
      case Instruction::FAdd: Op = OP_FADD; break;
      case Instruction::FSub: Op = OP_FSUB; break;
      case Instruction::FMul: Op = OP_FMUL; break;
      case Instruction::FDiv: Op = OP_FDIV; break;
      case Instruction::FRem: Op = OP_FREM; break;
      default: return fail("unsupported fp binary operator");
      }
      emit(Op, W, A, B, C);
      Regs[&I] = A;
      return true;
    }
    uint8_t A = allocReg();
    uint8_t B = regOf(BO->getOperand(0));
    uint8_t C = regOf(BO->getOperand(1));
    if (Failed)
      return false;
    uint8_t Op;
    switch (BO->getOpcode()) {
    case Instruction::Add:  Op = OP_ADD; break;
    case Instruction::Sub:  Op = OP_SUB; break;
    case Instruction::Mul:  Op = OP_MUL; break;
    case Instruction::UDiv: Op = OP_UDIV; break;
    case Instruction::SDiv: Op = OP_SDIV; break;
    case Instruction::URem: Op = OP_UREM; break;
    case Instruction::SRem: Op = OP_SREM; break;
    case Instruction::And:  Op = OP_AND; break;
    case Instruction::Or:   Op = OP_OR; break;
    case Instruction::Xor:  Op = OP_XOR; break;
    case Instruction::Shl:  Op = OP_SHL; break;
    case Instruction::LShr: Op = OP_LSHR; break;
    case Instruction::AShr: Op = OP_ASHR; break;
    default: return fail("unsupported binary operator");
    }
    emit(Op, W, A, B, C);
    Regs[&I] = A;
    return true;
  }

  if (auto *FC = dyn_cast<FCmpInst>(&I)) {
    uint8_t W;
    if (!storageWidthCode(FC->getOperand(0)->getType(), DL, W))
      return fail("fcmp width");
    uint8_t A = allocReg();
    uint8_t B = regOf(FC->getOperand(0));
    uint8_t C = regOf(FC->getOperand(1));
    if (Failed)
      return false;
    emit(OP_FCMP, W, A, B, C, 0, (uint32_t)FC->getPredicate());
    Regs[&I] = A;
    return true;
  }

  if (auto *CI = dyn_cast<ICmpInst>(&I)) {
    Value *L = CI->getOperand(0);
    Type *OT = L->getType();
    if (!isSupportedScalar(OT, DL))
      return fail("icmp operand type");
    if (OT->isPointerTy() && CI->getPredicate() != CmpInst::ICMP_EQ &&
        CI->getPredicate() != CmpInst::ICMP_NE)
      return fail("relational pointer compare");
    uint8_t W;
    if (!widthCodeForBits(bitWidthOf(OT, DL), W))
      return fail("icmp width");
    uint8_t A = allocReg();
    uint8_t B = regOf(L);
    uint8_t C = regOf(CI->getOperand(1));
    if (Failed)
      return false;
    uint8_t Op;
    switch (CI->getPredicate()) {
    case CmpInst::ICMP_EQ:  Op = OP_ICMP_EQ; break;
    case CmpInst::ICMP_NE:  Op = OP_ICMP_NE; break;
    case CmpInst::ICMP_UGT: Op = OP_ICMP_UGT; break;
    case CmpInst::ICMP_UGE: Op = OP_ICMP_UGE; break;
    case CmpInst::ICMP_ULT: Op = OP_ICMP_ULT; break;
    case CmpInst::ICMP_ULE: Op = OP_ICMP_ULE; break;
    case CmpInst::ICMP_SGT: Op = OP_ICMP_SGT; break;
    case CmpInst::ICMP_SGE: Op = OP_ICMP_SGE; break;
    case CmpInst::ICMP_SLT: Op = OP_ICMP_SLT; break;
    case CmpInst::ICMP_SLE: Op = OP_ICMP_SLE; break;
    default: return fail("unsupported icmp predicate");
    }
    emit(Op, W, A, B, C);
    Regs[&I] = A;
    return true;
  }

  if (auto *SI = dyn_cast<SelectInst>(&I)) {
    if (!isSupportedScalar(SI->getType(), DL))
      return fail("select type");
    uint8_t W;
    if (!widthCodeForBits(bitWidthOf(SI->getType(), DL), W))
      return fail("select width");
    uint8_t A = allocReg();
    uint8_t B = regOf(SI->getCondition());
    uint8_t C = regOf(SI->getTrueValue());
    uint8_t D = regOf(SI->getFalseValue());
    if (Failed)
      return false;
    emit(OP_SELECT, W, A, B, C, 0, D);
    Regs[&I] = A;
    return true;
  }

  if (auto *CI = dyn_cast<CastInst>(&I)) {
    unsigned DstBits = bitWidthOf(CI->getType(), DL);
    unsigned SrcBits = bitWidthOf(CI->getOperand(0)->getType(), DL);
    uint8_t DW, SW;
    if (!widthCodeForBits(DstBits, DW) || !widthCodeForBits(SrcBits, SW))
      return fail("cast width");
    uint8_t B = regOf(CI->getOperand(0));
    uint8_t A = allocReg();
    if (Failed)
      return false;
    switch (CI->getOpcode()) {
    case Instruction::FPExt:
      emit(OP_FPEXT, DW, A, B, 0, SW);
      break;
    case Instruction::FPTrunc:
      emit(OP_FPTRUNC, DW, A, B, 0, SW);
      break;
    case Instruction::FPToSI:
      emit(OP_FPTOSI, DW, A, B, 0, SW);
      break;
    case Instruction::FPToUI:
      emit(OP_FPTOUI, DW, A, B, 0, SW);
      break;
    case Instruction::SIToFP:
    case Instruction::UIToFP: {
      // Normalise the integer source to 64 bits so the handler only needs to
      // deal with the two floating-point widths.
      uint8_t X = allocReg();
      if (Failed)
        return false;
      emit(CI->getOpcode() == Instruction::SIToFP ? OP_SEXT : OP_ZEXT, W_I64,
           X, B, 0, SW);
      emit(CI->getOpcode() == Instruction::SIToFP ? OP_SITOFP : OP_UITOFP, DW,
           A, X, 0, W_I64);
      break;
    }
    case Instruction::Trunc:
      emit(OP_TRUNC, DW, A, B, 0, SW);
      break;
    case Instruction::ZExt:
      emit(OP_ZEXT, DW, A, B, 0, SW);
      break;
    case Instruction::SExt:
      emit(OP_SEXT, DW, A, B, 0, SW);
      break;
    case Instruction::PtrToInt:
    case Instruction::IntToPtr:
      if (SrcBits > DstBits)
        emit(OP_TRUNC, DW, A, B, 0, SW);
      else if (SrcBits < DstBits)
        emit(OP_ZEXT, DW, A, B, 0, SW);
      else
        emit(OP_MOV, DW, A, B);
      break;
    case Instruction::BitCast:
      if (SrcBits != DstBits)
        return fail("bitcast width change");
      emit(OP_MOV, DW, A, B);
      break;
    case Instruction::AddrSpaceCast:
      if (CI->getOperand(0)->getType()->getPointerAddressSpace() != 0 ||
          CI->getType()->getPointerAddressSpace() != 0)
        return fail("addrspacecast");
      emit(OP_MOV, DW, A, B);
      break;
    default:
      return fail("unsupported cast");
    }
    Regs[&I] = A;
    return true;
  }

  if (auto *LI = dyn_cast<LoadInst>(&I)) {
    if (!LI->isSimple())
      return fail("volatile/atomic load");
    if (!isSupportedScalar(LI->getType(), DL))
      return fail("load type");
    uint8_t W;
    if (!widthCodeForBits(bitWidthOf(LI->getType(), DL), W))
      return fail("load width");
    uint8_t A = allocReg();
    uint8_t B = regOf(LI->getPointerOperand());
    if (Failed)
      return false;
    emit(OP_LOAD, W, A, B);
    Regs[&I] = A;
    return true;
  }

  if (auto *SI = dyn_cast<StoreInst>(&I)) {
    if (!SI->isSimple())
      return fail("volatile/atomic store");
    if (!isSupportedScalar(SI->getValueOperand()->getType(), DL))
      return fail("store type");
    uint8_t W;
    if (!widthCodeForBits(
            bitWidthOf(SI->getValueOperand()->getType(), DL), W))
      return fail("store width");
    uint8_t A = regOf(SI->getPointerOperand());
    uint8_t B = regOf(SI->getValueOperand());
    if (Failed)
      return false;
    emit(OP_STORE, W, A, B);
    return true;
  }

  if (auto *GEP = dyn_cast<GetElementPtrInst>(&I))
    return translateGEP(*GEP);

  if (isa<FreezeInst>(&I)) {
    uint8_t W;
    if (!widthCodeForBits(bitWidthOf(I.getType(), DL), W))
      return fail("freeze width");
    uint8_t A = allocReg();
    uint8_t B = regOf(I.getOperand(0));
    if (Failed)
      return false;
    emit(OP_MOV, W, A, B);
    Regs[&I] = A;
    return true;
  }

  return fail(Twine("unsupported instruction: ") + I.getOpcodeName());
}

bool VMTranslator::translateBlock(BasicBlock &BB) {
  for (PHINode &PN : BB.phis()) {
    if (!Regs.count(&PN)) {
      uint8_t R = allocReg();
      if (Failed)
        return false;
      Regs[&PN] = R;
    }
  }
  for (Instruction &I : BB)
    if (!translateInst(I))
      return false;
  return true;
}

bool VMTranslator::run() {
  if (!functionShapeOK(F, DL, Reason))
    return false;

  PtrBits = DL.getPointerSizeInBits(0);
  RngState = Seed ^ 0xD1B54A32D192ED03ULL ^
             (uint64_t)F.arg_size() * 1315423911ULL;
  for (char C : F.getName())
    RngState = RngState * 131 + (unsigned char)C;

  for (Argument &A : F.args()) {
    uint8_t R = allocReg();
    if (Failed)
      return false;
    Regs[&A] = R;
  }
  Program.ArgCount = (unsigned)F.arg_size();

  uint8_t Perm[OP_COUNT];
  for (unsigned I = 0; I < OP_COUNT; ++I)
    Perm[I] = (uint8_t)I;
  for (unsigned I = OP_COUNT; I > 1; --I) {
    unsigned J = (unsigned)(nextRand() % I);
    std::swap(Perm[I - 1], Perm[J]);
  }
  for (unsigned I = 0; I < OP_COUNT; ++I)
    Program.OpMap[I] = Perm[I];

  std::vector<BasicBlock *> Order;
  DenseSet<BasicBlock *> Seen;
  SmallVector<BasicBlock *, 16> Stack;
  Stack.push_back(&F.getEntryBlock());
  while (!Stack.empty()) {
    BasicBlock *BB = Stack.pop_back_val();
    if (!Seen.insert(BB).second)
      continue;
    Order.push_back(BB);
    for (BasicBlock *S : successors(BB))
      Stack.push_back(S);
  }

  // Hoist every constant to a prologue so a value materialised in one arm is
  // still available on every other path (constants must dominate all uses).
  for (BasicBlock *BB : Order) {
    for (Instruction &I : *BB) {
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        for (Use &U : CB->args())
          collectConstant(U.get());
      } else {
        for (Value *Op : I.operands())
          collectConstant(Op);
      }
      if (auto *PN = dyn_cast<PHINode>(&I))
        for (Value *V : PN->incoming_values())
          collectConstant(V);
    }
  }
  for (Constant *C : ConstOrder) {
    if (Regs.count(C))
      continue;
    uint8_t R = allocReg();
    if (Failed)
      return false;
    if (!materialize(C, R, C->getType()))
      return false;
    Regs[C] = R;
  }

  // Static allocas live in the wrapper's frame.  Only entry-block allocas with
  // a constant size are accepted; a loop alloca would need a fresh slot per
  // iteration and is left untouched.
  BasicBlock &Entry = F.getEntryBlock();
  for (Instruction &I : Entry) {
    auto *AI = dyn_cast<AllocaInst>(&I);
    if (!AI)
      continue;
    if (AI->isSwiftError() || AI->isUsedWithInAlloca() ||
        AI->getAllocatedType()->isScalableTy())
      return fail("special/scalable alloca");
    if (AI->isArrayAllocation()) {
      auto *N = dyn_cast<ConstantInt>(AI->getArraySize());
      if (!N)
        return fail("dynamic alloca");
      uint64_t Count = N->getZExtValue();
      uint64_t Elem = DL.getTypeAllocSize(AI->getAllocatedType()).getFixedValue();
      uint64_t Size = Count * Elem;
      uint64_t A = std::max<uint64_t>(AI->getAlign().value(), 1);
      FrameSize = alignTo(FrameSize, A);
      AllocaOff[AI] = FrameSize;
      FrameSize += std::max<uint64_t>(Size, 1);
    } else {
      uint64_t Size =
          DL.getTypeAllocSize(AI->getAllocatedType()).getFixedValue();
      uint64_t A = std::max<uint64_t>(AI->getAlign().value(), 1);
      FrameSize = alignTo(FrameSize, A);
      AllocaOff[AI] = FrameSize;
      FrameSize += std::max<uint64_t>(Size, 1);
    }
    Allocas.push_back(AI);
  }
  for (AllocaInst *AI : Allocas) {
    uint8_t R = allocReg();
    if (Failed)
      return false;
    Regs[AI] = R;
    uint64_t Off = AllocaOff[AI];
    emit(OP_MOV, W_PTR, R, kFrameReg);
    if (Off) {
      uint8_t CR = allocReg();
      if (Failed)
        return false;
      emit(OP_IMM, W_I64, CR, 0, 0, 0, addIntConst(Off));
      uint8_t NR = allocReg();
      if (Failed)
        return false;
      emit(OP_ADD, W_I64, NR, R, CR);
      if (PtrBits < 64) {
        uint8_t TR = allocReg();
        if (Failed)
          return false;
        emit(OP_TRUNC, W_PTR, TR, NR, 0, W_I64);
        Regs[AI] = TR;
      } else {
        Regs[AI] = NR;
      }
    }
  }
  Program.FrameSize = FrameSize;
  Program.EntryPC = 0;
  for (BasicBlock *BB : Order) {
    BlockPC[BB] = (uint32_t)Program.Code.size();
    if (!translateBlock(*BB))
      return false;
  }

  for (auto &FX : Fixups) {
    auto It = BlockPC.find(FX.second);
    if (It == BlockPC.end())
      return fail("branch to unreachable block");
    Program.Code[FX.first].Imm = It->second;
  }

  Program.Key = nextRand() | 1;
  Program.Level = Level;
  Program.BodyHash = nextRand();

  // Level 2+: permute all non-argument registers.  Arguments stay at
  // 0..ArgCount-1 because the interpreter prologue writes them there.
  if (Level >= 2) {
    uint8_t Perm[236];
    for (unsigned I = 0; I < 236; ++I)
      Perm[I] = (uint8_t)I;
    for (unsigned I = 236; I > std::max(Program.ArgCount, 1u); --I) {
      unsigned J = Program.ArgCount +
                   (unsigned)(nextRand() % (I - Program.ArgCount));
      std::swap(Perm[I - 1], Perm[J]);
    }
    auto Map = [&](uint8_t &R) {
      if (R <= 235)
        R = Perm[R];
    };
    for (VInst &I : Program.Code) {
      Map(I.A);
      Map(I.B);
      Map(I.C);
      if ((I.Op == OP_SELECT || I.Op == OP_FMA) && I.Imm <= 235)
        I.Imm = Perm[I.Imm];
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Runtime emission
// ---------------------------------------------------------------------------

static std::string randomName(uint64_t &State, StringRef Prefix) {
  uint64_t A = splitmix64(State);
  uint64_t B = splitmix64(State);
  return (Prefix + Twine::utohexstr(A) + Twine::utohexstr(B)).str();
}

static Value *gepI8(IRBuilder<> &B, Value *Base, uint64_t Off,
                    const Twine &N = "") {
  return B.CreateGEP(B.getInt8Ty(), Base, B.getInt64(Off), N);
}

static Type *typeForWidth(LLVMContext &Ctx, unsigned W) {
  switch (W) {
  case W_I1:  return Type::getInt1Ty(Ctx);
  case W_I8:  return Type::getInt8Ty(Ctx);
  case W_I16: return Type::getInt16Ty(Ctx);
  case W_I32: return Type::getInt32Ty(Ctx);
  case W_I64: return Type::getInt64Ty(Ctx);
  default:    return PointerType::getUnqual(Ctx);
  }
}

class VMRuntimeBuilder {
public:
  VMRuntimeBuilder(Function &Wrapper, VMProgram &P, uint64_t Seed,
                   std::string &Reason)
      : Wrapper(Wrapper), P(P), M(*Wrapper.getParent()),
        Ctx(M.getContext()), DL(M.getDataLayout()), Reason(Reason) {
    RngState = Seed ^ P.BodyHash;
  }

  Function *build();
  bool emitWrapper();
  void discard();

  std::vector<GlobalVariable *> CreatedGlobals;
  std::vector<Function *> CreatedFunctions;

private:
  Function &Wrapper;
  VMProgram &P;
  Module &M;
  LLVMContext &Ctx;
  const DataLayout &DL;
  std::string &Reason;
  uint64_t RngState;

  GlobalVariable *CodeGV = nullptr;
  GlobalVariable *IntGV = nullptr;
  GlobalVariable *PtrGV = nullptr;
  GlobalVariable *ThunkGV = nullptr;
  GlobalVariable *BitsGV = nullptr;
  Function *Interp = nullptr;

  bool fail(const Twine &Msg) {
    if (Reason.empty())
      Reason = Msg.str();
    return false;
  }

  bool createThunks();
  bool createGlobals();
  Function *createInterpreter();
};

bool VMRuntimeBuilder::createThunks() {
  IRBuilder<> B(Ctx);
  Type *I64 = B.getInt64Ty();
  Type *Ptr = B.getPtrTy();
  auto unmarshal = [&](Value *V, Type *T) -> Value * {
    if (T->isPointerTy())
      return B.CreateIntToPtr(V, T);
    if (T->isFloatTy())
      return B.CreateBitCast(B.CreateTrunc(V, B.getInt32Ty()), T);
    if (T->isDoubleTy())
      return B.CreateBitCast(V, T);
    if (T->isIntegerTy() && T->getIntegerBitWidth() < 64)
      return B.CreateTrunc(V, T);
    return V;
  };

  for (unsigned Id = 0; Id < P.Thunks.size(); ++Id) {
    const VMThunk &D = P.Thunks[Id];
    FunctionType *ThunkFT = FunctionType::get(I64, {Ptr, Ptr}, false);
    Function *T = Function::Create(ThunkFT, GlobalValue::InternalLinkage,
                                   randomName(RngState, "__o"), &M);
    T->addFnAttr(kGeneratedAttr);
    CreatedFunctions.push_back(T);
    BasicBlock *Entry = BasicBlock::Create(Ctx, "", T);
    B.SetInsertPoint(Entry);

    Value *Args = T->getArg(0);
    SmallVector<Value *, 8> CallArgs;
    for (unsigned I = 0; I < D.ArgTys.size(); ++I) {
      Value *Pp = gepI8(B, Args, I * 8);
      Value *V = B.CreateAlignedLoad(I64, Pp, Align(8), false);
      CallArgs.push_back(unmarshal(V, D.ArgTys[I]));
    }

    CallInst *Call;
    if (D.Direct) {
      Call = B.CreateCall(D.Direct, CallArgs);
      Call->setCallingConv(D.Direct->getCallingConv());
      Call->setAttributes(D.Direct->getAttributes());
    } else {
      Call = B.CreateCall(D.SiteFT, T->getArg(1), CallArgs);
      Call->setCallingConv(CallingConv::C);
    }
    Call->setTailCallKind(CallInst::TCK_None);

    Type *RT = D.RetTy;
    if (RT->isVoidTy())
      B.CreateRet(B.getInt64(0));
    else if (RT->isPointerTy())
      B.CreateRet(B.CreatePtrToInt(Call, I64));
    else if (RT->isFloatTy())
      B.CreateRet(B.CreateZExt(B.CreateBitCast(Call, B.getInt32Ty()), I64));
    else if (RT->isDoubleTy())
      B.CreateRet(B.CreateBitCast(Call, I64));
    else if (RT->getIntegerBitWidth() < 64)
      B.CreateRet(B.CreateZExt(Call, I64));
    else
      B.CreateRet(Call);
  }
  return true;
}

bool VMRuntimeBuilder::createGlobals() {
  IRBuilder<> B(Ctx);
  IntegerType *I32 = B.getInt32Ty();
  Type *I64 = B.getInt64Ty();
  Type *Ptr = B.getPtrTy();

  std::vector<uint32_t> Words;
  Words.reserve(P.Code.size() * 3);
  for (uint32_t I = 0; I < P.Code.size(); ++I) {
    const VInst &V = P.Code[I];
    uint32_t W0 = (uint32_t)P.OpMap[V.Op] | ((uint32_t)V.W << 8) |
                  ((uint32_t)V.A << 16) | ((uint32_t)V.B << 24);
    uint32_t W1 = (uint32_t)V.C | ((uint32_t)V.Flags << 8);
    uint32_t W2 = V.Imm;
    // The stream is indexed by PC, not by execution order: a branch must not
    // desynchronise the decoder.
    uint64_t K = P.Key + (uint64_t)I * streamStride(P.Key);
    for (uint32_t W : {W0, W1, W2}) {
      uint32_t KS = (uint32_t)(K >> 32);
      Words.push_back(W ^ KS);
      K = K * streamMul(P.Key) + streamInc(P.Key);
    }
  }
  ArrayType *CodeTy = ArrayType::get(I32, Words.size());
  std::vector<Constant *> WordConsts;
  WordConsts.reserve(Words.size());
  for (uint32_t W : Words)
    WordConsts.push_back(ConstantInt::get(I32, W));
  CodeGV = new GlobalVariable(M, CodeTy, false, GlobalValue::InternalLinkage,
                              ConstantArray::get(CodeTy, WordConsts),
                              randomName(RngState, "__o"));
  CodeGV->setAlignment(Align(16));
  CreatedGlobals.push_back(CodeGV);

  // The pools always exist, even when empty: handlers are emitted
  // unconditionally and must never GEP a null global.
  {
    size_t N = std::max<size_t>(P.Ints.size(), 1);
    ArrayType *Ty = ArrayType::get(I64, N);
    std::vector<Constant *> Cs;
    for (unsigned I = 0; I < P.Ints.size(); ++I) {
      uint64_t V = P.Ints[I];
      if (P.Level >= 2)
        V ^= constMask(P.Key, I);
      Cs.push_back(ConstantInt::get(I64, V));
    }
    while (Cs.size() < N)
      Cs.push_back(ConstantInt::get(I64, 0));
    IntGV = new GlobalVariable(M, Ty, true, GlobalValue::InternalLinkage,
                               ConstantArray::get(Ty, Cs),
                               randomName(RngState, "__o"));
    IntGV->setAlignment(Align(8));
    CreatedGlobals.push_back(IntGV);
  }

  {
    size_t N = std::max<size_t>(P.Ptrs.size(), 1);
    ArrayType *Ty = ArrayType::get(Ptr, N);
    std::vector<Constant *> Cs(P.Ptrs.begin(), P.Ptrs.end());
    while (Cs.size() < N)
      Cs.push_back(ConstantPointerNull::get(cast<PointerType>(Ptr)));
    PtrGV = new GlobalVariable(M, Ty, true, GlobalValue::InternalLinkage,
                               ConstantArray::get(Ty, Cs),
                               randomName(RngState, "__o"));
    PtrGV->setAlignment(Align(8));
    CreatedGlobals.push_back(PtrGV);
  }

  {
    size_t N = std::max<size_t>(P.Thunks.size(), 1);
    ArrayType *Ty = ArrayType::get(Ptr, N);
    std::vector<Constant *> Cs;
    for (unsigned I = 0; I < P.Thunks.size(); ++I)
      Cs.push_back(CreatedFunctions[I]);
    while (Cs.size() < N)
      Cs.push_back(ConstantPointerNull::get(cast<PointerType>(Ptr)));
    ThunkGV = new GlobalVariable(M, Ty, true, GlobalValue::InternalLinkage,
                                 ConstantArray::get(Ty, Cs),
                                 randomName(RngState, "__o"));
    ThunkGV->setAlignment(Align(8));
    CreatedGlobals.push_back(ThunkGV);
  }

  std::vector<Constant *> BC;
  for (unsigned V : {1u, 8u, 16u, 32u, 64u,
                     (unsigned)DL.getPointerSizeInBits(0)})
    BC.push_back(ConstantInt::get(I32, V));
  ArrayType *BT = ArrayType::get(I32, BC.size());
  BitsGV = new GlobalVariable(M, BT, true, GlobalValue::InternalLinkage,
                              ConstantArray::get(BT, BC),
                              randomName(RngState, "__o"));
  BitsGV->setAlignment(Align(4));
  CreatedGlobals.push_back(BitsGV);
  return true;
}

namespace {
struct Decoded {
  Value *Pc;
  Value *Op;
  Value *W;
  Value *A;
  Value *B;
  Value *C;
  Value *Flags;
  Value *Imm;
  Value *Regs;
  Value *PcSlot;
};
} // namespace

Function *VMRuntimeBuilder::createInterpreter() {
  IRBuilder<> B(Ctx);
  Type *I64 = B.getInt64Ty();
  IntegerType *I32 = B.getInt32Ty();
  Type *Ptr = B.getPtrTy();
  // Randomised slot count: the register file is still indexed by an 8-bit
  // operand, but the array no longer has a constant, recognisable size.
  unsigned RegSlots = 256 + (unsigned)((P.Key >> 8) & 0x7f);
  Type *RegArrayTy = ArrayType::get(I64, RegSlots);

  FunctionType *FT = FunctionType::get(I64, {Ptr, Ptr}, false);
  Function *Fn = Function::Create(FT, GlobalValue::InternalLinkage,
                                  randomName(RngState, "__o"), &M);
  Fn->addFnAttr(Attribute::NoInline);
  Fn->addFnAttr(kGeneratedAttr);
  CreatedFunctions.push_back(Fn);
  Interp = Fn;

  BasicBlock *Entry = BasicBlock::Create(Ctx, "", Fn);
  BasicBlock *Loop = BasicBlock::Create(Ctx, "", Fn);
  BasicBlock *Dispatch = BasicBlock::Create(Ctx, "", Fn);
  BasicBlock *Trap = BasicBlock::Create(Ctx, "", Fn);
  B.SetInsertPoint(Entry);

  Value *Regs = B.CreateAlloca(RegArrayTy, nullptr, "r");
  Regs->setName("r");
  Value *PcSlot = B.CreateAlloca(I32, nullptr, "pc");
  PcSlot->setName("pc");


  for (unsigned I = 0; I < P.ArgCount; ++I) {
    Value *Src = gepI8(B, Fn->getArg(0), I * 8);
    Value *V = B.CreateAlignedLoad(I64, Src, Align(8), false);
    Value *Dst = B.CreateGEP(RegArrayTy, Regs, {B.getInt32(0), B.getInt32(I)});
    B.CreateAlignedStore(V, Dst, Align(8));
  }
  {
    Value *FrameBits = B.CreatePtrToInt(Fn->getArg(1), I64);
    Value *Dst = B.CreateGEP(RegArrayTy, Regs,
                             {B.getInt32(0), B.getInt32(kFrameReg)});
    B.CreateAlignedStore(FrameBits, Dst, Align(8));
  }
  B.CreateAlignedStore(B.getInt32(P.EntryPC), PcSlot, Align(4));
  B.CreateBr(Loop);

  B.SetInsertPoint(Loop);
  Value *Pc = B.CreateAlignedLoad(I32, PcSlot, Align(4), false);
  Value *InRange =
      B.CreateICmpULT(Pc, B.getInt32((uint32_t)P.Code.size()));
  B.CreateCondBr(InRange, Dispatch, Trap);

  B.SetInsertPoint(Dispatch);
  Value *Idx = B.CreateMul(Pc, B.getInt32(3));
  Value *W0P = B.CreateGEP(I32, CodeGV, Idx);
  Value *W1P = B.CreateGEP(I32, CodeGV, B.CreateAdd(Idx, B.getInt32(1)));
  Value *W2P = B.CreateGEP(I32, CodeGV, B.CreateAdd(Idx, B.getInt32(2)));
  Value *E0 = B.CreateAlignedLoad(I32, W0P, Align(4), true);
  Value *E1 = B.CreateAlignedLoad(I32, W1P, Align(4), true);
  Value *E2 = B.CreateAlignedLoad(I32, W2P, Align(4), true);

  Value *Ks = B.CreateAdd(
      B.getInt64(P.Key),
      B.CreateMul(B.CreateZExt(Pc, I64), B.getInt64(streamStride(P.Key))));
  auto Decode = [&](Value *E) {
    Value *K32 = B.CreateTrunc(B.CreateLShr(Ks, B.getInt64(32)), I32);
    Value *D = B.CreateXor(E, K32);
    Ks = B.CreateAdd(B.CreateMul(Ks, B.getInt64(streamMul(P.Key))),
                     B.getInt64(streamInc(P.Key)));
    return D;
  };
  Value *D0 = Decode(E0);
  Value *D1 = Decode(E1);
  Value *D2 = Decode(E2);

  Decoded D;
  D.Op = B.CreateAnd(D0, B.getInt32(0xff));
  D.W = B.CreateAnd(B.CreateLShr(D0, B.getInt32(8)), B.getInt32(0xff));
  D.A = B.CreateAnd(B.CreateLShr(D0, B.getInt32(16)), B.getInt32(0xff));
  D.B = B.CreateAnd(B.CreateLShr(D0, B.getInt32(24)), B.getInt32(0xff));
  D.C = B.CreateAnd(D1, B.getInt32(0xff));
  D.Flags = B.CreateAnd(B.CreateLShr(D1, B.getInt32(8)), B.getInt32(0xff));
  D.Imm = D2;
  D.Pc = Pc;
  D.Regs = Regs;
  D.PcSlot = PcSlot;

  SwitchInst *Sw = B.CreateSwitch(D.Op, Trap, OP_COUNT);

  // ---- helpers ----------------------------------------------------------
  auto *RegArrayT = RegArrayTy;
  auto loadReg = [&](Value *IdxV) {
    Value *Pp = B.CreateGEP(RegArrayT, Regs, {B.getInt32(0), IdxV});
    return B.CreateAlignedLoad(I64, Pp, Align(8), false);
  };
  auto storeReg = [&](Value *IdxV, Value *V) {
    Value *Pp = B.CreateGEP(RegArrayT, Regs, {B.getInt32(0), IdxV});
    B.CreateAlignedStore(V, Pp, Align(8));
  };
  auto loadBits = [&](Value *WV) {
    Value *Pp = B.CreateGEP(I32, BitsGV, WV);
    return B.CreateAlignedLoad(I32, Pp, Align(4), false);
  };
  auto zextTo = [&](Value *V, Value *WV) {
    Value *Bits = loadBits(WV);
    Value *Sh = B.CreateSub(B.getInt32(64), Bits);
    Value *ZSh = B.CreateZExt(Sh, I64);
    Value *Mask = B.CreateLShr(ConstantInt::getAllOnesValue(I64), ZSh);
    return B.CreateAnd(V, Mask);
  };
  auto sextTo = [&](Value *V, Value *WV) {
    Value *Bits = loadBits(WV);
    Value *Sh = B.CreateSub(B.getInt32(64), Bits);
    Value *ZSh = B.CreateZExt(Sh, I64);
    return B.CreateAShr(B.CreateShl(V, ZSh), ZSh);
  };
  auto ptrMask = [&]() -> Value * {
    unsigned PB = DL.getPointerSizeInBits(0);
    if (PB >= 64)
      return ConstantInt::getAllOnesValue(I64);
    return ConstantInt::get(I64, (1ULL << PB) - 1);
  };
  auto newBB = [&]() { return BasicBlock::Create(Ctx, "", Fn); };

  auto AddCase = [&](VMOp Op, BasicBlock *BB) {
    Sw->addCase(ConstantInt::get(I32, P.OpMap[Op]), BB);
  };

  // ---- OP_NOP -----------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_NOP, BB);
  }

  // ---- OP_MOV -----------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    storeReg(D.A, zextTo(loadReg(D.B), D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_MOV, BB);
  }

  // ---- OP_IMM -----------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Cp = B.CreateGEP(I64, IntGV, D.Imm);
    Value *V = B.CreateAlignedLoad(I64, Cp, Align(8), P.Level >= 2);
    if (P.Level >= 2) {
      Value *Mask = B.CreateAdd(
          B.getInt64(P.Key),
          B.CreateMul(B.CreateZExt(D.Imm, I64),
                      B.getInt64(0x9E3779B97F4A7C15ULL)));
      V = B.CreateXor(V, Mask);
    }
    storeReg(D.A, zextTo(V, D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_IMM, BB);
  }

  // ---- OP_PTR -----------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Pp = B.CreateGEP(Ptr, PtrGV, D.Imm);
    Value *V = B.CreateAlignedLoad(Ptr, Pp, Align(8), false);
    storeReg(D.A, zextTo(B.CreatePtrToInt(V, I64), D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_PTR, BB);
  }

  // ---- OP_LOAD ----------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *AddrBits = B.CreateAnd(loadReg(D.B), ptrMask());
    Value *Addr = B.CreateIntToPtr(AddrBits, Ptr);
    SwitchInst *WSw = B.CreateSwitch(D.W, Trap, 6);
    for (unsigned W = 0; W < 6; ++W) {
      BasicBlock *CB = newBB();
      B.SetInsertPoint(CB);
      Type *T = typeForWidth(Ctx, W);
      Value *V = B.CreateAlignedLoad(T, Addr, Align(1), false);
      Value *V64;
      if (W == W_PTR)
        V64 = B.CreatePtrToInt(V, I64);
      else if (W == W_I64)
        V64 = V;
      else
        V64 = B.CreateZExt(V, I64);
      storeReg(D.A, V64);
      B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
      B.CreateBr(Loop);
      WSw->addCase(ConstantInt::get(I32, W), CB);
    }
    AddCase(OP_LOAD, BB);
  }

  // ---- OP_STORE ---------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *AddrBits = B.CreateAnd(loadReg(D.A), ptrMask());
    Value *Addr = B.CreateIntToPtr(AddrBits, Ptr);
    Value *V = loadReg(D.B);
    SwitchInst *WSw = B.CreateSwitch(D.W, Trap, 6);
    for (unsigned W = 0; W < 6; ++W) {
      BasicBlock *CB = newBB();
      B.SetInsertPoint(CB);
      Type *T = typeForWidth(Ctx, W);
      Value *SV;
      if (W == W_PTR)
        SV = B.CreateIntToPtr(V, Ptr);
      else if (W == W_I64)
        SV = V;
      else
        SV = B.CreateTrunc(V, T);
      B.CreateAlignedStore(SV, Addr, Align(1));
      B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
      B.CreateBr(Loop);
      WSw->addCase(ConstantInt::get(I32, W), CB);
    }
    AddCase(OP_STORE, BB);
  }

  auto emitBin = [&](VMOp Op, bool Signed, bool Div) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *X = Signed ? sextTo(loadReg(D.B), D.W) : zextTo(loadReg(D.B), D.W);
    Value *Y =
        Signed ? sextTo(loadReg(D.C), D.W) : zextTo(loadReg(D.C), D.W);
    Value *R = nullptr;
    switch (Op) {
    case OP_ADD: R = B.CreateAdd(X, Y); break;
    case OP_SUB: R = B.CreateSub(X, Y); break;
    case OP_MUL: R = B.CreateMul(X, Y); break;
    case OP_AND: R = B.CreateAnd(X, Y); break;
    case OP_OR:  R = B.CreateOr(X, Y); break;
    case OP_XOR: R = B.CreateXor(X, Y); break;
    case OP_UDIV: R = B.CreateUDiv(X, Y); break;
    case OP_SDIV: R = B.CreateSDiv(X, Y); break;
    case OP_UREM: R = B.CreateURem(X, Y); break;
    case OP_SREM: R = B.CreateSRem(X, Y); break;
    default: llvm_unreachable("bad binop");
    }
    storeReg(D.A, zextTo(R, D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(Op, BB);
    (void)Div;
  };
  emitBin(OP_ADD, false, false);
  emitBin(OP_SUB, false, false);
  emitBin(OP_MUL, false, false);
  emitBin(OP_AND, false, false);
  emitBin(OP_OR, false, false);
  emitBin(OP_XOR, false, false);
  emitBin(OP_UDIV, false, true);
  emitBin(OP_SDIV, true, true);
  emitBin(OP_UREM, false, true);
  emitBin(OP_SREM, true, true);

  auto emitShift = [&](VMOp Op) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Bits = loadBits(D.W);
    Value *AmtMask = B.CreateSub(Bits, B.getInt32(1));
    Value *Amt = B.CreateAnd(B.CreateTrunc(loadReg(D.C), I32), AmtMask);
    Value *ZAmt = B.CreateZExt(Amt, I64);
    Value *X = (Op == OP_ASHR) ? sextTo(loadReg(D.B), D.W)
                               : zextTo(loadReg(D.B), D.W);
    Value *R;
    if (Op == OP_SHL)
      R = B.CreateShl(X, ZAmt);
    else if (Op == OP_LSHR)
      R = B.CreateLShr(X, ZAmt);
    else
      R = B.CreateAShr(X, ZAmt);
    storeReg(D.A, zextTo(R, D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(Op, BB);
  };
  emitShift(OP_SHL);
  emitShift(OP_LSHR);
  emitShift(OP_ASHR);

  auto emitCmp = [&](VMOp Op, CmpInst::Predicate Pred, bool Signed) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *X = Signed ? sextTo(loadReg(D.B), D.W) : zextTo(loadReg(D.B), D.W);
    Value *Y = Signed ? sextTo(loadReg(D.C), D.W) : zextTo(loadReg(D.C), D.W);
    Value *Cmp = B.CreateICmp(Pred, X, Y);
    storeReg(D.A, B.CreateZExt(Cmp, I64));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(Op, BB);
  };
  emitCmp(OP_ICMP_EQ, CmpInst::ICMP_EQ, false);
  emitCmp(OP_ICMP_NE, CmpInst::ICMP_NE, false);
  emitCmp(OP_ICMP_UGT, CmpInst::ICMP_UGT, false);
  emitCmp(OP_ICMP_UGE, CmpInst::ICMP_UGE, false);
  emitCmp(OP_ICMP_ULT, CmpInst::ICMP_ULT, false);
  emitCmp(OP_ICMP_ULE, CmpInst::ICMP_ULE, false);
  emitCmp(OP_ICMP_SGT, CmpInst::ICMP_SGT, true);
  emitCmp(OP_ICMP_SGE, CmpInst::ICMP_SGE, true);
  emitCmp(OP_ICMP_SLT, CmpInst::ICMP_SLT, true);
  emitCmp(OP_ICMP_SLE, CmpInst::ICMP_SLE, true);

  // ---- OP_SELECT --------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Cond = B.CreateAnd(loadReg(D.B), B.getInt64(1));
    Value *T = loadReg(D.C);
    Value *F = loadReg(D.Imm);
    Value *R = B.CreateSelect(B.CreateICmpNE(Cond, B.getInt64(0)), T, F);
    storeReg(D.A, zextTo(R, D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_SELECT, BB);
  }

  // ---- casts ------------------------------------------------------------
  auto emitCast = [&](VMOp Op) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *V = loadReg(D.B);
    Value *R;
    switch (Op) {
    case OP_ZEXT: R = zextTo(V, D.Flags); break;
    case OP_SEXT: R = zextTo(sextTo(V, D.Flags), D.W); break;
    default:      R = zextTo(V, D.W); break; // TRUNC
    }
    storeReg(D.A, R);
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(Op, BB);
  };
  emitCast(OP_ZEXT);
  emitCast(OP_SEXT);
  emitCast(OP_TRUNC);

  auto emitBitIntrinsic = [&](VMOp Op) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *X = zextTo(loadReg(D.B), D.W);
    Value *Bits = loadBits(D.W);
    Value *R;
    if (Op == OP_CTPOP) {
      R = B.CreateIntrinsic(Intrinsic::ctpop, {I64}, {X});
    } else if (Op == OP_CTLZ) {
      Value *Z = B.CreateIntrinsic(Intrinsic::ctlz, {I64},
                                   {X, B.getInt1(false)});
      R = B.CreateSub(Z, B.CreateSub(B.getInt64(64), B.CreateZExt(Bits, I64)));
    } else if (Op == OP_CTTZ) {
      Value *Z = B.CreateIntrinsic(Intrinsic::cttz, {I64},
                                   {X, B.getInt1(false)});
      Value *B64 = B.CreateZExt(Bits, I64);
      R = B.CreateSelect(B.CreateICmpUGE(Z, B64), B64, Z);
    } else if (Op == OP_BSWAP) {
      Value *Z = B.CreateIntrinsic(Intrinsic::bswap, {I64}, {X});
      Value *Sh = B.CreateSub(B.getInt64(64), B.CreateZExt(Bits, I64));
      R = B.CreateLShr(Z, Sh);
    } else {
      Value *Z = B.CreateIntrinsic(Intrinsic::bitreverse, {I64}, {X});
      Value *Sh = B.CreateSub(B.getInt64(64), B.CreateZExt(Bits, I64));
      R = B.CreateLShr(Z, Sh);
    }
    storeReg(D.A, zextTo(R, D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(Op, BB);
  };
  emitBitIntrinsic(OP_CTPOP);
  emitBitIntrinsic(OP_CTLZ);
  emitBitIntrinsic(OP_CTTZ);
  emitBitIntrinsic(OP_BSWAP);
  emitBitIntrinsic(OP_BITREVERSE);

  // ---- floating point ---------------------------------------------------
  auto fpTy = [&](unsigned Code) -> Type * {
    return Code == W_I32 ? Type::getFloatTy(Ctx) : Type::getDoubleTy(Ctx);
  };
  auto widenFP = [&](Value *V, unsigned Code) -> Value * {
    return Code == W_I32 ? B.CreateZExt(V, I64) : V;
  };
  auto narrowFP = [&](Value *V, unsigned Code) -> Value * {
    return Code == W_I32 ? B.CreateTrunc(V, I32) : V;
  };
  auto adv = [&]() {
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
  };
  auto fpBitsTy = [&](unsigned Code) -> Type * {
    return Code == W_I32 ? (Type *)I32 : (Type *)I64;
  };

  auto emitFPBin = [&](VMOp Op) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    SwitchInst *WSw = B.CreateSwitch(D.W, Trap, 2);
    for (unsigned Idx = 0; Idx < 2; ++Idx) {
      unsigned Code = Idx == 0 ? W_I32 : W_I64;
      BasicBlock *CB = newBB();
      B.SetInsertPoint(CB);
      Type *FT = fpTy(Code);
      Value *X = B.CreateBitCast(narrowFP(loadReg(D.B), Code), FT);
      Value *Y = B.CreateBitCast(narrowFP(loadReg(D.C), Code), FT);
      Value *R;
      switch (Op) {
      case OP_FADD: R = B.CreateFAdd(X, Y); break;
      case OP_FSUB: R = B.CreateFSub(X, Y); break;
      case OP_FMUL: R = B.CreateFMul(X, Y); break;
      case OP_FDIV: R = B.CreateFDiv(X, Y); break;
      default:      R = B.CreateFRem(X, Y); break;
      }
      storeReg(D.A, widenFP(B.CreateBitCast(R, fpBitsTy(Code)), Code));
      adv();
      WSw->addCase(ConstantInt::get(I32, Code), CB);
    }
    AddCase(Op, BB);
  };
  emitFPBin(OP_FADD);
  emitFPBin(OP_FSUB);
  emitFPBin(OP_FMUL);
  emitFPBin(OP_FDIV);
  emitFPBin(OP_FREM);

  auto emitFPUn = [&](VMOp Op) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    SwitchInst *WSw = B.CreateSwitch(D.W, Trap, 2);
    for (unsigned Idx = 0; Idx < 2; ++Idx) {
      unsigned Code = Idx == 0 ? W_I32 : W_I64;
      BasicBlock *CB = newBB();
      B.SetInsertPoint(CB);
      Type *FT = fpTy(Code);
      Value *X = B.CreateBitCast(narrowFP(loadReg(D.B), Code), FT);
      Value *R;
      if (Op == OP_FNEG)
        R = B.CreateFNeg(X);
      else if (Op == OP_FABS)
        R = B.CreateUnaryIntrinsic(Intrinsic::fabs, X);
      else
        R = B.CreateUnaryIntrinsic(Intrinsic::sqrt, X);
      storeReg(D.A, widenFP(B.CreateBitCast(R, fpBitsTy(Code)), Code));
      adv();
      WSw->addCase(ConstantInt::get(I32, Code), CB);
    }
    AddCase(Op, BB);
  };
  emitFPUn(OP_FNEG);
  emitFPUn(OP_FABS);
  emitFPUn(OP_FSQRT);

  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    SwitchInst *WSw = B.CreateSwitch(D.W, Trap, 2);
    for (unsigned Idx = 0; Idx < 2; ++Idx) {
      unsigned Code = Idx == 0 ? W_I32 : W_I64;
      BasicBlock *CB = newBB();
      B.SetInsertPoint(CB);
      Type *FT = fpTy(Code);
      Value *X = B.CreateBitCast(narrowFP(loadReg(D.B), Code), FT);
      Value *Y = B.CreateBitCast(narrowFP(loadReg(D.C), Code), FT);
      Value *Z = B.CreateBitCast(narrowFP(loadReg(D.Imm), Code), FT);
      Value *Mul = B.CreateFMul(X, Y);
      Value *R = B.CreateFAdd(Mul, Z);
      storeReg(D.A, widenFP(B.CreateBitCast(R, fpBitsTy(Code)), Code));
      adv();
      WSw->addCase(ConstantInt::get(I32, Code), CB);
    }
    AddCase(OP_FMA, BB);
  }

  {
    static const CmpInst::Predicate Preds[] = {
        CmpInst::FCMP_FALSE, CmpInst::FCMP_OEQ, CmpInst::FCMP_OGT,
        CmpInst::FCMP_OGE,   CmpInst::FCMP_OLT, CmpInst::FCMP_OLE,
        CmpInst::FCMP_ONE,   CmpInst::FCMP_ORD, CmpInst::FCMP_UNO,
        CmpInst::FCMP_UEQ,   CmpInst::FCMP_UGT, CmpInst::FCMP_UGE,
        CmpInst::FCMP_ULT,   CmpInst::FCMP_ULE, CmpInst::FCMP_UNE,
        CmpInst::FCMP_TRUE};
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    SwitchInst *WSw = B.CreateSwitch(D.W, Trap, 2);
    for (unsigned Idx = 0; Idx < 2; ++Idx) {
      unsigned Code = Idx == 0 ? W_I32 : W_I64;
      BasicBlock *CB = newBB();
      B.SetInsertPoint(CB);
      Type *FT = fpTy(Code);
      Value *X = B.CreateBitCast(narrowFP(loadReg(D.B), Code), FT);
      Value *Y = B.CreateBitCast(narrowFP(loadReg(D.C), Code), FT);
      SwitchInst *PSw = B.CreateSwitch(D.Imm, Trap, 16);
      for (CmpInst::Predicate P : Preds) {
        BasicBlock *PB = newBB();
        B.SetInsertPoint(PB);
        Value *R = B.CreateFCmp(P, X, Y);
        storeReg(D.A, B.CreateZExt(R, I64));
        adv();
        PSw->addCase(ConstantInt::get(I32, (unsigned)P), PB);
      }
      WSw->addCase(ConstantInt::get(I32, Code), CB);
    }
    AddCase(OP_FCMP, BB);
  }

  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Bits = B.CreateTrunc(loadReg(D.B), I32);
    Value *X = B.CreateBitCast(Bits, Type::getFloatTy(Ctx));
    Value *R = B.CreateFPExt(X, Type::getDoubleTy(Ctx));
    storeReg(D.A, B.CreateBitCast(R, I64));
    adv();
    AddCase(OP_FPEXT, BB);
  }
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *X = B.CreateBitCast(loadReg(D.B), Type::getDoubleTy(Ctx));
    Value *R = B.CreateFPTrunc(X, Type::getFloatTy(Ctx));
    storeReg(D.A, B.CreateZExt(B.CreateBitCast(R, I32), I64));
    adv();
    AddCase(OP_FPTRUNC, BB);
  }

  auto emitFPToInt = [&](VMOp Op, bool Signed) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    SwitchInst *WSw = B.CreateSwitch(D.Flags, Trap, 2);
    for (unsigned Idx = 0; Idx < 2; ++Idx) {
      unsigned Code = Idx == 0 ? W_I32 : W_I64;
      BasicBlock *CB = newBB();
      B.SetInsertPoint(CB);
      Type *FT = fpTy(Code);
      Value *X = B.CreateBitCast(narrowFP(loadReg(D.B), Code), FT);
      Value *R = Signed ? B.CreateFPToSI(X, I64) : B.CreateFPToUI(X, I64);
      storeReg(D.A, zextTo(R, D.W));
      adv();
      WSw->addCase(ConstantInt::get(I32, Code), CB);
    }
    AddCase(Op, BB);
  };
  emitFPToInt(OP_FPTOSI, true);
  emitFPToInt(OP_FPTOUI, false);

  auto emitIntToFP = [&](VMOp Op, bool Signed) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    SwitchInst *WSw = B.CreateSwitch(D.W, Trap, 2);
    for (unsigned Idx = 0; Idx < 2; ++Idx) {
      unsigned Code = Idx == 0 ? W_I32 : W_I64;
      BasicBlock *CB = newBB();
      B.SetInsertPoint(CB);
      Type *FT = fpTy(Code);
      Value *X = loadReg(D.B);
      Value *R = Signed ? B.CreateSIToFP(X, FT) : B.CreateUIToFP(X, FT);
      storeReg(D.A, widenFP(B.CreateBitCast(R, fpBitsTy(Code)), Code));
      adv();
      WSw->addCase(ConstantInt::get(I32, Code), CB);
    }
    AddCase(Op, BB);
  };
  emitIntToFP(OP_SITOFP, true);
  emitIntToFP(OP_UITOFP, false);

  // ---- OP_BR ------------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    B.CreateAlignedStore(D.Imm, PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_BR, BB);
  }

  // ---- OP_CBR -----------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Cond = B.CreateAnd(loadReg(D.A), B.getInt64(1));
    Value *Next = B.CreateAdd(Pc, B.getInt32(1));
    Value *Tgt = B.CreateSelect(B.CreateICmpNE(Cond, B.getInt64(0)), D.Imm,
                                Next);
    B.CreateAlignedStore(Tgt, PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_CBR, BB);
  }

  // ---- OP_RET -----------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *V = zextTo(loadReg(D.A), D.W);
    B.CreateRet(V);
    AddCase(OP_RET, BB);
  }

  // ---- OP_CALL ----------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Pp = B.CreateGEP(Ptr, ThunkGV, D.Imm);
    Value *FnPtr = B.CreateAlignedLoad(Ptr, Pp, Align(8), false);
    Value *ArgBase = B.CreateGEP(RegArrayTy, Regs,
                                 {B.getInt32(0), B.getInt32(kArgBase)});
    Value *HasFn = B.CreateICmpNE(B.CreateAnd(D.Flags, B.getInt32(0x80)),
                                  B.getInt32(0));
    Value *Target = B.CreateIntToPtr(loadReg(D.B), Ptr);
    Value *FnArg = B.CreateSelect(
        HasFn, Target, ConstantPointerNull::get(cast<PointerType>(Ptr)));
    FunctionType *ThunkFT = FunctionType::get(I64, {Ptr, Ptr}, false);
    CallInst *Call = B.CreateCall(ThunkFT, FnPtr, {ArgBase, FnArg});
    Call->setCallingConv(CallingConv::C);
    storeReg(B.getInt32(kRetReg), Call);
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_CALL, BB);
  }

  // ---- OP_TRAP ----------------------------------------------------------
  {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    B.CreateBr(Trap);
    AddCase(OP_TRAP, BB);
  }

  B.SetInsertPoint(Trap);
  FunctionCallee TrapFn =
      Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
  B.CreateCall(TrapFn);
  B.CreateUnreachable();

  return Fn;
}

bool VMRuntimeBuilder::emitWrapper() {
  Function &F = Wrapper;
  BasicBlock *OldEntry = &F.getEntryBlock();

  IRBuilder<> B(Ctx);
  BasicBlock *Entry = BasicBlock::Create(Ctx, "", &F, OldEntry);
  B.SetInsertPoint(Entry);
  Type *I64 = B.getInt64Ty();
  unsigned N = (unsigned)F.arg_size();
  AllocaInst *Args =
      B.CreateAlloca(ArrayType::get(I64, std::max(N, 1u)), nullptr, "a");
  Args->setAlignment(Align(16));
  unsigned I = 0;
  for (Argument &A : F.args()) {
    Value *V = &A;
    Value *S;
    Type *AT = A.getType();
    if (AT->isPointerTy())
      S = B.CreatePtrToInt(V, I64);
    else if (AT->isFloatTy())
      S = B.CreateZExt(B.CreateBitCast(V, B.getInt32Ty()), I64);
    else if (AT->isDoubleTy())
      S = B.CreateBitCast(V, I64);
    else if (AT->getIntegerBitWidth() < 64)
      S = B.CreateZExt(V, I64);
    else
      S = V;
    Value *Pp = gepI8(B, Args, I * 8);
    B.CreateAlignedStore(S, Pp, Align(8));
    ++I;
  }
  uint64_t FS = std::max<uint64_t>(P.FrameSize, 1);
  AllocaInst *Frame = B.CreateAlloca(ArrayType::get(B.getInt8Ty(), FS),
                                     nullptr, "f");
  Frame->setAlignment(Align(16));
  CallInst *Call = B.CreateCall(Interp, {Args, Frame});
  Call->setCallingConv(CallingConv::C);

  Type *RT = F.getReturnType();
  if (RT->isVoidTy()) {
    B.CreateRetVoid();
  } else if (RT->isPointerTy()) {
    B.CreateRet(B.CreateIntToPtr(Call, RT));
  } else if (RT->isFloatTy()) {
    B.CreateRet(B.CreateBitCast(B.CreateTrunc(Call, B.getInt32Ty()), RT));
  } else if (RT->isDoubleTy()) {
    B.CreateRet(B.CreateBitCast(Call, RT));
  } else if (RT->getIntegerBitWidth() < 64) {
    B.CreateRet(B.CreateTrunc(Call, RT));
  } else {
    B.CreateRet(Call);
  }

  std::string VErr;
  raw_string_ostream OS(VErr);
  if (verifyFunction(F, &OS)) {
    Reason = "wrapper verification failed: " + OS.str();
    Entry->eraseFromParent();
    return false;
  }

  // The old body is unreachable now; drop it.  (It was kept attached during
  // verification so that no instruction is left without a parent.)
  SmallVector<BasicBlock *, 32> Dead;
  for (BasicBlock &BB : F)
    if (&BB != Entry)
      Dead.push_back(&BB);
  for (BasicBlock *BB : Dead)
    BB->eraseFromParent();
  return true;
}

void VMRuntimeBuilder::discard() {
  if (Interp) {
    Interp->eraseFromParent();
    Interp = nullptr;
  }
  for (auto It = CreatedFunctions.rbegin(); It != CreatedFunctions.rend();
       ++It) {
    Function *Fn = *It;
    if (Fn && Fn->getParent())
      Fn->eraseFromParent();
  }
  CreatedFunctions.clear();
  for (GlobalVariable *GV : CreatedGlobals)
    if (GV && GV->getParent())
      GV->eraseFromParent();
  CreatedGlobals.clear();
}

Function *VMRuntimeBuilder::build() {
  if (!createThunks())
    return nullptr;
  if (!createGlobals())
    return nullptr;
  Function *I = createInterpreter();
  if (!I)
    return nullptr;
  std::string VErr;
  raw_string_ostream OS(VErr);
  if (verifyFunction(*I, &OS)) {
    Reason = "interpreter verification failed: " + OS.str();
    return nullptr;
  }
  return I;
}

} // namespace

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

bool llvm::virtualizeFunction(Function &F, const VirtualizeConfig &Cfg,
                              std::string &Reason) {
  Reason.clear();
  if (!Cfg.Enabled) {
    Reason = "disabled";
    return false;
  }
  // Translating our own runtime would produce interpreter^N: the thunks we
  // emit are ordinary functions and would be picked up again by a module-wide
  // driver.  Never virtualise generated code.
  if (F.hasFnAttribute(kGeneratedAttr)) {
    Reason = "generated by vmp";
    return false;
  }
  uint64_t Seed = Cfg.Seed;
  if (!Seed)
    Seed = (uint64_t)std::chrono::high_resolution_clock::now()
               .time_since_epoch()
               .count();

  VMTranslator T(F, Seed, Cfg.Level, Reason);
  if (!T.run())
    return false;

  if (::getenv("OBORO_VMP_DUMP")) {
    static const char *Names[] = {
        "nop", "mov", "imm", "ptr", "load", "store", "add", "sub", "mul",
        "udiv", "sdiv", "urem", "srem", "and", "or", "xor", "shl", "lshr",
        "ashr", "eq", "ne", "ugt", "uge", "ult", "ule", "sgt", "sge", "slt",
        "sle", "select", "zext", "sext", "trunc", "ctpop", "ctlz", "cttz",
        "bswap", "bitrev", "fadd", "fsub", "fmul", "fdiv", "frem", "fneg",
        "fabs", "fsqrt", "fma", "fcmp", "fpext", "fptrunc", "fptosi",
        "fptoui", "sitofp", "uitofp", "br", "cbr", "ret", "call", "trap"};
    errs() << "[dump] " << F.getName() << " key=" << T.Program.Key
           << " args=" << T.Program.ArgCount << "\n";
    for (unsigned I = 0; I < T.Program.Code.size(); ++I) {
      const VInst &V = T.Program.Code[I];
      errs() << "  " << I << ": " << (V.Op < OP_COUNT ? Names[V.Op] : "?")
             << " w=" << (unsigned)V.W << " a=" << (unsigned)V.A << " b="
             << (unsigned)V.B << " c=" << (unsigned)V.C << " f="
             << (unsigned)V.Flags << " imm=" << V.Imm << "\n";
    }
  }

  VMRuntimeBuilder RB(F, T.Program, Seed, Reason);
  Function *Interp = RB.build();
  if (!Interp) {
    RB.discard();
    return false;
  }
  if (!RB.emitWrapper()) {
    RB.discard();
    return false;
  }
  return true;
}
