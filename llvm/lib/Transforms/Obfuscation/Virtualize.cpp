//===- Virtualize.cpp - IR-level code virtualization ----------------------===//
//
// The VM is a 64-bit register machine.  Registers hold the zero-extended bit
// pattern of the value; signed operations sign-extend at use time and truncate
// the result back, so two's-complement semantics match the source.  A value
// owns a register only for its live range: values defined and consumed inside
// one block are recycled, everything else (PHIs, cross-block values) is pinned.
//
// Bytecode is a sequence of fixed 12-byte records (three i32 words).  Every
// word is XOR-encrypted with a rolling stream whose parameters are derived from
// the per-function key.  The interpreter loads code words with `volatile`, so
// the optimizer cannot fold the encrypted program back into the original code.
//
// The interpreter is emitted per function: every virtualized function gets its
// own handler order, opcode aliases and global names.
//
// Attribution: three mechanisms follow the design of amice (Apache-2.0,
// https://github.com/fuqiuluo/amice), adapted to LLVM IR and reimplemented in
// C++ -- no Rust source was copied:
//   * block-local register reuse -- amice
//     crates/amice/src/aotu/vm_virtualize/translator.rs (build_reuse_plan)
//   * opcode aliasing -- amice crates/amice-vm/src/isa.rs (alias selection)
//   * compare+branch superinstruction -- amice crates/amice-vm/src/lowering.rs
//     (fuse_icmp_br_if)
// See NOTICE in the repository root.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/Virtualize.h"

namespace {
constexpr const char *kGeneratedAttr = "oboro.vmp.generated";
}

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/STLExtras.h"
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
#include "llvm/IR/CFG.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <set>
#include <cstdlib>
#include <random>
#include <string>
#include <unordered_map>
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
  // Immediate superinstructions: A = B <op> constant.  The constant would
  // otherwise cost a prologue OP_IMM plus a register read on every use; here
  // it is folded into the dispatch that already has to happen.  Shift amounts
  // live in the instruction word, the other operators index the constant pool
  // (a 64-bit immediate does not fit in Imm).
  OP_ADD_IMM,
  OP_SUB_IMM,
  OP_MUL_IMM,
  OP_AND_IMM,
  OP_OR_IMM,
  OP_XOR_IMM,
  OP_SHL_IMM,
  OP_LSHR_IMM,
  OP_ASHR_IMM,
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
  // Funnel shifts cover the rotate idioms that -O2 turns into llvm.fshl/fshr;
  // without them a single rotate anywhere in a function skips the whole body.
  OP_FSHL,
  OP_FSHR,
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
  // icmp+br superinstructions: the compare result never reaches the register
  // file, so one dispatch replaces two.  Same idea as amice's IcmpBrIf
  // (crates/amice-vm/src/lowering.rs, Apache-2.0), implemented on IR use-def
  // instead of bytecode so the "single use" test stays exact.
  OP_ICMP_EQ_CBR,
  OP_ICMP_NE_CBR,
  OP_ICMP_UGT_CBR,
  OP_ICMP_UGE_CBR,
  OP_ICMP_ULT_CBR,
  OP_ICMP_ULE_CBR,
  OP_ICMP_SGT_CBR,
  OP_ICMP_SGE_CBR,
  OP_ICMP_SLT_CBR,
  OP_ICMP_SLE_CBR,
  OP_BR,
  OP_CBR,
  OP_RET,
  OP_CALL,
  OP_TRAP,
  // Frame traffic for values that do not fit the register file.  Both carry
  // the frame offset in Imm, so a program can address far more than the 236
  // registers an 8-bit operand can name.
  OP_SPILL,
  OP_FILL,
  OP_COUNT
};

// A register operand is one byte, so slot 255 is the last one that can be
// named.  The scratch regions live at the bottom of the file (see
// VMProgram::ArgBase) and the value registers fill whatever is left.
constexpr unsigned kRegLimit = 255;
constexpr unsigned kMaxCallArgs = 16;
// Upper bound on the wrapper's frame.  It is a stack allocation, so an
// unbounded spill area turns a big function into a stack overflow.
constexpr uint64_t kMaxFrameBytes = 64 * 1024;
// Per-activation VM state (register file plus spill frame) allowed for a
// function that calls itself.  The interpreter's own frame is a multiple of
// this, so a recursive function with a large state would run out of stack far
// earlier than the original.  Functions above the limit are left alone.
constexpr uint64_t kMaxRecursiveVmBytes = 1024;

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

// Immediate form of a binary operator, or OP_COUNT when there is none.
static uint8_t immOpcodeFor(unsigned Opcode) {
  switch (Opcode) {
  case Instruction::Add:  return OP_ADD_IMM;
  case Instruction::Sub:  return OP_SUB_IMM;
  case Instruction::Mul:  return OP_MUL_IMM;
  case Instruction::And:  return OP_AND_IMM;
  case Instruction::Or:   return OP_OR_IMM;
  case Instruction::Xor:  return OP_XOR_IMM;
  case Instruction::Shl:  return OP_SHL_IMM;
  case Instruction::LShr: return OP_LSHR_IMM;
  case Instruction::AShr: return OP_ASHR_IMM;
  default:                return OP_COUNT;
  }
}

// True when the opcode reads its immediate as a shift amount rather than as an
// index into the constant pool.
static bool isShiftImm(uint8_t Op) {
  return Op == OP_SHL_IMM || Op == OP_LSHR_IMM || Op == OP_ASHR_IMM;
}

// Signed operators must sign-extend both sides before the operation.
static bool isSignedImm(uint8_t Op) { return Op == OP_ASHR_IMM; }

// A few four-operand instructions carry their last source register in the Imm
// field instead of allocating a fifth encoding slot.  Anything that renumbers
// virtual registers has to remap those fields too, otherwise the instruction
// reads a slot that was never written.
static bool immHoldsReg(uint8_t Op) {
  return Op == OP_SELECT || Op == OP_FMA || Op == OP_FSHL || Op == OP_FSHR;
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
  // Kept so an indirect call through __stdcall / __fastcall / a target
  // specific convention keeps working: the thunk used to issue a plain C call.
  CallingConv::ID CC = CallingConv::C;
  // Attributes of the original call site.  `sret` in particular is not
  // cosmetic: the backend has to know that the pointer argument is the
  // structure return slot, or the callee's prologue and the caller's stack
  // cleanup disagree.
  AttributeList Attrs;
};

struct VMProgram {
  std::vector<VInst> Code;
  std::vector<uint64_t> Ints;
  std::vector<Constant *> Ptrs;
  std::vector<VMThunk> Thunks;
  uint32_t EntryPC = 0;
  // Opcode aliasing, modelled on amice's `opcode_alias_selection_uses_
  // function_key` (crates/amice-vm/src/isa.rs, Apache-2.0): one semantic can be
  // encoded by several byte values, chosen per instruction from the function
  // key so the same opcode never maps to a single stable constant.
  uint8_t OpMap[OP_COUNT] = {};
  std::array<std::vector<uint8_t>, OP_COUNT> Aliases;
  uint64_t Key = 0;
  unsigned Level = 1;
  unsigned ArgCount = 0;
  // Register file layout.  Arguments occupy 0..ArgCount-1 because the
  // interpreter prologue stores them there; the three scratch regions sit
  // directly above them and the ordinary value registers start after that.
  // Keeping the scratch slots low lets the interpreter size its register file
  // from the actual register count: a small recursive function then costs a
  // few hundred bytes of stack per activation instead of a fixed two
  // kilobytes, which is what used to turn deep recursion into a stack
  // overflow.
  uint8_t ArgBase = 0;   // kMaxCallArgs slots for outgoing call arguments
  uint8_t TmpReg = 0;    // scratch for fused compare/branch
  uint8_t FrameReg = 0;  // pointer to the wrapper's spill frame
  uint8_t RegBase = 0;   // first ordinary value register
  // Total slots in the interpreter's register array.  Rounded up and slightly
  // padded so the size is not a recognisable constant.
  unsigned RegSlots = 0;
  uint64_t FrameSize = 0;
  // Number of frame slots reserved for values that did not fit the register
  // file.  Zero for every function that translates without spilling.
  unsigned SpillSlots = 0;
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
  // The runtime keeps the register file, the spill frame and the constant
  // pools in the default address space and addresses all of them with i64
  // arithmetic.  A datalayout that puts allocas or globals somewhere else
  // (CHERI-style 128-bit spaces, GPU private spaces) cannot be served: the
  // frame handed to the interpreter would have a different pointer type than
  // the one it declares, which is a hard type error, and the pools would live
  // in a space the VM cannot index.  Refuse such a module outright.
  if (DL.getAllocaAddrSpace() != 0 || DL.getDefaultGlobalsAddressSpace() != 0) {
    Reason = "non-default alloca/global address space";
    return false;
  }
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
    // `sret` is only a pointer argument on the callee side: the wrapper keeps
    // the signature, so the caller still passes the return slot and the VM
    // writes through it.  The attributes below change the ABI itself.
    if (A.hasAttribute(Attribute::ByVal) ||
        A.hasAttribute(Attribute::InAlloca) ||
        A.hasAttribute(Attribute::Preallocated) ||
        A.hasAttribute(Attribute::SwiftSelf) ||
        A.hasAttribute(Attribute::SwiftError) ||
        A.hasAttribute(Attribute::Nest)) {
      Reason = "unsupported argument attribute";
      return false;
    }
  }
  if (F.arg_size() >= kRegLimit) {
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
  VMTranslator(Function &F, uint64_t Seed, unsigned Level, std::string &Reason,
               bool SpillPinned = false, unsigned RecursionCycle = 0)
      : F(F), M(*F.getParent()), DL(M.getDataLayout()), Seed(Seed),
        Level(Level), Reason(Reason), SpillPinned(SpillPinned),
        RecursionCycle(RecursionCycle) {}

  bool run();

  VMProgram Program;
  std::string &Reason;

private:
  Function &F;
  Module &M;
  const DataLayout &DL;
  uint64_t Seed;
  unsigned Level;
  // Call-graph cycle size reported by the driver; 0 when the driver could not
  // tell, in which case only a direct self-call is detected here.
  unsigned RecursionCycle = 0;

  DenseMap<Value *, uint8_t> Regs;
  // Frame residency.  With `SpillPinned` set, every value whose live range
  // crosses a block boundary lives in the wrapper frame instead of a register:
  // the defining block keeps it in a register until its terminator, then the
  // register is recycled and later blocks read it back with OP_FILL.  This is
  // what lets a function with thousands of cross-block values translate at
  // all; without it the 236-slot register file runs out.
  bool SpillPinned = false;
  DenseMap<Value *, uint32_t> SpillSlot;
  // Registers holding a value read out of the frame for the instruction that
  // is currently being translated; recycled once that instruction is emitted.
  SmallVector<uint8_t, 8> FillRegs;
  uint32_t SpillBase = 0;
  // Register reuse, modelled on amice's block-local reuse plan
  // (crates/amice/src/aotu/vm_virtualize/translator.rs, Apache-2.0).
  // A value may only be recycled when it is defined and consumed inside the
  // same basic block and is not a PHI: anything that can be read on a path the
  // linear scan does not describe stays pinned.
  DenseMap<Value *, BasicBlock *> DefBlock;
  DenseSet<Value *> PinnedSet;
  DenseMap<BasicBlock *, DenseMap<Value *, unsigned>> LastUse;
  SmallVector<uint8_t, 8> FreeRegs;
  // (predecessor, phi) pairs whose edge copy has been emitted.  Verified once
  // translation finishes: a PHI that never receives a copy keeps a stale or
  // zero register, which for a pointer is an immediate wild access.
  std::set<std::pair<BasicBlock *, PHINode *>> PhiEdgesDone;
  // Set when an icmp has exactly one user, a conditional branch in the same
  // block.  The compare is then emitted by the terminator as one fused opcode.
  // The deferred compare must survive until the terminator consumes it, so it
  // is only cleared when a block starts (and when the branch is emitted).
  ICmpInst *DeferredCmp = nullptr;
  // True only for the instruction that was just deferred; lets the driver tell
  // "this instruction produced nothing" from "this instruction is normal".
  bool JustDeferred = false;
  // Operands of a deferred icmp are consumed by the terminator, not by the
  // icmp itself, so their release is postponed until the block ends.
  SmallVector<Value *, 4> DeferredOps;
  DenseSet<Constant *> ConstSeen;
  std::vector<Constant *> ConstOrder;
  // Integer constants that appear exactly once in this function and feed a
  // binary operator that has an immediate form.  They are folded into that
  // instruction instead of being hoisted into a register, which removes both
  // the prologue OP_IMM and a register read per use.
  DenseSet<ConstantInt *> ImmOnly;
  DenseMap<ConstantInt *, unsigned> IntUseCount;
  DenseMap<ConstantInt *, Instruction *> IntSoleUser;
  DenseMap<BasicBlock *, uint32_t> BlockPC;
  DenseMap<AllocaInst *, uint64_t> AllocaOff;
  std::vector<AllocaInst *> Allocas;
  uint64_t FrameSize = 0;
  std::vector<std::pair<uint32_t, BasicBlock *>> Fixups;
  uint8_t NextReg = 0;
  const Instruction *CurI = nullptr;
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
    if (!FreeRegs.empty())
      return FreeRegs.pop_back_val();
    if (NextReg >= kRegLimit) {
      fail(Twine("too many SSA values: ") + Twine((unsigned)NextReg) +
           " registers for " + Twine(kRegLimit) + " slots, " +
           Twine((unsigned)PinnedSet.size()) + " pinned, " +
           Twine((unsigned)Regs.size()) + " live, " +
           (SpillPinned ? "spill" : "no spill") + " at " +
           (CurI ? CurI->getOpcodeName() : "?"));
      return 0;
    }
    return NextReg++;
  }

  // A value is frame-resident when it outlives its block.  Only instructions
  // qualify: arguments arrive in registers at entry and are never written to a
  // slot, and constants are materialised on use instead of being hoisted.
  bool isSpilled(Value *V) const {
    return SpillPinned && isa<Instruction>(V) && PinnedSet.count(V) != 0;
  }

  uint32_t slotOf(Value *V) {
    auto It = SpillSlot.find(V);
    if (It != SpillSlot.end())
      return It->second;
    uint32_t S = (uint32_t)SpillSlot.size();
    SpillSlot[V] = S;
    return S;
  }

  uint32_t spillOff(Value *V) { return SpillBase + slotOf(V) * 8; }

  void releaseFills(size_t Mark) {
    for (size_t I = Mark; I < FillRegs.size(); ++I)
      FreeRegs.push_back(FillRegs[I]);
    FillRegs.resize(Mark);
  }

  uint8_t regOf(Value *V);
  bool materialize(Value *V, uint8_t Dst, Type *Ty);
  bool cmpJumpsTo(ICmpInst &CI, uint8_t &Op, uint8_t &W, uint8_t &A, uint8_t &B);
  void buildReuseInfo();
  void buildImmCandidates();
  void releaseDeadOperands(Instruction &I, unsigned Idx);
  void releaseValue(Value *V);
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

  // Constant pools.  Both are indexed by value, and a large generated function
  // can carry tens of thousands of distinct immediates; a linear scan per use
  // made translation quadratic in that case.  The integer pool cannot use a
  // DenseMap: its sentinel keys are all-ones and all-ones-minus-one, which are
  // ordinary constants here (adler32 alone uses 0xFFFFFFFF).
  std::unordered_map<uint64_t, uint32_t> IntConstIdx;
  DenseMap<Constant *, uint32_t> PtrConstIdx;

  uint32_t addIntConst(uint64_t V) {
    auto It = IntConstIdx.find(V);
    if (It != IntConstIdx.end())
      return It->second;
    uint32_t Idx = (uint32_t)Program.Ints.size();
    Program.Ints.push_back(V);
    IntConstIdx[V] = Idx;
    return Idx;
  }

  uint32_t addPtrConst(Constant *C) {
    auto It = PtrConstIdx.find(C);
    if (It != PtrConstIdx.end())
      return It->second;
    // The pool is a [N x ptr] array, so every entry must be a default address
    // space pointer.  A constant in another address space trips the element
    // type assertion in ConstantArray::get, and reading it back as `ptr` would
    // reinterpret it on targets where the spaces differ.  Refuse the function.
    if (!C->getType()->isPointerTy() ||
        C->getType()->getPointerAddressSpace() != 0) {
      fail("pointer constant in a non-default address space");
      return 0;
    }
    uint32_t Idx = (uint32_t)Program.Ptrs.size();
    Program.Ptrs.push_back(C);
    PtrConstIdx[C] = Idx;
    return Idx;
  }

  unsigned thunkForCall(CallInst &CI) {
    Function *Direct = CI.getCalledFunction();
    FunctionType *SiteFT = CI.getFunctionType();
    Type *RetTy = CI.getType();
    CallingConv::ID CC = CI.getCallingConv();
    SmallVector<Type *, 8> ArgTys;
    for (Value *A : CI.args())
      ArgTys.push_back(A->getType());

    for (unsigned I = 0; I < Program.Thunks.size(); ++I) {
      const VMThunk &T = Program.Thunks[I];
      if (T.Direct != Direct || T.RetTy != RetTy || T.CC != CC ||
          T.ArgTys.size() != ArgTys.size() || T.Attrs != CI.getAttributes())
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
    T.CC = CC;
    T.Attrs = CI.getAttributes();
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

// Resolve the operands of an icmp that is fused into its branch.  Signed
// relational predicates on pointers become their unsigned form because a
// register holds ptrtoint, exactly like the non-fused path.
bool VMTranslator::cmpJumpsTo(ICmpInst &CI, uint8_t &Op, uint8_t &W, uint8_t &A,
                              uint8_t &B) {
  Type *OT = CI.getOperand(0)->getType();
  if (!storageWidthCode(OT, DL, W))
    return fail("icmp width");
  bool IsPtr = OT->isPointerTy();
  switch (CI.getPredicate()) {
  case CmpInst::ICMP_EQ:  Op = OP_ICMP_EQ_CBR; break;
  case CmpInst::ICMP_NE:  Op = OP_ICMP_NE_CBR; break;
  case CmpInst::ICMP_UGT: Op = OP_ICMP_UGT_CBR; break;
  case CmpInst::ICMP_UGE: Op = OP_ICMP_UGE_CBR; break;
  case CmpInst::ICMP_ULT: Op = OP_ICMP_ULT_CBR; break;
  case CmpInst::ICMP_ULE: Op = OP_ICMP_ULE_CBR; break;
  case CmpInst::ICMP_SGT: Op = IsPtr ? OP_ICMP_UGT_CBR : OP_ICMP_SGT_CBR; break;
  case CmpInst::ICMP_SGE: Op = IsPtr ? OP_ICMP_UGE_CBR : OP_ICMP_SGE_CBR; break;
  case CmpInst::ICMP_SLT: Op = IsPtr ? OP_ICMP_ULT_CBR : OP_ICMP_SLT_CBR; break;
  case CmpInst::ICMP_SLE: Op = IsPtr ? OP_ICMP_ULE_CBR : OP_ICMP_SLE_CBR; break;
  default:
    return fail("unsupported icmp predicate for fusion");
  }
  A = regOf(CI.getOperand(0));
  B = regOf(CI.getOperand(1));
  return !Failed;
}

// A constant that appears exactly once inside this function can be folded into
// its consumer when that consumer is a binary operator with an immediate form.
// The count must include constants hidden inside ConstantExpr operands: those
// are materialised by collectConstant() as well, so missing them would mark a
// value foldable while another expression still needs its register.
void VMTranslator::buildImmCandidates() {
  SmallVector<std::pair<Value *, Instruction *>, 16> Work;
  for (BasicBlock &BB : F)
    for (Instruction &I : BB)
      for (Use &U : I.operands())
        Work.push_back({U.get(), &I});

  while (!Work.empty()) {
    auto [V, User] = Work.pop_back_val();
    if (auto *CI = dyn_cast<ConstantInt>(V)) {
      IntUseCount[CI]++;
      IntSoleUser[CI] = User;
      continue;
    }
    if (auto *CE = dyn_cast<ConstantExpr>(V))
      for (Value *Op : CE->operands())
        Work.push_back({Op, User});
  }

  for (auto &Entry : IntUseCount) {
    if (Entry.second != 1)
      continue;
    ConstantInt *CI = Entry.first;
    auto *BO = dyn_cast<BinaryOperator>(IntSoleUser[CI]);
    if (!BO || !BO->getType()->isIntegerTy() || CI->getBitWidth() > 64)
      continue;
    uint8_t Op = immOpcodeFor(BO->getOpcode());
    if (Op == OP_COUNT)
      continue;
    bool IsRhs = BO->getOperand(1) == CI;
    bool IsLhs = BO->getOperand(0) == CI;
    // A commutative operator may carry the constant on either side; anything
    // else only folds when the constant is on the right.
    if (!IsRhs && !(IsLhs && BO->isCommutative()))
      continue;
    // Two constants would have been folded by the IR already; refusing here
    // keeps the immediate path from needing a register for the other side.
    if (isa<Constant>(BO->getOperand(IsRhs ? 0 : 1)))
      continue;
    uint8_t W;
    if (!storageWidthCode(BO->getType(), DL, W))
      continue;
    // Shift amounts are stored in the instruction word, so they must fit.
    if (isShiftImm(Op) && CI->getZExtValue() > 0xFFFFFFFFull)
      continue;
    ImmOnly.insert(CI);
  }
}

// Build the block-local liveness table.  The rule is deliberately
// conservative: only values defined and used in one block are eligible, so a
// register can never be recycled while a path might still read it.  PHIs and
// cross-block values stay pinned for the whole function.
void VMTranslator::buildReuseInfo() {
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (!I.getType()->isVoidTy())
        DefBlock[&I] = &BB;
      if (isa<PHINode>(I))
        PinnedSet.insert(&I);
    }
  }

  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      bool IsPhi = isa<PHINode>(I);
      for (Value *Op : I.operands()) {
        if (isa<Constant>(Op))
          continue;
        auto It = DefBlock.find(Op);
        if (It == DefBlock.end() || It->second != &BB || IsPhi)
          PinnedSet.insert(Op);
      }
    }
  }

  for (BasicBlock &BB : F) {
    auto &LU = LastUse[&BB];
    unsigned Idx = 0;
    for (Instruction &I : BB) {
      bool IsPhi = isa<PHINode>(I);
      for (Value *Op : I.operands()) {
        if (isa<Constant>(Op))
          continue;
        // A frame-resident value already has its slot, so only its in-block
        // *register* uses keep the defining register alive.  A PHI operand is
        // read from the slot on the edge, never through that register, so it
        // does not count either.
        if (PinnedSet.count(Op) && !(isSpilled(Op) && !IsPhi))
          continue;
        auto It = DefBlock.find(Op);
        if (It == DefBlock.end() || It->second != &BB)
          continue;
        LU[Op] = Idx;
      }
      ++Idx;
    }
  }
}

void VMTranslator::releaseValue(Value *V) {
  auto R = Regs.find(V);
  if (R == Regs.end())
    return;
  FreeRegs.push_back(R->second);
  Regs.erase(R);
}

void VMTranslator::releaseDeadOperands(Instruction &I, unsigned Idx) {
  BasicBlock *BB = I.getParent();
  auto It = LastUse.find(BB);
  if (It == LastUse.end())
    return;
  for (Value *Op : I.operands()) {
    auto J = It->second.find(Op);
    if (J == It->second.end() || J->second != Idx)
      continue;
    auto R = Regs.find(Op);
    if (R == Regs.end())
      continue;
    FreeRegs.push_back(R->second);
    Regs.erase(R);
    It->second.erase(J);
  }
}

void VMTranslator::collectConstant(Value *V) {
  auto *C = dyn_cast<Constant>(V);
  if (!C || ConstSeen.count(C))
    return;
  // Folded into an immediate superinstruction: no register is needed.
  if (auto *CI = dyn_cast<ConstantInt>(C))
    if (ImmOnly.count(CI))
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
  // Frame-resident value: read it into a scratch register that stays live
  // until the instruction being translated has been emitted.  Every caller
  // consumes the register within that one instruction, so the scratch never
  // has to survive a release point.
  if (isSpilled(V)) {
    uint8_t R = allocReg();
    if (Failed)
      return 0;
    emit(OP_FILL, W_I64, R, 0, 0, 0, spillOff(V));
    FillRegs.push_back(R);
    return R;
  }
  // A constant that was not hoisted (spill mode materialises on use).
  if (SpillPinned) {
    if (auto *C = dyn_cast<Constant>(V)) {
      uint8_t R = allocReg();
      if (Failed)
        return 0;
      if (!materialize(C, R, C->getType()))
        return 0;
      FillRegs.push_back(R);
      return R;
    }
  }
  fail(isa<Constant>(V) ? "constant was not hoisted" : "value has no register");
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
    // `sret` is transparent here: the slot is allocated by our caller and the
    // callee only writes through the pointer, so forwarding it unchanged is
    // exactly what the ABI does.  The remaining attributes change the calling
    // convention itself (a private copy, a shadow slot, a special register) and
    // cannot be reproduced by a plain forward.
    if (CI.paramHasAttr(I, Attribute::ByVal) ||
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
  // The argument copies below write into the reserved block; a short
  // reservation would overwrite the scratch registers.
  if ((unsigned)Program.ArgBase + CI.arg_size() > (unsigned)Program.TmpReg)
    return fail("call argument block overlaps scratch registers");

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
    uint8_t Dst = Program.ArgBase + I;
    uint8_t W;
    if (!widthCodeForBits(bitWidthOf(Arg->getType(), DL), W))
      return fail("call argument width");
    uint8_t Src = regOf(Arg);
    if (Failed)
      return false;
    emit(OP_MOV, W, Dst, Src);
  }

  // Only bit 7 carries information here.  The thunk's signature already fixes
  // the argument count, so packing `arg_size()` into the low bits only ever
  // hurt: a call with 128 or more arguments set bit 7 by itself and the
  // interpreter then took the indirect path, loading a garbage function pointer
  // from a register that was never written.
  uint8_t CFlags = Indirect ? 0x80 : 0;

  if (CI.getType()->isVoidTy()) {
    // A void call still has to name a destination: the thunk returns an i64
    // (zero), and letting the handler store it unconditionally keeps the
    // "has a result" test out of the interpreter.  The scratch slot is never
    // live across an instruction, so clobbering it is free.
    emit(OP_CALL, W_I64, Program.TmpReg, FnReg, 0, CFlags, Id);
    if (CI.doesNotReturn())
      emit(OP_TRAP, 0);
    return true;
  }

  uint8_t W;
  if (!widthCodeForBits(bitWidthOf(CI.getType(), DL), W))
    return fail("call return width");
  // The result goes straight into its register: OP_CALL already knows where to
  // put it, so the extra move through a fixed return slot is not needed.
  uint8_t Dst = allocReg();
  if (Failed)
    return false;
  emit(OP_CALL, W, Dst, FnReg, 0, CFlags, Id);
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
    // A scalable type has no fixed allocation size: getFixedValue() asserts on
    // it.  The VM cannot express a vscale-sized stride, so refuse the function
    // instead of asserting or baking in a wrong constant.
    auto allocSize = [&](Type *T, int64_t &Out) {
      TypeSize Sz = DL.getTypeAllocSize(T);
      if (Sz.isScalable())
        return false;
      Out = (int64_t)Sz.getFixedValue();
      return true;
    };
    if (I == 0) {
      // The first index steps over the source element type.
      if (!Cur->isSized())
        return fail("GEP of unsized type");
      if (!allocSize(Cur, Stride))
        return fail("GEP of scalable type");
    } else if (Cur->isStructTy()) {
      auto *CI = dyn_cast<ConstantInt>(Idx);
      if (!CI)
        return fail("dynamic struct index");
      auto *ST = cast<StructType>(Cur);
      // Compare before narrowing: a 64-bit index that does not fit in unsigned
      // would otherwise wrap to a small, valid-looking field number.
      if (CI->getValue().uge(ST->getNumElements()))
        return fail("struct index out of range");
      unsigned Field = (unsigned)CI->getZExtValue();
      ConstOff += (int64_t)DL.getStructLayout(ST)->getElementOffset(Field);
      Cur = ST->getElementType(Field);
      continue;
    } else if (Cur->isArrayTy()) {
      Type *Elem = Cur->getArrayElementType();
      if (!Elem->isSized())
        return fail("unsized array element");
      if (!allocSize(Elem, Stride))
        return fail("GEP of scalable array element");
      Cur = Elem;
    } else {
      return fail("GEP into unsupported type");
    }

    if (auto *CI = dyn_cast<ConstantInt>(Idx)) {
      // Wrapping arithmetic: the address computation is allowed to wrap, but a
      // signed multiply would be undefined behaviour on the host for a huge
      // index, and a GEP is free to carry one.
      ConstOff = (int64_t)((uint64_t)ConstOff +
                           (uint64_t)CI->getSExtValue() * (uint64_t)Stride);
    } else {
      uint8_t R = regOf(Idx);
      if (Failed)
        return false;
      Dyn.push_back({R, Stride});
    }
  }

  // The result register is allocated before any intermediate: the last step
  // of the address computation can then write into it directly instead of
  // producing a temporary that has to be moved afterwards.  On a typical GEP
  // that removes one instruction per address.
  uint8_t Dst = allocReg();
  if (Failed)
    return false;

  uint8_t Acc = Base;
  bool First = true;
  if (ConstOff != 0) {
    // base + constant is a single immediate add on a 64-bit pointer.
    if (Dyn.empty() && PtrBits == 64) {
      emit(OP_ADD_IMM, W_I64, Dst, Base, 0, 0,
           addIntConst((uint64_t)ConstOff));
      Regs[&GEP] = Dst;
      return true;
    }
    uint8_t CR = allocReg();
    if (Failed)
      return false;
    emit(OP_IMM, W_I64, CR, 0, 0, 0, addIntConst((uint64_t)ConstOff));
    emit(OP_ADD, W_I64, Dst, Base, CR);
    Acc = Dst;
    First = false;
  }
  for (const DynTerm &T : Dyn) {
    uint8_t MR = T.Reg;
    if (T.Stride != 1) {
      MR = allocReg();
      if (Failed)
        return false;
      emit(OP_MUL_IMM, W_I64, MR, T.Reg, 0, 0,
           addIntConst((uint64_t)T.Stride));
    }
    emit(OP_ADD, W_I64, Dst, First ? Base : Acc, MR);
    Acc = Dst;
    First = false;
  }

  if (First)
    emit(OP_MOV, W_PTR, Dst, Base);
  else if (PtrBits < 64)
    emit(OP_TRUNC, W_PTR, Dst, Acc, 0, W_I64);
  // Otherwise the last add already produced the pointer in Dst.
  Regs[&GEP] = Dst;
  return true;
}

// PHI copies on one edge are a *parallel* assignment, not a sequence: two
// phis may swap their values, and a phi may take its incoming value from
// another phi of the same block (legal SSA, since the source is defined in the
// predecessor and only read here).  Emitting the moves in block order would
// clobber a value that a later move still needs -- exactly the failure that
// turned a NULL into an argument register in the regex corpus.
//
// Standard schedule: repeatedly emit any move whose source is not still a
// pending destination; when every remaining source is blocked, the pending
// moves form at least one cycle, so stash one source in a scratch register to
// break it.
bool VMTranslator::phiCopiesFor(BasicBlock *From, BasicBlock *To) {
  // A copy endpoint is either a register or a frame slot.  The scheduling rule
  // below is unchanged; only the identity comparison and the emitted
  // instruction differ.  A constant source is carried symbolically: in spill
  // mode materialising one costs a register, and a parallel copy of a thousand
  // constant phis would need a thousand of them at once.
  struct Loc {
    bool Slot = false;
    uint32_t Id = 0;
    Constant *C = nullptr;
  };
  struct PendingCopy {
    Loc Dst;
    Loc Src;
    uint8_t Width;
  };
  SmallVector<PendingCopy, 8> Pending;
  size_t FillMark = FillRegs.size();

  auto Same = [](const Loc &A, const Loc &B) {
    return A.Slot == B.Slot && A.Id == B.Id && A.C == B.C;
  };
  auto EmitFill = [&](uint32_t Slot, uint8_t Dst) {
    emit(OP_FILL, W_I64, Dst, 0, 0, 0, SpillBase + Slot * 8);
  };
  auto EmitSpill = [&](uint8_t Src, uint32_t Slot) {
    emit(OP_SPILL, W_I64, Src, 0, 0, 0, SpillBase + Slot * 8);
  };
  auto EmitCopy = [&](const Loc &D, const Loc &S, uint8_t W) {
    if (S.C) {
      // A constant never aliases a destination, so it can be written straight
      // into the target and the scratch register released immediately.
      if (D.Slot) {
        uint8_t T = allocReg();
        if (Failed)
          return false;
        if (!materialize(S.C, T, S.C->getType()))
          return false;
        EmitSpill(T, D.Id);
        FreeRegs.push_back(T);
      } else if (!materialize(S.C, (uint8_t)D.Id, S.C->getType())) {
        return false;
      }
      return true;
    }
    if (D.Slot && S.Slot) {
      // One scratch register, released as soon as the value has been written
      // back: a parallel copy of a thousand phis must not need a thousand
      // registers.
      uint8_t T = allocReg();
      if (Failed)
        return false;
      EmitFill(S.Id, T);
      EmitSpill(T, D.Id);
      FreeRegs.push_back(T);
    } else if (D.Slot) {
      EmitSpill((uint8_t)S.Id, D.Id);
    } else if (S.Slot) {
      EmitFill(S.Id, (uint8_t)D.Id);
    } else {
      emit(OP_MOV, W, (uint8_t)D.Id, (uint8_t)S.Id);
    }
    return true;
  };

  for (PHINode &PN : To->phis()) {
    PhiEdgesDone.insert({From, &PN});
    Loc Dst;
    if (isSpilled(&PN)) {
      Dst = {true, slotOf(&PN), nullptr};
    } else {
      auto It = Regs.find(&PN);
      if (It == Regs.end()) {
        uint8_t R = allocReg();
        if (Failed) {
          releaseFills(FillMark);
          return false;
        }
        Regs[&PN] = R;
        It = Regs.find(&PN);
      }
      Dst = {false, It->second, nullptr};
    }
    Value *Src = PN.getIncomingValueForBlock(From);
    uint8_t W;
    if (!widthCodeForBits(bitWidthOf(PN.getType(), DL), W)) {
      releaseFills(FillMark);
      return fail("phi width");
    }
    Loc S;
    if (auto *C = dyn_cast<Constant>(Src)) {
      S = {false, 0, C};
    } else if (isSpilled(Src)) {
      S = {true, slotOf(Src), nullptr};
    } else {
      S = {false, regOf(Src), nullptr};
      if (Failed) {
        releaseFills(FillMark);
        return false;
      }
    }
    if (!Same(S, Dst))
      Pending.push_back({Dst, S, W});
  }

  // A copy may only run when its destination is not still a source of another
  // pending copy -- writing it would destroy the old value that copy must read.
  // The naive condition (source is not a destination) is wrong: for
  //   %a = phi [%b] ; %b = phi [%a]        (a rotation)
  // it lets "%a = %b" run first and "%b = %a" then reads the value just
  // written.  That is exactly how a pointer came out wrong in the regex
  // state machine.
  while (!Pending.empty()) {
    bool Progress = false;
    for (unsigned I = 0; I < Pending.size(); ++I) {
      const Loc &Dst = Pending[I].Dst;
      bool Blocked = false;
      for (unsigned J = 0; J < Pending.size(); ++J)
        if (J != I && Same(Pending[J].Src, Dst)) {
          Blocked = true;
          break;
        }
      if (Blocked)
        continue;
      if (!EmitCopy(Pending[I].Dst, Pending[I].Src, Pending[I].Width)) {
        releaseFills(FillMark);
        return false;
      }
      Pending.erase(Pending.begin() + I);
      Progress = true;
      break;
    }
    if (Progress)
      continue;
    // All remaining sources are live destinations: a cycle exists.  Stash one
    // source in a scratch register to break it.
    uint8_t Tmp = allocReg();
    if (Failed) {
      releaseFills(FillMark);
      return false;
    }
    FillRegs.push_back(Tmp);
    if (Pending[0].Src.C) {
      if (!materialize(Pending[0].Src.C, Tmp, Pending[0].Src.C->getType()))
        return false;
    } else if (Pending[0].Src.Slot) {
      EmitFill(Pending[0].Src.Id, Tmp);
    } else {
      emit(OP_MOV, Pending[0].Width, Tmp, (uint8_t)Pending[0].Src.Id);
    }
    Pending[0].Src = {false, Tmp, nullptr};
  }
  releaseFills(FillMark);
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
    emit(OP_ICMP_EQ, W, Program.TmpReg, CondReg, CaseReg);

    BasicBlock *Target = Case.getCaseSuccessor();
    if (hasPhi(Target)) {
      // CBR true -> stub; CBR false -> the BR below, which jumps to the next
      // comparison.  The stub is placed after that BR.
      uint32_t StubPC = (uint32_t)Program.Code.size() + 2;
      emit(OP_CBR, 0, Program.TmpReg, 0, 0, 0, StubPC);
      uint32_t NextBrIdx = (uint32_t)Program.Code.size();
      emit(OP_BR, 0, 0, 0, 0, 0, 0);
      if (!phiCopiesFor(From, Target))
        return false;
      emitFixup(OP_BR, 0, 0, 0, 0, 0, Target);
      Program.Code[NextBrIdx].Imm = (uint32_t)Program.Code.size();
    } else {
      emitFixup(OP_CBR, 0, Program.TmpReg, 0, 0, 0, Target);
    }
  }
  // The default edge is the fall-through of the comparison chain, so its PHI
  // copies belong right here.  Missing them leaves stale registers behind and
  // the target block then loops on old values.
  // The default edge falls through the comparison chain.  Copying its PHIs
  // here has proven unreliable for targets that are also loop headers, so the
  // function is skipped instead of risking wrong register state.
  BasicBlock *Default = SI.getDefaultDest();
  if (hasPhi(Default) && !phiCopiesFor(From, Default))
    return false;
  emitFixup(OP_BR, 0, 0, 0, 0, 0, Default);
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

    // Fused layout is identical to CBR: true jumps to the first successor,
    // false falls through to the BR that follows.
    uint8_t FOp = 0, FW = 0, FA = 0, FB = 0;
    bool Fused = false;
    if (auto *CI = dyn_cast<ICmpInst>(BI->getCondition())) {
      if (DeferredCmp == CI) {
        DeferredCmp = nullptr;
        Fused = cmpJumpsTo(*CI, FOp, FW, FA, FB);
        if (!Fused)
          return false;
      }
    }

    uint8_t Cond = 0;
    if (!Fused) {
      Cond = regOf(BI->getCondition());
      if (Failed)
        return false;
    }

    auto EmitCond = [&](uint32_t Pc, BasicBlock *Target) {
      if (Fused) {
        if (Target)
          emitFixup(FOp, FW, FA, FB, 0, 0, Target);
        else
          emit(FOp, FW, FA, FB, 0, 0, Pc);
      } else {
        if (Target)
          emitFixup(OP_CBR, 0, Cond, 0, 0, 0, Target);
        else
          emit(OP_CBR, 0, Cond, 0, 0, 0, Pc);
      }
    };

    bool TPhi = hasPhi(T), FPhi = hasPhi(F);
    if (!TPhi && !FPhi) {
      EmitCond(0, T);
      emitFixup(OP_BR, 0, 0, 0, 0, 0, F);
      return true;
    }

    uint32_t TrueStub = (uint32_t)Program.Code.size() + 2;
    EmitCond(TrueStub, nullptr);
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
  CurI = &I;
  if (isa<PHINode>(I))
    return true;

  // Defer an icmp that feeds a conditional branch of this block; hasOneUse
  // makes the decision exact -- nothing else can observe the compare result.
  // Spill mode never defers: the fused opcode is emitted by the terminator,
  // long after the scratch registers holding frame-resident operands have been
  // recycled.
  if (!SpillPinned)
    if (auto *CI = dyn_cast<ICmpInst>(&I)) {
      if (!DeferredCmp && CI->hasOneUse()) {
        User *U = *CI->user_begin();
        if (auto *BI = dyn_cast<BranchInst>(U))
          if (BI->isConditional() && BI->getParent() == CI->getParent()) {
            DeferredCmp = CI;
            JustDeferred = true;
            return true;
          }
      }
    }
  if (isa<DbgInfoIntrinsic>(I))
    return true;

  if (auto *MI = dyn_cast<MemIntrinsic>(&I)) {
    if (MI->isVolatile())
      return fail("volatile memintrinsic");
    // The three arguments live in the outgoing-argument block.  If that block
    // was sized too small the stores below would land on the scratch
    // registers, so refuse rather than emit a program that corrupts itself.
    if ((unsigned)Program.ArgBase + 3 > (unsigned)Program.TmpReg)
      return fail("memintrinsic argument block overlaps scratch registers");
    bool IsSet = isa<MemSetInst>(MI);
    const char *Name = IsSet ? "memset"
                             : (isa<MemMoveInst>(MI) ? "memmove" : "memcpy");
    LLVMContext &C = M.getContext();
    Type *Ptr = PointerType::getUnqual(C);
    FunctionType *FT = FunctionType::get(
        Ptr, {Ptr, IsSet ? Type::getInt32Ty(C) : Ptr,
              MI->getLength()->getType()},
        false);
    // The module may already declare memset/memcpy/memmove, and not
    // necessarily with our prototype: libc headers declare `void *memset(void
    // *, int, size_t)` while some code declares it returning void, and the
    // length is `size_t` or `unsigned` depending on the source.  When a
    // declaration already exists getOrInsertFunction hands it back unchanged,
    // so a call built from our own signature would not match it -- and two
    // memintrinsics with different length widths would also collide on the
    // same name.  Take the types from the declaration that actually won and
    // let the thunk convert each VM register to its real parameter type.
    Function *Fn = dyn_cast<Function>(M.getOrInsertFunction(Name, FT).getCallee());
    if (!Fn)
      return fail("memintrinsic symbol is not a function");
    FunctionType *ActualFT = Fn->getFunctionType();
    if (ActualFT->isVarArg() || ActualFT->getNumParams() != 3)
      return fail("memintrinsic with an unexpected prototype");
    SmallVector<Type *, 4> MTys(ActualFT->params());
    for (Type *T : MTys)
      if (!T->isPointerTy() &&
          !(T->isIntegerTy() && (T->getIntegerBitWidth() == 32 ||
                                 T->getIntegerBitWidth() == 64)))
        return fail("memintrinsic with an unsupported parameter type");
    unsigned Id = thunkForFunction(Fn, MTys);
    uint8_t Dst0 = Program.ArgBase;
    uint8_t Src0 = Program.ArgBase + 1;
    uint8_t Len0 = Program.ArgBase + 2;
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
    // The handler always stores a result, so name the scratch slot: a zero
    // destination would overwrite a live SSA register.
    emit(OP_CALL, W_I64, Program.TmpReg, 0, 0, 3, Id);
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
      case Intrinsic::abs: {
        // abs(x) = x < 0 ? -x : x.  The `is_int_min_poison` flag only licenses
        // the backend to assume INT_MIN never appears; wrapping negation gives
        // the same value, so it can be ignored.
        Type *T = CI->getArgOperand(0)->getType();
        unsigned Bits = bitWidthOf(T, DL);
        auto *IT = dyn_cast<IntegerType>(T);
        uint8_t W;
        if (!IT || !Bits || !storageWidthCode(T, DL, W))
          return fail("abs width");
        uint8_t Bv = regOf(CI->getArgOperand(0));
        uint8_t Zero = allocReg();
        uint8_t Cmp = allocReg();
        uint8_t Neg = allocReg();
        uint8_t R = allocReg();
        if (Failed)
          return false;
        if (!materialize(ConstantInt::get(IT, APInt::getZero(Bits)), Zero, T))
          return false;
        emit(OP_ICMP_SLT, W, Cmp, Bv, Zero);
        emit(OP_SUB, W, Neg, Zero, Bv);
        emit(OP_SELECT, W, R, Cmp, Neg, 0, Bv);
        Regs[&I] = R;
        return true;
      }
      case Intrinsic::uadd_sat:
      case Intrinsic::usub_sat:
      case Intrinsic::sadd_sat:
      case Intrinsic::ssub_sat: {
        // Saturating arithmetic is a handful of ordinary operations: compute
        // the wrapping result, detect the overflow with a compare, then select
        // the clamped value.  Nothing here needs a new opcode.
        Type *T = CI->getArgOperand(0)->getType();
        unsigned Bits = bitWidthOf(T, DL);
        auto *IT = dyn_cast<IntegerType>(T);
        uint8_t W;
        if (!IT || !Bits || !storageWidthCode(T, DL, W))
          return fail("saturating intrinsic width");
        Intrinsic::ID Id = Callee->getIntrinsicID();
        bool Signed = (Id == Intrinsic::sadd_sat || Id == Intrinsic::ssub_sat);
        bool Add = (Id == Intrinsic::sadd_sat || Id == Intrinsic::uadd_sat);
        uint8_t Bv = regOf(CI->getArgOperand(0));
        uint8_t Cv = regOf(CI->getArgOperand(1));
        uint8_t Tmp = allocReg();
        uint8_t Cmp = allocReg();
        uint8_t Sat = allocReg();
        uint8_t R = allocReg();
        if (Failed)
          return false;
        emit(Add ? OP_ADD : OP_SUB, W, Tmp, Bv, Cv);
        if (!Signed) {
          // The unsigned result wraps past the other operand exactly when the
          // operation overflows (add) or underflows (sub).
          if (Add)
            emit(OP_ICMP_ULT, W, Cmp, Tmp, Bv);
          else
            emit(OP_ICMP_ULT, W, Cmp, Bv, Cv);
          APInt Clamp = Add ? APInt::getAllOnes(Bits) : APInt::getZero(Bits);
          if (!materialize(ConstantInt::get(IT, Clamp), Sat, T))
            return false;
        } else {
          // Signed overflow: the operands and the result disagree in sign.
          uint8_t X = allocReg();
          uint8_t Y = allocReg();
          uint8_t Z = allocReg();
          uint8_t Sgn = allocReg();
          uint8_t Hi = allocReg();
          if (Failed)
            return false;
          // add: (B ^ Tmp) & (C ^ Tmp) < 0
          // sub: (B ^ C)   & (B ^ Tmp) < 0
          emit(OP_XOR, W, X, Bv, Tmp);
          emit(OP_XOR, W, Y, Add ? Cv : Bv, Add ? Tmp : Cv);
          emit(OP_AND, W, Z, X, Y);
          if (!materialize(ConstantInt::get(IT, APInt::getZero(Bits)), Sat, T))
            return false;
          emit(OP_ICMP_SLT, W, Cmp, Z, Sat);
          // The clamped value is INT_MIN when the first operand is negative,
          // which is the sign the true result would have had.
          emit(OP_ICMP_SLT, W, Sgn, Bv, Sat);
          if (!materialize(
                  ConstantInt::get(IT, APInt::getSignedMinValue(Bits)), Sat, T))
            return false;
          if (!materialize(
                  ConstantInt::get(IT, APInt::getSignedMaxValue(Bits)), Hi, T))
            return false;
          emit(OP_SELECT, W, Sat, Sgn, Sat, 0, Hi);
        }
        emit(OP_SELECT, W, R, Cmp, Sat, 0, Tmp);
        Regs[&I] = R;
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
      case Intrinsic::fshl:
      case Intrinsic::fshr: {
        uint8_t W;
        if (!widthCodeForBits(bitWidthOf(CI->getType(), DL), W))
          return fail("funnel shift width");
        uint8_t A = allocReg();
        uint8_t Bv = regOf(CI->getArgOperand(0));
        uint8_t Cv = regOf(CI->getArgOperand(1));
        uint8_t Sv = regOf(CI->getArgOperand(2));
        if (Failed)
          return false;
        emit(Callee->getIntrinsicID() == Intrinsic::fshl ? OP_FSHL : OP_FSHR,
             W, A, Bv, Cv, 0, Sv);
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
  if (!Ty->isVoidTy() && !isSupportedScalar(Ty, DL)) {
    std::string S;
    raw_string_ostream OS(S);
    Ty->print(OS);
    return fail("unsupported value type: " + OS.str());
  }

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

    // Immediate form: buildImmCandidates() proved the constant has no other
    // use, so it was never given a register.  Shifts carry the amount inline;
    // everything else indexes the constant pool.
    auto EmitImm = [&](ConstantInt *CI, Value *Other) -> bool {
      uint8_t Op = immOpcodeFor(BO->getOpcode());
      if (Op == OP_COUNT)
        return false;
      uint8_t A = allocReg();
      uint8_t B = regOf(Other);
      if (Failed)
        return false;
      uint32_t Imm = isShiftImm(Op) ? (uint32_t)CI->getZExtValue()
                                    : addIntConst(CI->getZExtValue());
      emit(Op, W, A, B, 0, 0, Imm);
      Regs[&I] = A;
      return true;
    };
    if (auto *CI = dyn_cast<ConstantInt>(BO->getOperand(1)))
      if (ImmOnly.count(CI))
        return EmitImm(CI, BO->getOperand(0));
    if (auto *CI = dyn_cast<ConstantInt>(BO->getOperand(0)))
      if (ImmOnly.count(CI) && BO->isCommutative())
        return EmitImm(CI, BO->getOperand(1));

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
    // Pointer relations are unsigned; the register already holds ptrtoint.
    if (OT->isPointerTy() && CI->getPredicate() != CmpInst::ICMP_EQ &&
        CI->getPredicate() != CmpInst::ICMP_NE &&
        CI->getPredicate() != CmpInst::ICMP_UGT &&
        CI->getPredicate() != CmpInst::ICMP_UGE &&
        CI->getPredicate() != CmpInst::ICMP_ULT &&
        CI->getPredicate() != CmpInst::ICMP_ULE)
      return fail("signed relational pointer compare");
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
    case CmpInst::ICMP_SGT:
      Op = OT->isPointerTy() ? OP_ICMP_UGT : OP_ICMP_SGT;
      break;
    case CmpInst::ICMP_SGE:
      Op = OT->isPointerTy() ? OP_ICMP_UGE : OP_ICMP_SGE;
      break;
    case CmpInst::ICMP_SLT:
      Op = OT->isPointerTy() ? OP_ICMP_ULT : OP_ICMP_SLT;
      break;
    case CmpInst::ICMP_SLE:
      Op = OT->isPointerTy() ? OP_ICMP_ULE : OP_ICMP_SLE;
      break;
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
    // A frame-resident phi has no register at all: its incoming edges write
    // the slot and every use reads it back.
    if (SpillPinned || Regs.count(&PN))
      continue;
    uint8_t R = allocReg();
    if (Failed)
      return false;
    Regs[&PN] = R;
  }
  unsigned Idx = 0;
  DeferredOps.clear();
  DeferredCmp = nullptr;
  for (Instruction &I : BB) {
    JustDeferred = false;
    size_t FillMark = FillRegs.size();
    if (!translateInst(I))
      return false;
    if (!JustDeferred) {
      // Frame-resident definition: the slot becomes authoritative right away.
      // The defining register survives only while the block still reads it,
      // which is what keeps the register file from filling up with values that
      // are already in memory.
      if (isSpilled(&I)) {
        auto R = Regs.find(&I);
        if (R != Regs.end()) {
          emit(OP_SPILL, W_I64, R->second, 0, 0, 0, spillOff(&I));
          auto LU = LastUse.find(&BB);
          bool ReadLater = LU != LastUse.end() && LU->second.count(&I) != 0;
          if (!ReadLater)
            releaseValue(&I);
        }
      }
      releaseDeadOperands(I, Idx);
    } else {
      // The compare is emitted by the terminator, which is the only place its
      // operands are read.  Keeping them until then also keeps their registers
      // out of the free list while the terminator still needs them.
      for (Value *Op : I.operands())
        if (!isa<Constant>(Op))
          DeferredOps.push_back(Op);
    }
    releaseFills(FillMark);
    ++Idx;
  }
  // The block is done; any frame-resident definition that was still holding a
  // register has its slot written already.
  // The terminator has run; now the deferred operands are genuinely dead.
  for (Value *V : DeferredOps)
    if (!PinnedSet.count(V))
      releaseValue(V);
  DeferredOps.clear();
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

  // Reserve the scratch slots immediately above the argument registers.  The
  // outgoing-argument block is sized from the widest call in this function so
  // a leaf that never calls anything does not pay for it; those small leaves
  // are exactly the functions that tend to recurse deeply.
  unsigned CallArgs = 0;
  for (BasicBlock &BB : F)
    for (Instruction &I : BB) {
      // memcpy/memmove/memset are intrinsics but are lowered to a three
      // argument call, so they need the same argument block as a real call.
      if (isa<MemIntrinsic>(&I)) {
        CallArgs = std::max(CallArgs, 3u);
        continue;
      }
      auto *CB = dyn_cast<CallBase>(&I);
      if (!CB)
        continue;
      if (Function *Callee = CB->getCalledFunction())
        if (Callee->isIntrinsic())
          continue;
      CallArgs = std::max(CallArgs, (unsigned)CB->arg_size());
    }
  Program.ArgBase = NextReg;
  for (unsigned I = 0; I < CallArgs; ++I) {
    allocReg();
    if (Failed)
      return false;
  }
  Program.TmpReg = allocReg();
  Program.FrameReg = allocReg();
  if (Failed)
    return false;
  Program.RegBase = NextReg;

  uint8_t Perm[OP_COUNT];
  for (unsigned I = 0; I < OP_COUNT; ++I)
    Perm[I] = (uint8_t)I;
  for (unsigned I = OP_COUNT; I > 1; --I) {
    unsigned J = (unsigned)(nextRand() % I);
    std::swap(Perm[I - 1], Perm[J]);
  }
  for (unsigned I = 0; I < OP_COUNT; ++I)
    Program.OpMap[I] = Perm[I];

  // Level 2+: give every semantic between two and four encodings.  The pool is
  // shared, so the 59 semantics still fit in one byte (worst case 236 values).
  if (Level >= 2) {
    std::vector<uint8_t> Pool(256);
    for (unsigned I = 0; I < 256; ++I)
      Pool[I] = (uint8_t)I;
    for (unsigned I = 256; I > 1; --I) {
      unsigned J = (unsigned)(nextRand() % I);
      std::swap(Pool[I - 1], Pool[J]);
    }
    // Every semantic gets the same base number of encodings; the remainder is
    // handed out in random order, so the total never exceeds one byte.
    unsigned Base = 256 / OP_COUNT;
    unsigned Extra = 256 % OP_COUNT;
    std::vector<unsigned> Order(OP_COUNT);
    for (unsigned I = 0; I < OP_COUNT; ++I)
      Order[I] = I;
    for (unsigned I = OP_COUNT; I > 1; --I) {
      unsigned J = (unsigned)(nextRand() % I);
      std::swap(Order[I - 1], Order[J]);
    }
    unsigned Cursor = 0;
    for (unsigned K = 0; K < OP_COUNT; ++K) {
      unsigned Op = Order[K];
      unsigned N = Base + (K < Extra ? 1 : 0);
      for (unsigned M = 0; M < N; ++M)
        Program.Aliases[Op].push_back(Pool[Cursor++]);
    }
  } else {
    for (unsigned Op = 0; Op < OP_COUNT; ++Op)
      Program.Aliases[Op].push_back(Program.OpMap[Op]);
  }

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

  // Decide which constants fold into an immediate instruction before the
  // hoist loop runs; collectConstant() consults the result.
  buildImmCandidates();

  // Hoist every constant to a prologue so a value materialised in one arm is
  // still available on every other path (constants must dominate all uses).
  // Spill mode trades that for register pressure: a function that has already
  // overflowed the register file is usually also constant-heavy, and a
  // materialisation per use is far cheaper than failing outright.
  if (!SpillPinned) {
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
      // The frame is capped at kMaxFrameBytes later, so an alloca larger than
      // that is rejected anyway.  Checking here as well keeps the multiply
      // below from wrapping: a wrapped size would hand out a slot that is far
      // smaller than the object the function believes it owns.
      if (Elem && Count > kMaxFrameBytes / Elem)
        return fail("alloca too large");
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
  // Frame slots start after the last alloca, 8-byte aligned.  The offsets are
  // baked into the bytecode, so this has to be fixed before the first block is
  // translated.
  SpillBase = (uint32_t)alignTo(FrameSize, 8);
  // Register-reuse information has to exist before the prologue: whether an
  // alloca pointer stays in a register or moves to the frame depends on whether
  // its live range crosses a block boundary.
  buildReuseInfo();
  for (AllocaInst *AI : Allocas) {
    uint8_t R = allocReg();
    if (Failed)
      return false;
    uint64_t Off = AllocaOff[AI];
    emit(OP_MOV, W_PTR, R, Program.FrameReg);
    SmallVector<uint8_t, 4> Temps{R};
    uint8_t Final = R;
    if (Off) {
      uint8_t CR = allocReg();
      if (Failed)
        return false;
      emit(OP_IMM, W_I64, CR, 0, 0, 0, addIntConst(Off));
      uint8_t NR = allocReg();
      if (Failed)
        return false;
      emit(OP_ADD, W_I64, NR, R, CR);
      Temps.push_back(CR);
      Temps.push_back(NR);
      if (PtrBits < 64) {
        uint8_t TR = allocReg();
        if (Failed)
          return false;
        emit(OP_TRUNC, W_PTR, TR, NR, 0, W_I64);
        Temps.push_back(TR);
        Final = TR;
      } else {
        Final = NR;
      }
    }
    if (isSpilled(AI)) {
      // The pointer is frame-resident like any other cross-block value; the
      // address registers can go straight back to the free list.
      emit(OP_SPILL, W_I64, Final, 0, 0, 0, spillOff(AI));
      for (uint8_t X : Temps)
        FreeRegs.push_back(X);
    } else {
      Regs[AI] = Final;
      for (uint8_t X : Temps)
        if (X != Final)
          FreeRegs.push_back(X);
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

  // Every PHI of every translated block must have been copied on every
  // reachable incoming edge.  This is a structural invariant: if a copy is
  // missing, the destination register holds whatever the previous block left
  // behind, which for a pointer means a wild access at run time.  Checking it
  // here costs one skipped function, not a corrupt binary.
  for (BasicBlock &BB : F) {
    if (!BlockPC.count(&BB))
      continue;
    for (PHINode &PN : BB.phis()) {
      for (BasicBlock *Pred : predecessors(&BB)) {
        if (!BlockPC.count(Pred))
          continue;
        if (!PhiEdgesDone.count({Pred, &PN}))
          return fail(Twine("phi edge not copied for ") + PN.getName());
      }
    }
  }

  Program.Key = nextRand() | 1;
  Program.Level = Level;
  Program.BodyHash = nextRand();
  // The wrapper allocates Program.FrameSize bytes, so the spill area has to be
  // part of it.  SpillBase was fixed before translation and the slot count is
  // only known now.
  Program.SpillSlots = (unsigned)SpillSlot.size();
  if (Program.SpillSlots)
    Program.FrameSize = SpillBase + (uint64_t)Program.SpillSlots * 8;
  // The frame is a stack object in the wrapper, so its size is charged to every
  // call, including recursive ones.  A function with tens of thousands of
  // cross-block values would otherwise turn into a stack overflow at run time,
  // which is worse than leaving it unvirtualized.
  if (Program.FrameSize > kMaxFrameBytes)
    return fail(Twine("frame too large: ") + Twine(Program.FrameSize) + " bytes");

  // Size the interpreter's register file from the registers this function
  // actually uses.  A small pad keeps the array size from being a recognisable
  // constant without reintroducing the fixed two-kilobyte frame that made deep
  // recursion overflow the stack.
  {
    unsigned Slots = (unsigned)NextReg + (unsigned)(nextRand() % 8);
    if (Slots > kRegLimit)
      Slots = kRegLimit;
    if (Slots < (unsigned)NextReg)
      Slots = NextReg;
    Program.RegSlots = std::max(Slots, 1u);
  }

  // A recursive function keeps one interpreter frame per activation, so its
  // per-call footprint is multiplied by the recursion depth.  A function that
  // spills heavily would exhaust the stack after a few hundred levels, which
  // is worse than leaving it unvirtualized: callers of the original see the
  // same depth they always had.  The driver reports how many functions share
  // this one's call-graph cycle, so mutual recursion (A -> B -> A) is charged
  // like a direct self-call: one level of recursion runs every member once,
  // therefore the whole cycle has to fit in the budget together.
  {
    uint64_t PerCall = Program.FrameSize + (uint64_t)Program.RegSlots * 8 +
                       (uint64_t)Program.ArgCount * 8;
    unsigned Cycle = RecursionCycle;
    if (!Cycle) {
      for (BasicBlock &BB : F)
        for (Instruction &I : BB)
          if (auto *CB = dyn_cast<CallBase>(&I))
            if (CB->getCalledOperand()->stripPointerCasts() == &F)
              Cycle = 1;
    }
    if (Cycle && PerCall > kMaxRecursiveVmBytes / Cycle) {
      std::string Msg = "recursive function";
      if (Cycle > 1)
        Msg += " in a call cycle of " + std::to_string(Cycle);
      Msg += " with " + std::to_string(PerCall) +
             " bytes of per-call VM state";
      return fail(Msg);
    }
  }

  // Level 2+: permute the ordinary value registers.  Arguments and the scratch
  // slots stay put: the interpreter prologue writes arguments at 0..ArgCount-1
  // and the handlers name the scratch slots directly.
  if (Level >= 2) {
    unsigned Base = Program.RegBase;
    unsigned Count = Program.RegSlots;
    if (Count > Base) {
      std::vector<uint8_t> Perm(Count);
      for (unsigned I = 0; I < Count; ++I)
        Perm[I] = (uint8_t)I;
      for (unsigned I = Count; I > Base + 1; --I) {
        unsigned J = Base + (unsigned)(nextRand() % (I - Base));
        std::swap(Perm[I - 1], Perm[J]);
      }
      auto Map = [&](uint8_t &R) {
        if (R >= Base && R < Count)
          R = Perm[R];
      };
      for (VInst &I : Program.Code) {
        Map(I.A);
        Map(I.B);
        Map(I.C);
        if (immHoldsReg(I.Op) && I.Imm >= Base && I.Imm < Count)
          I.Imm = Perm[I.Imm];
      }
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
      Call->setCallingConv(D.CC);
      Call->setAttributes(D.Direct->getAttributes());
    } else {
      Call = B.CreateCall(D.SiteFT, T->getArg(1), CallArgs);
      Call->setCallingConv(D.CC);
      Call->setAttributes(D.Attrs);
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
    const std::vector<uint8_t> &Aliases = P.Aliases[V.Op];
    uint32_t Fold = I * 2654435761u ^ (uint32_t)P.Key;
    uint8_t EncOp = Aliases[Fold % Aliases.size()];
    uint32_t W0 = (uint32_t)EncOp | ((uint32_t)V.W << 8) |
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

  // Only emit handlers this program actually uses.  A function that never
  // compares anything should not carry ten compare handlers, and one without
  // floating point should not carry twenty FP handlers: on a per-function
  // interpreter that is most of the size.  `Covered` lets the builder reject
  // a program whose bytecode mentions an opcode it failed to emit, instead of
  // silently trapping at run time.
  DenseSet<uint8_t> Used;
  for (const VInst &V : P.Code)
    Used.insert(V.Op);
  DenseSet<uint8_t> Covered;

  // The register file is sized from the translator's actual register count
  // (plus a small random pad), not from the 8-bit operand space.  It is a
  // stack object in every interpreter activation, so a fixed 2 KB array would
  // be paid again on every recursive call and blow the stack long before the
  // native version does.
  unsigned RegSlots = P.RegSlots;
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
  // The handlers load and store every slot with `align 8`, so the array has to
  // be at least that aligned.  The natural alignment of `[N x i64]` is only 4
  // on targets whose i64 ABI alignment is 4 (i386 SysV, some bare-metal ARM
  // ABIs), which would make every odd slot's `store i64, align 8` an
  // over-aligned access -- undefined behaviour even though x86 and ARM happen
  // to tolerate it.  Allocas may be over-aligned freely, so pin it here.
  cast<AllocaInst>(Regs)->setAlignment(Align(8));
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
                             {B.getInt32(0), B.getInt32(P.FrameReg)});
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
  // Read one entry of the integer constant pool.  Level 2+ stores it encrypted
  // with a per-index mask, and the volatile load keeps the optimiser from
  // folding the plaintext back in.
  auto loadIntConst = [&](Value *IdxV) -> Value * {
    Value *Cp = B.CreateGEP(I64, IntGV, IdxV);
    Value *V = B.CreateAlignedLoad(I64, Cp, Align(8), P.Level >= 2);
    if (P.Level >= 2) {
      Value *Mask = B.CreateAdd(
          B.getInt64(P.Key),
          B.CreateMul(B.CreateZExt(IdxV, I64),
                      B.getInt64(0x9E3779B97F4A7C15ULL)));
      V = B.CreateXor(V, Mask);
    }
    return V;
  };
  auto newBB = [&]() { return BasicBlock::Create(Ctx, "", Fn); };

  auto AddCase = [&](VMOp Op, BasicBlock *BB) {
    Covered.insert((uint8_t)Op);
    for (uint8_t Alias : P.Aliases[Op])
      Sw->addCase(ConstantInt::get(I32, Alias), BB);
  };

  // ---- OP_NOP -----------------------------------------------------------
  if (Used.count(OP_NOP)) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_NOP, BB);
  }

  // ---- OP_MOV -----------------------------------------------------------
  if (Used.count(OP_MOV)) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    storeReg(D.A, zextTo(loadReg(D.B), D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_MOV, BB);
  }

  // ---- OP_IMM -----------------------------------------------------------
  if (Used.count(OP_IMM)) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *V = loadIntConst(D.Imm);
    storeReg(D.A, zextTo(V, D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_IMM, BB);
  }

  // ---- OP_PTR -----------------------------------------------------------
  if (Used.count(OP_PTR)) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Pp = B.CreateGEP(Ptr, PtrGV, D.Imm);
    // `[N x ptr]` only guarantees the element ABI alignment, which is 4 on a
    // 32-bit target: claiming 8 for an odd index would be an over-aligned
    // access.
    Value *V = B.CreateAlignedLoad(Ptr, Pp, DL.getPointerABIAlignment(0), false);
    storeReg(D.A, zextTo(B.CreatePtrToInt(V, I64), D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_PTR, BB);
  }

  // ---- OP_LOAD ----------------------------------------------------------
  if (Used.count(OP_LOAD)) {
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
  if (Used.count(OP_STORE)) {
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

  // ---- OP_SPILL / OP_FILL ----------------------------------------------
  // Frame traffic.  The frame base is already in a register; the slot offset
  // is an immediate, so the addressable frame is not limited by the 8-bit
  // register operand.
  auto frameAddr = [&](Value *Off) {
    Value *Base = B.CreateAnd(loadReg(B.getInt32(P.FrameReg)), ptrMask());
    Value *Bits =
        B.CreateAnd(B.CreateAdd(Base, B.CreateZExt(Off, I64)), ptrMask());
    return B.CreateIntToPtr(Bits, Ptr);
  };
  if (Used.count(OP_SPILL)) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Addr = frameAddr(D.Imm);
    B.CreateAlignedStore(loadReg(D.A), Addr, Align(8));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_SPILL, BB);
  }
  if (Used.count(OP_FILL)) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Addr = frameAddr(D.Imm);
    Value *V = B.CreateAlignedLoad(I64, Addr, Align(8), false);
    storeReg(D.A, V);
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_FILL, BB);
  }

  auto emitBin = [&](VMOp Op, bool Signed, bool Div) {    BasicBlock *BB = newBB();
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
  if (Used.count(OP_ADD)) emitBin(OP_ADD, false, false);
  if (Used.count(OP_SUB)) emitBin(OP_SUB, false, false);
  if (Used.count(OP_MUL)) emitBin(OP_MUL, false, false);
  if (Used.count(OP_AND)) emitBin(OP_AND, false, false);
  if (Used.count(OP_OR)) emitBin(OP_OR, false, false);
  if (Used.count(OP_XOR)) emitBin(OP_XOR, false, false);
  if (Used.count(OP_UDIV)) emitBin(OP_UDIV, false, true);
  if (Used.count(OP_SDIV)) emitBin(OP_SDIV, true, true);
  if (Used.count(OP_UREM)) emitBin(OP_UREM, false, true);
  if (Used.count(OP_SREM)) emitBin(OP_SREM, true, true);

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
  if (Used.count(OP_SHL)) emitShift(OP_SHL);
  if (Used.count(OP_LSHR)) emitShift(OP_LSHR);
  if (Used.count(OP_ASHR)) emitShift(OP_ASHR);

  // ---- immediate superinstructions --------------------------------------
  // A = B <op> constant.  The shift variants keep the amount in the
  // instruction word; the rest read the pool.  Masking matches emitShift so a
  // malformed bytecode cannot shift by more than the operand width.
  auto emitBinImm = [&](VMOp Op) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    bool Signed = isSignedImm(Op);
    Value *X = Signed ? sextTo(loadReg(D.B), D.W) : zextTo(loadReg(D.B), D.W);
    Value *R = nullptr;
    if (isShiftImm(Op)) {
      Value *Bits = loadBits(D.W);
      Value *AmtMask = B.CreateSub(Bits, B.getInt32(1));
      Value *Amt = B.CreateAnd(D.Imm, AmtMask);
      Value *ZAmt = B.CreateZExt(Amt, I64);
      if (Op == OP_SHL_IMM)
        R = B.CreateShl(X, ZAmt);
      else if (Op == OP_LSHR_IMM)
        R = B.CreateLShr(X, ZAmt);
      else
        R = B.CreateAShr(X, ZAmt);
    } else {
      Value *Cst = loadIntConst(D.Imm);
      Value *Y = Signed ? sextTo(Cst, D.W) : zextTo(Cst, D.W);
      switch (Op) {
      case OP_ADD_IMM: R = B.CreateAdd(X, Y); break;
      case OP_SUB_IMM: R = B.CreateSub(X, Y); break;
      case OP_MUL_IMM: R = B.CreateMul(X, Y); break;
      case OP_AND_IMM: R = B.CreateAnd(X, Y); break;
      case OP_OR_IMM:  R = B.CreateOr(X, Y); break;
      default:         R = B.CreateXor(X, Y); break;
      }
    }
    storeReg(D.A, zextTo(R, D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(Op, BB);
  };
  if (Used.count(OP_ADD_IMM)) emitBinImm(OP_ADD_IMM);
  if (Used.count(OP_SUB_IMM)) emitBinImm(OP_SUB_IMM);
  if (Used.count(OP_MUL_IMM)) emitBinImm(OP_MUL_IMM);
  if (Used.count(OP_AND_IMM)) emitBinImm(OP_AND_IMM);
  if (Used.count(OP_OR_IMM)) emitBinImm(OP_OR_IMM);
  if (Used.count(OP_XOR_IMM)) emitBinImm(OP_XOR_IMM);
  if (Used.count(OP_SHL_IMM)) emitBinImm(OP_SHL_IMM);
  if (Used.count(OP_LSHR_IMM)) emitBinImm(OP_LSHR_IMM);
  if (Used.count(OP_ASHR_IMM)) emitBinImm(OP_ASHR_IMM);

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
  if (Used.count(OP_ICMP_EQ)) emitCmp(OP_ICMP_EQ, CmpInst::ICMP_EQ, false);
  if (Used.count(OP_ICMP_NE)) emitCmp(OP_ICMP_NE, CmpInst::ICMP_NE, false);
  if (Used.count(OP_ICMP_UGT)) emitCmp(OP_ICMP_UGT, CmpInst::ICMP_UGT, false);
  if (Used.count(OP_ICMP_UGE)) emitCmp(OP_ICMP_UGE, CmpInst::ICMP_UGE, false);
  if (Used.count(OP_ICMP_ULT)) emitCmp(OP_ICMP_ULT, CmpInst::ICMP_ULT, false);
  if (Used.count(OP_ICMP_ULE)) emitCmp(OP_ICMP_ULE, CmpInst::ICMP_ULE, false);
  if (Used.count(OP_ICMP_SGT)) emitCmp(OP_ICMP_SGT, CmpInst::ICMP_SGT, true);
  if (Used.count(OP_ICMP_SGE)) emitCmp(OP_ICMP_SGE, CmpInst::ICMP_SGE, true);
  if (Used.count(OP_ICMP_SLT)) emitCmp(OP_ICMP_SLT, CmpInst::ICMP_SLT, true);
  if (Used.count(OP_ICMP_SLE)) emitCmp(OP_ICMP_SLE, CmpInst::ICMP_SLE, true);

  // Fused compare-and-branch: operands in A/B, width in W, true target in Imm.
  // False simply advances the PC, so the following BR still owns the other
  // edge and PHI copies keep working unchanged.
  auto emitCmpBr = [&](VMOp Op, CmpInst::Predicate Pred, bool Signed) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *X = Signed ? sextTo(loadReg(D.A), D.W) : zextTo(loadReg(D.A), D.W);
    Value *Y = Signed ? sextTo(loadReg(D.B), D.W) : zextTo(loadReg(D.B), D.W);
    Value *Cmp = B.CreateICmp(Pred, X, Y);
    Value *Next = B.CreateAdd(Pc, B.getInt32(1));
    Value *Tgt = B.CreateSelect(Cmp, D.Imm, Next);
    B.CreateAlignedStore(Tgt, PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(Op, BB);
  };
  if (Used.count(OP_ICMP_EQ_CBR)) emitCmpBr(OP_ICMP_EQ_CBR, CmpInst::ICMP_EQ, false);
  if (Used.count(OP_ICMP_NE_CBR)) emitCmpBr(OP_ICMP_NE_CBR, CmpInst::ICMP_NE, false);
  if (Used.count(OP_ICMP_UGT_CBR)) emitCmpBr(OP_ICMP_UGT_CBR, CmpInst::ICMP_UGT, false);
  if (Used.count(OP_ICMP_UGE_CBR)) emitCmpBr(OP_ICMP_UGE_CBR, CmpInst::ICMP_UGE, false);
  if (Used.count(OP_ICMP_ULT_CBR)) emitCmpBr(OP_ICMP_ULT_CBR, CmpInst::ICMP_ULT, false);
  if (Used.count(OP_ICMP_ULE_CBR)) emitCmpBr(OP_ICMP_ULE_CBR, CmpInst::ICMP_ULE, false);
  if (Used.count(OP_ICMP_SGT_CBR)) emitCmpBr(OP_ICMP_SGT_CBR, CmpInst::ICMP_SGT, true);
  if (Used.count(OP_ICMP_SGE_CBR)) emitCmpBr(OP_ICMP_SGE_CBR, CmpInst::ICMP_SGE, true);
  if (Used.count(OP_ICMP_SLT_CBR)) emitCmpBr(OP_ICMP_SLT_CBR, CmpInst::ICMP_SLT, true);
  if (Used.count(OP_ICMP_SLE_CBR)) emitCmpBr(OP_ICMP_SLE_CBR, CmpInst::ICMP_SLE, true);

  // ---- OP_SELECT --------------------------------------------------------
  if (Used.count(OP_SELECT)) {
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
  if (Used.count(OP_ZEXT)) emitCast(OP_ZEXT);
  if (Used.count(OP_SEXT)) emitCast(OP_SEXT);
  if (Used.count(OP_TRUNC)) emitCast(OP_TRUNC);

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
  if (Used.count(OP_CTPOP)) emitBitIntrinsic(OP_CTPOP);
  if (Used.count(OP_CTLZ)) emitBitIntrinsic(OP_CTLZ);
  if (Used.count(OP_CTTZ)) emitBitIntrinsic(OP_CTTZ);
  if (Used.count(OP_BSWAP)) emitBitIntrinsic(OP_BSWAP);
  if (Used.count(OP_BITREVERSE)) emitBitIntrinsic(OP_BITREVERSE);

  // ---- funnel shifts ----------------------------------------------------
  // fshl(a,b,s) = s == 0 ? a : (a << s) | (b >> (Bits - s))
  // fshr(a,b,s) = s == 0 ? b : (a << (Bits - s)) | (b >> s)
  // The shift amount is masked to Bits-1 and the zero case is selected
  // explicitly, so neither a 64-bit shift-by-64 nor a spurious OR of the two
  // inputs can happen.
  auto emitFunnel = [&](VMOp Op) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Bits = loadBits(D.W);
    Value *X = zextTo(loadReg(D.B), D.W);
    Value *Y = zextTo(loadReg(D.C), D.W);
    Value *AmtMask = B.CreateSub(Bits, B.getInt32(1));
    Value *S32 = B.CreateAnd(B.CreateTrunc(loadReg(D.Imm), I32), AmtMask);
    Value *S = B.CreateZExt(S32, I64);
    Value *B64 = B.CreateZExt(Bits, I64);
    Value *Inv = B.CreateAnd(B.CreateSub(B64, S), B.getInt64(63));
    Value *L = Op == OP_FSHL ? B.CreateShl(X, S) : B.CreateShl(X, Inv);
    Value *R = Op == OP_FSHL ? B.CreateLShr(Y, Inv) : B.CreateLShr(Y, S);
    Value *V = B.CreateOr(L, R);
    Value *IsZero = B.CreateICmpEQ(S, B.getInt64(0));
    Value *Res = B.CreateSelect(IsZero, Op == OP_FSHL ? X : Y, V);
    storeReg(D.A, zextTo(Res, D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(Op, BB);
  };
  if (Used.count(OP_FSHL)) emitFunnel(OP_FSHL);
  if (Used.count(OP_FSHR)) emitFunnel(OP_FSHR);

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
  if (Used.count(OP_FADD)) emitFPBin(OP_FADD);
  if (Used.count(OP_FSUB)) emitFPBin(OP_FSUB);
  if (Used.count(OP_FMUL)) emitFPBin(OP_FMUL);
  if (Used.count(OP_FDIV)) emitFPBin(OP_FDIV);
  if (Used.count(OP_FREM)) emitFPBin(OP_FREM);

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
  if (Used.count(OP_FNEG)) emitFPUn(OP_FNEG);
  if (Used.count(OP_FABS)) emitFPUn(OP_FABS);
  if (Used.count(OP_FSQRT)) emitFPUn(OP_FSQRT);

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
  if (Used.count(OP_FPTOSI)) emitFPToInt(OP_FPTOSI, true);
  if (Used.count(OP_FPTOUI)) emitFPToInt(OP_FPTOUI, false);

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
  if (Used.count(OP_SITOFP)) emitIntToFP(OP_SITOFP, true);
  if (Used.count(OP_UITOFP)) emitIntToFP(OP_UITOFP, false);

  // ---- OP_BR ------------------------------------------------------------
  if (Used.count(OP_BR)) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    B.CreateAlignedStore(D.Imm, PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_BR, BB);
  }

  // ---- OP_CBR -----------------------------------------------------------
  if (Used.count(OP_CBR)) {
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
  if (Used.count(OP_RET)) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *V = zextTo(loadReg(D.A), D.W);
    B.CreateRet(V);
    AddCase(OP_RET, BB);
  }

  // ---- OP_CALL ----------------------------------------------------------
  if (Used.count(OP_CALL)) {
    BasicBlock *BB = newBB();
    B.SetInsertPoint(BB);
    Value *Pp = B.CreateGEP(Ptr, ThunkGV, D.Imm);
    // Same element-alignment rule as OP_PTR: the thunk table is `[N x ptr]`.
    Value *FnPtr =
        B.CreateAlignedLoad(Ptr, Pp, DL.getPointerABIAlignment(0), false);
    Value *ArgBase = B.CreateGEP(RegArrayTy, Regs,
                                 {B.getInt32(0), B.getInt32(P.ArgBase)});
    Value *HasFn = B.CreateICmpNE(B.CreateAnd(D.Flags, B.getInt32(0x80)),
                                  B.getInt32(0));
    Value *Target = B.CreateIntToPtr(loadReg(D.B), Ptr);
    Value *FnArg = B.CreateSelect(
        HasFn, Target, ConstantPointerNull::get(cast<PointerType>(Ptr)));
    FunctionType *ThunkFT = FunctionType::get(I64, {Ptr, Ptr}, false);
    CallInst *Call = B.CreateCall(ThunkFT, FnPtr, {ArgBase, FnArg});
    Call->setCallingConv(CallingConv::C);
    // The destination is part of the instruction, so the result lands in its
    // register without a separate move.  Void calls name the scratch slot.
    storeReg(D.A, zextTo(Call, D.W));
    B.CreateAlignedStore(B.CreateAdd(Pc, B.getInt32(1)), PcSlot, Align(4));
    B.CreateBr(Loop);
    AddCase(OP_CALL, BB);
  }

  // ---- OP_TRAP ----------------------------------------------------------
  if (Used.count(OP_TRAP)) {
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

  for (uint8_t Op : Used)
    if (!Covered.count(Op)) {
      Reason = "no handler for opcode " + std::to_string((unsigned)Op);
      return nullptr;
    }
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
  //
  // Operands must be released before the blocks are destroyed.  An alloca in
  // the entry block is referenced by loads and stores in later blocks, so
  // erasing the entry first would destroy the alloca while those uses are
  // still live -- a use-after-free that only an assertions build reports.
  SmallVector<BasicBlock *, 32> Dead;
  for (BasicBlock &BB : F)
    if (&BB != Entry)
      Dead.push_back(&BB);
  for (BasicBlock *BB : Dead)
    BB->dropAllReferences();
  for (BasicBlock *BB : Dead)
    BB->eraseFromParent();
  return true;
}

void VMRuntimeBuilder::discard() {
  // `Interp` is also the first entry of `CreatedFunctions`, so erasing it here
  // and then walking the list would touch the freed object: `getParent()` on a
  // deleted Function reads recycled storage and, when the allocator hands the
  // block back with the old contents, calls eraseFromParent() a second time --
  // a double free.  Delete each function exactly once and clear Interp last.
  Function *Skip = Interp;
  for (auto It = CreatedFunctions.rbegin(); It != CreatedFunctions.rend();
       ++It) {
    Function *Fn = *It;
    if (Fn && Fn != Skip && Fn->getParent())
      Fn->eraseFromParent();
  }
  if (Skip && Skip->getParent())
    Skip->eraseFromParent();
  Interp = nullptr;
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

// ---------------------------------------------------------------------------
// Vector memory scalarisation
// ---------------------------------------------------------------------------
//
// SLP turns constant initialisers and struct copies into vector stores and
// loads.  The VM has no vector registers, so one such instruction is enough to
// keep an entire function out of the virtualiser.  Splitting them back into
// element accesses costs nothing: the backend re-vectorises whatever it can
// still prove, and the function becomes translatable.
//
// Only the shapes whose memory layout is exactly that of the equivalent array
// are handled.  A <3 x i32> occupies 16 bytes with padding while [3 x i32]
// occupies 12, so splitting it would touch the wrong offsets.

static bool vectorLayoutMatchesArray(Type *Ty, const DataLayout &DL) {
  auto *VT = dyn_cast<FixedVectorType>(Ty);
  if (!VT)
    return false;
  Type *Elem = VT->getElementType();
  if (!Elem->isSized() || Elem->isVectorTy())
    return false;
  ArrayType *Arr = ArrayType::get(Elem, VT->getNumElements());
  return DL.getTypeStoreSize(Ty) == DL.getTypeStoreSize(Arr);
}


// True when every lane of the constant is known.  A constant expression such
// as `bitcast (i64 1 to <2 x i32>)` has no per-lane value without evaluating
// the whole register, so it is left for the skip path.
static bool isLaneWiseConstant(Constant *C) {
  auto *VT = dyn_cast<FixedVectorType>(C->getType());
  if (!VT)
    return false;
  if (isa<PoisonValue>(C) || isa<UndefValue>(C))
    return true;
  for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i)
    if (!C->getAggregateElement(i))
      return false;
  return true;
}

// An elementwise intrinsic applied to a vector is the same operation applied
// to each lane, so it scalarises into one call to the scalar overload.  Only
// the intrinsics the translator understands are listed: a whitelist keeps
// shapes such as masked.load -- whose scalar form still reads a whole vector
// from one address -- out of the rewrite.
// Returns the scalar declaration, or null when the call is not of that shape.
static Function *scalarIntrinsicCallee(CallInst *CI) {
  Function *Callee = CI->getCalledFunction();
  if (!Callee || !Callee->isIntrinsic())
    return nullptr;
  Intrinsic::ID Id = Callee->getIntrinsicID();
  switch (Id) {
  case Intrinsic::sadd_sat:
  case Intrinsic::uadd_sat:
  case Intrinsic::ssub_sat:
  case Intrinsic::usub_sat:
  case Intrinsic::abs:
  case Intrinsic::ctlz:
  case Intrinsic::cttz:
  case Intrinsic::ctpop:
  case Intrinsic::bswap:
  case Intrinsic::bitreverse:
  case Intrinsic::fshl:
  case Intrinsic::fshr:
  case Intrinsic::fabs:
  case Intrinsic::sqrt:
  case Intrinsic::fmuladd:
    break;
  default:
    return nullptr;
  }
  auto *VT = dyn_cast<FixedVectorType>(CI->getType());
  if (!VT)
    return nullptr;
  Type *Elem = VT->getElementType();
  if (!Elem->isIntegerTy() && !Elem->isFloatingPointTy())
    return nullptr;
  Function *Scalar = Intrinsic::getOrInsertDeclaration(CI->getModule(), Id,
                                                       {Elem});
  if (!Scalar || Scalar == Callee)
    return nullptr;
  FunctionType *FT = Scalar->getFunctionType();
  if (FT->getReturnType() != Elem || FT->getNumParams() != CI->arg_size())
    return nullptr;
  for (unsigned i = 0; i != CI->arg_size(); ++i) {
    Type *PT = FT->getParamType(i);
    Type *AT = CI->getArgOperand(i)->getType();
    if (PT != AT && !(AT->isVectorTy() && PT == Elem))
      return nullptr;
  }
  return Scalar;
}

// Reductions fold every lane into one scalar.  Only the associative integer
// forms the vectoriser emits are handled.
static bool isVectorReduceCall(CallInst *CI) {
  Function *Callee = CI->getCalledFunction();
  if (!Callee || !Callee->isIntrinsic() || CI->arg_size() != 1)
    return false;
  switch (Callee->getIntrinsicID()) {
  case Intrinsic::vector_reduce_add:
  case Intrinsic::vector_reduce_mul:
  case Intrinsic::vector_reduce_and:
  case Intrinsic::vector_reduce_or:
  case Intrinsic::vector_reduce_xor:
  case Intrinsic::vector_reduce_smax:
  case Intrinsic::vector_reduce_smin:
  case Intrinsic::vector_reduce_umax:
  case Intrinsic::vector_reduce_umin:
    return dyn_cast<FixedVectorType>(CI->getArgOperand(0)->getType()) != nullptr;
  default:
    return false;
  }
}

// Instructions that mean the same thing when rebuilt one lane at a time.
// `bitcast` does not: it reinterprets the whole register.
static bool isLaneWiseOp(const Instruction &I) {
  if (isa<BinaryOperator>(I) || isa<UnaryOperator>(I) || isa<ICmpInst>(I) ||
      isa<FCmpInst>(I) || isa<SelectInst>(I))
    return true;
  if (auto *CI = dyn_cast<CastInst>(&I))
    return !isa<BitCastInst>(CI);
  return false;
}

// Scalarisation replaces one vector value with one value per lane, so a
// pathological width would multiply the function instead of shrinking it.
// SLP and the loop vectoriser stay far below this.
constexpr unsigned kMaxVectorLanes = 64;

static bool canScalarizeVectors(Function &F, const DataLayout &DL) {
  for (BasicBlock &BB : F)
    for (Instruction &I : BB) {
      bool HasVector = false;
      if (auto *VT = dyn_cast<VectorType>(I.getType())) {
        if (VT->getElementCount().isScalable() ||
            VT->getElementCount().getKnownMinValue() > kMaxVectorLanes)
          return false;
        HasVector = true;
      }
      for (Value *Op : I.operands()) {
        if (auto *VT = dyn_cast<VectorType>(Op->getType())) {
          if (VT->getElementCount().isScalable() ||
              VT->getElementCount().getKnownMinValue() > kMaxVectorLanes)
            return false;
          HasVector = true;
        }
      }
      if (!HasVector)
        continue;
      // Every vector constant has to be readable one lane at a time.
      for (Value *Op : I.operands())
        if (auto *C = dyn_cast<Constant>(Op))
          if (C->getType()->isVectorTy() && !isLaneWiseConstant(C))
            return false;

      if (auto *LI = dyn_cast<LoadInst>(&I)) {
        if (!LI->isVolatile() && !LI->isAtomic() &&
            vectorLayoutMatchesArray(LI->getType(), DL))
          continue;
        return false;
      }
      if (auto *SI = dyn_cast<StoreInst>(&I)) {
        if (!SI->isVolatile() && !SI->isAtomic() &&
            vectorLayoutMatchesArray(SI->getValueOperand()->getType(), DL))
          continue;
        return false;
      }
      if (auto *EE = dyn_cast<ExtractElementInst>(&I)) {
        if (isa<ConstantInt>(EE->getIndexOperand()))
          continue;
        return false;
      }
      if (auto *IE = dyn_cast<InsertElementInst>(&I)) {
        if (isa<ConstantInt>(IE->getOperand(2)))
          continue;
        return false;
      }
      if (auto *PN = dyn_cast<PHINode>(&I)) {
        if (isa<FixedVectorType>(PN->getType()))
          continue;
        return false;
      }
      if (auto *CB = dyn_cast<CallInst>(&I)) {
        if (isVectorReduceCall(CB) || scalarIntrinsicCallee(CB))
          continue;
        return false;
      }
      if (isa<ShuffleVectorInst>(&I))
        continue;
      if (!isLaneWiseOp(I))
        return false;
    }
  return true;
}

// Splits every vector value in F into one scalar value per lane.  Returns
// false, leaving F untouched, when the function holds a vector shape the
// rewrite does not understand.
static bool scalarizeVectors(Function &F, const DataLayout &DL) {
  SmallVector<BasicBlock *, 32> Order;
  for (BasicBlock *BB : ReversePostOrderTraversal<Function *>(&F))
    Order.push_back(BB);
  // A value defined in an unreachable block has no lane mapping by the time
  // its use is reached, so those functions are left alone.
  if (Order.size() != F.size() || !canScalarizeVectors(F, DL))
    return false;

  DenseMap<Value *, SmallVector<Value *, 4>> Lanes;
  SmallVector<Instruction *, 32> Dead;
  // Vector PHIs whose incoming lists are filled once every block has been
  // walked: a latch value is not known when its header is reached in RPO.
  SmallVector<PHINode *, 8> PendingPHIs;

  auto LaneOf = [&](Value *V, unsigned Idx) -> Value * {
    if (auto *C = dyn_cast<Constant>(V)) {
      if (isa<PoisonValue>(C) || isa<UndefValue>(C))
        return PoisonValue::get(
            cast<FixedVectorType>(V->getType())->getElementType());
      return C->getAggregateElement(Idx);
    }
    auto It = Lanes.find(V);
    if (It == Lanes.end() || Idx >= It->second.size())
      return nullptr;
    return It->second[Idx];
  };

  for (BasicBlock *BB : Order) {
    for (Instruction &I : make_early_inc_range(*BB)) {
      Type *Ty = I.getType();
      bool Vector = Ty->isVectorTy();
      for (Value *Op : I.operands())
        Vector |= Op->getType()->isVectorTy();
      if (!Vector)
        continue;

      if (auto *PN = dyn_cast<PHINode>(&I)) {
        auto *VT = cast<FixedVectorType>(Ty);
        Type *Elem = VT->getElementType();
        SmallVector<Value *, 4> V;
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          PHINode *LP = PHINode::Create(
              Elem, PN->getNumIncomingValues(),
              PN->getName() + Twine(".lane") + Twine(i), PN->getIterator());
          V.push_back(LP);
        }
        Lanes[PN] = std::move(V);
        PendingPHIs.push_back(PN);
        Dead.push_back(PN);
        continue;
      }

      if (auto *LI = dyn_cast<LoadInst>(&I)) {
        auto *VT = cast<FixedVectorType>(Ty);
        Type *Elem = VT->getElementType();
        uint64_t ElemSize = DL.getTypeStoreSize(Elem);
        IRBuilder<> B(LI);
        SmallVector<Value *, 4> V;
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          Value *P = B.CreateGEP(B.getInt8Ty(), LI->getPointerOperand(),
                                 B.getInt64(i * ElemSize));
          LoadInst *E = B.CreateLoad(Elem, P);
          E->setAlignment(Align(MinAlign(LI->getAlign().value(), ElemSize)));
          V.push_back(E);
        }
        Lanes[LI] = std::move(V);
        Dead.push_back(LI);
        continue;
      }

      if (auto *SI = dyn_cast<StoreInst>(&I)) {
        auto *VT = cast<FixedVectorType>(SI->getValueOperand()->getType());
        Type *Elem = VT->getElementType();
        uint64_t ElemSize = DL.getTypeStoreSize(Elem);
        SmallVector<Value *, 4> V;
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          Value *L = LaneOf(SI->getValueOperand(), i);
          if (!L)
            return false;
          V.push_back(L);
        }
        IRBuilder<> B(SI);
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          Value *P = B.CreateGEP(B.getInt8Ty(), SI->getPointerOperand(),
                                 B.getInt64(i * ElemSize));
          StoreInst *E = B.CreateStore(V[i], P);
          E->setAlignment(Align(MinAlign(SI->getAlign().value(), ElemSize)));
        }
        Dead.push_back(SI);
        continue;
      }

      if (auto *EE = dyn_cast<ExtractElementInst>(&I)) {
        unsigned Idx =
            (unsigned)cast<ConstantInt>(EE->getIndexOperand())->getZExtValue();
        Value *L = LaneOf(EE->getVectorOperand(), Idx);
        if (!L)
          return false;
        EE->replaceAllUsesWith(L);
        Dead.push_back(EE);
        continue;
      }

      if (auto *IE = dyn_cast<InsertElementInst>(&I)) {
        auto *VT = cast<FixedVectorType>(Ty);
        unsigned Idx =
            (unsigned)cast<ConstantInt>(IE->getOperand(2))->getZExtValue();
        SmallVector<Value *, 4> V;
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          if (i == Idx) {
            V.push_back(IE->getOperand(1));
            continue;
          }
          Value *L = LaneOf(IE->getOperand(0), i);
          if (!L)
            return false;
          V.push_back(L);
        }
        Lanes[IE] = std::move(V);
        Dead.push_back(IE);
        continue;
      }

      if (auto *SV = dyn_cast<ShuffleVectorInst>(&I)) {
        auto *VT = cast<FixedVectorType>(Ty);
        unsigned NumA = cast<FixedVectorType>(SV->getOperand(0)->getType())
                            ->getNumElements();
        SmallVector<Value *, 4> V;
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          int M = SV->getMaskValue(i);
          Value *L;
          if (M < 0) {
            L = PoisonValue::get(VT->getElementType());
          } else if ((unsigned)M < NumA) {
            L = LaneOf(SV->getOperand(0), (unsigned)M);
          } else {
            L = LaneOf(SV->getOperand(1), (unsigned)M - NumA);
          }
          if (!L)
            return false;
          V.push_back(L);
        }
        Lanes[SV] = std::move(V);
        Dead.push_back(SV);
        continue;
      }

      if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
        auto *VT = cast<FixedVectorType>(Ty);
        IRBuilder<> B(BO);
        SmallVector<Value *, 4> V;
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          Value *A = LaneOf(BO->getOperand(0), i);
          Value *C = LaneOf(BO->getOperand(1), i);
          if (!A || !C)
            return false;
          Value *N = B.CreateBinOp(BO->getOpcode(), A, C);
          if (auto *NBO = dyn_cast<BinaryOperator>(N))
            NBO->copyIRFlags(BO);
          V.push_back(N);
        }
        Lanes[BO] = std::move(V);
        Dead.push_back(BO);
        continue;
      }

      if (auto *UO = dyn_cast<UnaryOperator>(&I)) {
        auto *VT = cast<FixedVectorType>(Ty);
        IRBuilder<> B(UO);
        SmallVector<Value *, 4> V;
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          Value *A = LaneOf(UO->getOperand(0), i);
          if (!A)
            return false;
          Value *N = B.CreateFNeg(A);
          if (auto *NUO = dyn_cast<UnaryOperator>(N))
            NUO->copyIRFlags(UO);
          V.push_back(N);
        }
        Lanes[UO] = std::move(V);
        Dead.push_back(UO);
        continue;
      }

      if (auto *IC = dyn_cast<ICmpInst>(&I)) {
        auto *VT = cast<FixedVectorType>(Ty);
        IRBuilder<> B(IC);
        SmallVector<Value *, 4> V;
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          Value *A = LaneOf(IC->getOperand(0), i);
          Value *C = LaneOf(IC->getOperand(1), i);
          if (!A || !C)
            return false;
          V.push_back(B.CreateICmp(IC->getPredicate(), A, C));
        }
        Lanes[IC] = std::move(V);
        Dead.push_back(IC);
        continue;
      }

      if (auto *FC = dyn_cast<FCmpInst>(&I)) {
        auto *VT = cast<FixedVectorType>(Ty);
        IRBuilder<> B(FC);
        SmallVector<Value *, 4> V;
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          Value *A = LaneOf(FC->getOperand(0), i);
          Value *C = LaneOf(FC->getOperand(1), i);
          if (!A || !C)
            return false;
          Value *N = B.CreateFCmp(FC->getPredicate(), A, C);
          if (auto *NFC = dyn_cast<FCmpInst>(N))
            NFC->copyIRFlags(FC);
          V.push_back(N);
        }
        Lanes[FC] = std::move(V);
        Dead.push_back(FC);
        continue;
      }

      if (auto *SEL = dyn_cast<SelectInst>(&I)) {
        auto *VT = cast<FixedVectorType>(Ty);
        bool VecCond = SEL->getCondition()->getType()->isVectorTy();
        IRBuilder<> B(SEL);
        SmallVector<Value *, 4> V;
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          Value *Cond =
              VecCond ? LaneOf(SEL->getCondition(), i) : SEL->getCondition();
          Value *T = LaneOf(SEL->getTrueValue(), i);
          Value *Fv = LaneOf(SEL->getFalseValue(), i);
          if (!Cond || !T || !Fv)
            return false;
          SelectInst *N = SelectInst::Create(Cond, T, Fv, "", SEL->getIterator());
          N->copyIRFlags(SEL);
          V.push_back(N);
        }
        Lanes[SEL] = std::move(V);
        Dead.push_back(SEL);
        continue;
      }

      if (auto *CB = dyn_cast<CallInst>(&I)) {
        IRBuilder<> B(CB);
        // A reduction folds the lanes into one scalar, so it has no lane
        // mapping of its own: the folded value replaces the call outright.
        if (isVectorReduceCall(CB)) {
          auto *VT = cast<FixedVectorType>(CB->getArgOperand(0)->getType());
          SmallVector<Value *, 4> V;
          for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
            Value *L = LaneOf(CB->getArgOperand(0), i);
            if (!L)
              return false;
            V.push_back(L);
          }
          Value *Acc = V.front();
          for (unsigned i = 1, e = V.size(); i != e; ++i) {
            Value *N = nullptr;
            switch (CB->getIntrinsicID()) {
            case Intrinsic::vector_reduce_add:
              N = B.CreateAdd(Acc, V[i]);
              break;
            case Intrinsic::vector_reduce_mul:
              N = B.CreateMul(Acc, V[i]);
              break;
            case Intrinsic::vector_reduce_and:
              N = B.CreateAnd(Acc, V[i]);
              break;
            case Intrinsic::vector_reduce_or:
              N = B.CreateOr(Acc, V[i]);
              break;
            case Intrinsic::vector_reduce_xor:
              N = B.CreateXor(Acc, V[i]);
              break;
            case Intrinsic::vector_reduce_smax:
              N = B.CreateSelect(B.CreateICmpSGT(Acc, V[i]), Acc, V[i]);
              break;
            case Intrinsic::vector_reduce_smin:
              N = B.CreateSelect(B.CreateICmpSLT(Acc, V[i]), Acc, V[i]);
              break;
            case Intrinsic::vector_reduce_umax:
              N = B.CreateSelect(B.CreateICmpUGT(Acc, V[i]), Acc, V[i]);
              break;
            case Intrinsic::vector_reduce_umin:
              N = B.CreateSelect(B.CreateICmpULT(Acc, V[i]), Acc, V[i]);
              break;
            default:
              return false;
            }
            Acc = N;
          }
          CB->replaceAllUsesWith(Acc);
          Dead.push_back(CB);
          continue;
        }
        // Elementwise intrinsic: one call per lane, scalar arguments passed
        // through unchanged.
        if (Function *Scalar = scalarIntrinsicCallee(CB)) {
          auto *VT = cast<FixedVectorType>(Ty);
          SmallVector<Value *, 4> V;
          for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
            SmallVector<Value *, 4> Args;
            for (Value *A : CB->args()) {
              if (!A->getType()->isVectorTy()) {
                Args.push_back(A);
                continue;
              }
              Value *L = LaneOf(A, i);
              if (!L)
                return false;
              Args.push_back(L);
            }
            V.push_back(B.CreateCall(Scalar, Args));
          }
          Lanes[CB] = std::move(V);
          Dead.push_back(CB);
          continue;
        }
        return false;
      }

      if (auto *CI = dyn_cast<CastInst>(&I)) {
        auto *VT = cast<FixedVectorType>(Ty);
        IRBuilder<> B(CI);
        SmallVector<Value *, 4> V;
        for (unsigned i = 0, e = VT->getNumElements(); i != e; ++i) {
          Value *A = LaneOf(CI->getOperand(0), i);
          if (!A)
            return false;
          V.push_back(B.CreateCast(CI->getOpcode(), A, VT->getElementType()));
        }
        Lanes[CI] = std::move(V);
        Dead.push_back(CI);
        continue;
      }
    }
  }

  // Second pass: every value now has lanes, so the deferred PHI edges can be
  // resolved even when they come from a loop latch.
  for (PHINode *PN : PendingPHIs) {
    auto &LV = Lanes[PN];
    for (unsigned k = 0, e = PN->getNumIncomingValues(); k != e; ++k) {
      BasicBlock *In = PN->getIncomingBlock(k);
      Value *Inc = PN->getIncomingValue(k);
      for (unsigned i = 0, n = LV.size(); i != n; ++i) {
        Value *L = LaneOf(Inc, i);
        if (!L)
          return false;
        cast<PHINode>(LV[i])->addIncoming(L, In);
      }
    }
  }

  // Users always come after their producers in RPO, so erasing in reverse
  // order peels insertelement/shuffle chains from the top down.  A PHI is the
  // exception: a latch value feeds a header PHI, which makes the two reference
  // each other.  Dropping the incoming edges first breaks that cycle.
  DenseSet<Instruction *> DeadSet(Dead.begin(), Dead.end());
  for (Instruction *I : Dead)
    for (User *U : I->users())
      if (auto *UI = dyn_cast<Instruction>(U))
        if (!DeadSet.count(UI))
          return false;
  // Split the PHIs out *before* anything is freed.  `Dead` holds raw pointers,
  // so walking it again after the non-PHI instructions have been erased would
  // run `isa<PHINode>` on released storage: if the allocator has already
  // recycled the object the vtable is garbage and the pass segfaults.  That is
  // exactly the one-in-a-hundred crash the unseeded runs showed, since the seed
  // decides whether a function ever reaches this retry at all.
  SmallVector<PHINode *, 8> DeadPHIs;
  for (Instruction *I : Dead)
    if (auto *PN = dyn_cast<PHINode>(I))
      DeadPHIs.push_back(PN);
  for (PHINode *PN : DeadPHIs)
    PN->dropAllReferences();
  for (Instruction *I : reverse(Dead)) {
    if (isa<PHINode>(I))
      continue;
    if (!I->use_empty())
      return false;
    I->eraseFromParent();
  }
  for (PHINode *PN : reverse(DeadPHIs))
    PN->eraseFromParent();
  return true;
}


} // namespace

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

// Emits the interpreter and the wrapper for a program that translated
// successfully.  Split out so the vector-scalarisation retry can share it.
static bool finishVirtualize(Function &F, VMTranslator &T, uint64_t Seed,
                             std::string &Reason) {
  if (::getenv("OBORO_VMP_DUMP")) {
    static const char *Names[] = {
        "nop", "mov", "imm", "ptr", "load", "store", "add", "sub", "mul",
        "udiv", "sdiv", "urem", "srem", "and", "or", "xor", "shl", "lshr",
        "ashr", "add_imm", "sub_imm", "mul_imm", "and_imm", "or_imm",
        "xor_imm", "shl_imm", "lshr_imm", "ashr_imm",
        "eq", "ne", "ugt", "uge", "ult", "ule", "sgt", "sge", "slt",
        "sle", "select", "zext", "sext", "trunc", "ctpop", "ctlz", "cttz",
        "bswap", "bitrev", "fshl", "fshr", "fadd", "fsub", "fmul", "fdiv", "frem", "fneg",
        "fabs", "fsqrt", "fma", "fcmp", "fpext", "fptrunc", "fptosi",
        "fptoui", "sitofp", "uitofp", "ieq_cbr", "ine_cbr", "iugt_cbr",
        "iuge_cbr", "iult_cbr", "iule_cbr", "isgt_cbr", "isge_cbr",
        "islt_cbr", "isle_cbr", "br", "cbr", "ret", "call", "trap",
        "spill", "fill"};
    static_assert(sizeof(Names) / sizeof(Names[0]) == OP_COUNT,
                  "opcode name table must cover every opcode");
    errs() << "[dump] " << F.getName() << " key=" << T.Program.Key
           << " args=" << T.Program.ArgCount
           << " regs=" << T.Program.RegSlots
           << " spill=" << T.Program.SpillSlots
           << " frame=" << T.Program.FrameSize << "\n";
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

// Translation is read-only, so a failure costs nothing but the attempt.  Two
// fallbacks are tried, cheapest first:
//   1. frame-resident values -- a function with more cross-block values than
//      the 236-slot register file can hold is translated again with those
//      values kept in the wrapper frame;
//   2. vector scalarisation -- vector accesses left behind by SLP are split
//      and the function is retried.
// The caller gets the translator that succeeded, or the original reason.
static std::unique_ptr<VMTranslator>
translateFunction(Function &F, uint64_t Seed, unsigned Level,
                  std::string &Reason, unsigned RecursionCycle = 0) {
  auto T = std::make_unique<VMTranslator>(F, Seed, Level, Reason, false,
                                          RecursionCycle);
  if (T->run())
    return T;
  if (!StringRef(Reason).starts_with("too many SSA values"))
    return nullptr;
  std::string SpillReason;
  auto S = std::make_unique<VMTranslator>(F, Seed, Level, SpillReason, true,
                                          RecursionCycle);
  if (S->run()) {
    Reason = SpillReason;
    return S;
  }
  if (::getenv("OBORO_VMP_DEBUG"))
    errs() << "[vmp] spill retry failed for " << F.getName() << ": "
           << SpillReason << "\n";
  return nullptr;
}

bool llvm::virtualizeFunction(Function &F, const VirtualizeConfig &Cfg,
                              std::string &Reason, bool *IRChanged) {
  if (IRChanged)
    *IRChanged = false;
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

  std::unique_ptr<VMTranslator> T =
      translateFunction(F, Seed, Cfg.Level, Reason, Cfg.RecursionCycle);
  if (T) {
    bool Ok = finishVirtualize(F, *T, Seed, Reason);
    if (IRChanged)
      *IRChanged = Ok;
    return Ok;
  }

  std::string FirstReason = Reason;
  const DataLayout &DL = F.getParent()->getDataLayout();

  // Scalarisation only adds scalar values, so it cannot rescue a function that
  // was rejected because its per-call VM state is already too large.  Bail out
  // before the probe: scalarising cannot shrink the register file, so the
  // retry would be rejected for the same reason and only waste time.
  if (StringRef(FirstReason).starts_with("recursive function"))
    return false;

  // Probe the rewrite on a throw-away clone.  Splitting vector accesses
  // pessimises the function unless the retry then succeeds, and translation has
  // no side effects, so the decision is made before touching F.  The cycle
  // size comes from the driver, not from the clone: a cloned function's calls
  // still point at the original, so inspecting the clone would miss them.
  ValueToValueMapTy VMap;
  Function *Probe = CloneFunction(&F, VMap);
  Probe->setName(F.getName() + ".vmp.probe");
  bool Feasible = false;
  if (scalarizeVectors(*Probe, DL)) {
    std::string ProbeReason;
    Feasible = translateFunction(*Probe, Seed, Cfg.Level, ProbeReason,
                                 Cfg.RecursionCycle) != nullptr;
  }
  Probe->eraseFromParent();
  if (!Feasible) {
    Reason = FirstReason;
    return false;
  }

  if (!scalarizeVectors(F, DL)) {
    // The probe already succeeded on a clone, so reaching this means the
    // rewrite was rolled out on the real function and then hit a check.  The
    // partially scalarised body is still valid -- the original vector
    // instructions are only erased at the very end -- but it is not the IR the
    // pass manager last analysed, so report the change even though the
    // function stays unvirtualised.
    if (IRChanged)
      *IRChanged = true;
    Reason = FirstReason;
    return false;
  }
  // The split stays only when the retry succeeds, so the pass manager has to
  // hear about the change.
  if (IRChanged)
    *IRChanged = true;
  std::unique_ptr<VMTranslator> Retry =
      translateFunction(F, Seed, Cfg.Level, Reason, Cfg.RecursionCycle);
  if (!Retry) {
    Reason = FirstReason;
    return false;
  }
  return finishVirtualize(F, *Retry, Seed, Reason);
}
