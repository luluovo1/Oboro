#ifndef __UTILS_OBF__
#define __UTILS_OBF__

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/Local.h" // For DemoteRegToStack and DemotePHIToStack

#include <unordered_map>
#include <set>
#include <vector>

namespace llvm {
  class CryptoUtils;
}

using namespace llvm;
struct CreatePageTableArgs {
  unsigned CountLoop;
  std::string GVNamePrefix;
  CryptoUtils* RandomEngine;
  Module* M;
  std::vector<Constant *> *Objects;
  std::unordered_map<Constant *, unsigned> *IndexMap;
  std::unordered_map<Constant *, uint64_t> *ObjectKeys;
  std::vector<GlobalVariable *> *OutPageTable;
  uint64_t PtrEncKey = 0;
  // AArch64 PAC: when enabled, createPageTable also emits a writable table
  // of signed pointers, filled by a module constructor, plus the constructor
  // itself.  PtrAuthKey is 0 (IA, code) or 2 (DA, data).
  bool EnablePtrAuth = false;
  int PtrAuthKey = -1;
  uint64_t PtrAuthDisc = 0;
  GlobalVariable **OutSignedObjects = nullptr;
};


struct BuildDecryptArgs {
  unsigned FuncLoopCount;
  unsigned NextIndex;
  Value *NextIndexValue;
  Function *Fn;
  Instruction *InsertBefore;
  Type *LoadTy;
  std::vector<GlobalVariable *> *ModulePageTable;
  std::vector<GlobalVariable *> *FuncPageTable;
  uint64_t ModuleKey;
  uint64_t FuncKey;
  uint64_t PtrEncKey = 0;
  // Signed counterpart of the objects table (nullptr = no PAC).
  GlobalVariable *SignedObjects = nullptr;
  int PtrAuthKey = -1;
  uint64_t PtrAuthDisc = 0;
};

IntegerType *getPageTableIntTy(Module &M);
bool hasPtrAuth(const Function &F);
bool valueEscapes(Instruction *Inst);
void fixStack(Function *f);
CallBase* fixEH(CallBase* CB);
void LowerConstantExpr(Function &F);
bool expandConstantExpr(Function &F);
void createPageTable(const CreatePageTableArgs& args);
void enhancedPageTable(const CreatePageTableArgs& args, std::unordered_map<Constant *, unsigned> *FuncIndexMap);
Value * buildPageTableDecryptIR(const BuildDecryptArgs& args);
Value * encryptConstant(Constant *plainConstant, Instruction *insertBefore, CryptoUtils *randomEngine, unsigned level);
#endif
