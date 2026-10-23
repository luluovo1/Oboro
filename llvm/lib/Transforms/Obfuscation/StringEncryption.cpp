#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ObfNaming.h"
#include "llvm/Transforms/Obfuscation/StringEncryption.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/GlobalStatus.h"
#include "llvm/Transforms/IPO/Attributor.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/CryptoUtils.h"
#include <map>
#include <set>
#include <iostream>
#include <algorithm>

#define DEBUG_TYPE "string-encryption"

using namespace llvm;
namespace {
struct StringEncryption : public ModulePass {
  static char ID;

  struct CSPEntry {
    CSPEntry() : ID(0), Offset(0), DecGV(nullptr), DecStatus(nullptr), IsUTF16(false), DecFunc(nullptr) {}
    unsigned ID;
    unsigned Offset;
    GlobalVariable *DecGV;
    GlobalVariable *DecStatus; // is decrypted or not
    // for 8-bit strings
    std::vector<uint8_t> Data;
    std::vector<uint8_t> EncKey;
    // for 16-bit strings (UTF-16)
    bool IsUTF16;
    std::vector<uint16_t> Data16;
    std::vector<uint16_t> EncKey16;
    Function *DecFunc;
  };

  struct CSUser {
    CSUser(Type* ETy, GlobalVariable *User, GlobalVariable *NewGV)
        : Ty(ETy), GV(User), DecGV(NewGV), DecStatus(nullptr),
          InitFunc(nullptr) {}
    Type *Ty;
    GlobalVariable *GV;
    GlobalVariable *DecGV;
    GlobalVariable *DecStatus; // is decrypted or not
    Function *InitFunc; // InitFunc will use decryted string to initialize DecGV
  };

  ObfuscationOptions *ArgsOptions;
  std::vector<CSPEntry *> ConstantStringPool;
  std::map<GlobalVariable *, CSPEntry *> CSPEntryMap;
  std::map<GlobalVariable *, CSUser *> CSUserMap;
  GlobalVariable *EncryptedStringTable = nullptr;
  std::set<GlobalVariable *> MaybeDeadGlobalVars;
  // config "cse": {"shared": true} —— 全模块共用 i8/i16 各一个解密器，
  // 长度改为运行期参数。默认按字符串各建一个：体积大但无单点入口。
  bool SharedDecrypt = false;
  Function *SharedDecI8 = nullptr;
  Function *SharedDecI16 = nullptr;

  StringEncryption(ObfuscationOptions *argsOptions) : ModulePass(ID) {
    this->ArgsOptions = argsOptions;
    initializeStringEncryptionPass(*PassRegistry::getPassRegistry());
  }

  bool doFinalization(Module &) override {
    for (CSPEntry *Entry : ConstantStringPool) {
      delete (Entry);
    }
    for (auto &I : CSUserMap) {
      CSUser *User = I.second;
      delete (User);
    }
    ConstantStringPool.clear();
    CSPEntryMap.clear();
    CSUserMap.clear();
    MaybeDeadGlobalVars.clear();
    return false;
  }

  StringRef getPassName() const override { return {"StringEncryption"}; }

  bool runOnModule(Module &M) override;
  static void collectConstantStringUser(GlobalVariable *CString, std::set<GlobalVariable *> &Users);
  static bool isValidToEncrypt(GlobalVariable *GV);
  bool processConstantStringUse(Function *F);
  void deleteUnusedGlobalVariable();
  static Function *buildDecryptFunction(Module *M, const CSPEntry *Entry);
  Function *buildSharedDecryptFunction(Module *M, bool IsUTF16);
  void emitDecryptCall(IRBuilder<> &IRB, CSPEntry *Entry, Value *OutBuf,
                       Value *Data);
  Function *buildInitFunction(Module *M, const CSUser *User);
  template <typename T>
  void getRandomBytes(std::vector<T> &Bytes, uint32_t MinSize, uint32_t MaxSize);
  void lowerGlobalConstant(Constant *CV, IRBuilder<> &IRB, Value *Ptr, Type *Ty);
  void lowerGlobalConstantStruct(ConstantStruct *CS, IRBuilder<> &IRB, Value *Ptr, Type *Ty);
  void lowerGlobalConstantArray(ConstantArray *CA, IRBuilder<> &IRB, Value *Ptr, Type *Ty);
};
} // namespace llvm

char StringEncryption::ID = 0;
bool StringEncryption::runOnModule(Module &M) {
  std::set<GlobalVariable *> ConstantStringUsers;

  // Module-wide knob from the config file ("cse": {"shared": true}).  There is
  // deliberately no command-line flag: per-string decryptors stay the default
  // and the size/single-entry tradeoff is a project-level policy decision.
  SharedDecrypt = ArgsOptions->cseOpt()->sharedDecrypt();

  // collect all c strings

  LLVMContext &Ctx = M.getContext();
  ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.isConstant() || !GV.hasInitializer() ||
      GV.hasDLLExportStorageClass() || GV.isDLLImportDependent()) {
      continue;
    }
    Constant *Init = GV.getInitializer();
    if (Init == nullptr)
      continue;
    if (ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(Init)) {
      if (CDS->isCString()) {
        CSPEntry *Entry = new CSPEntry();
        Entry->IsUTF16 = false;
        StringRef Data = CDS->getRawDataValues();
        Entry->Data.reserve(Data.size());
        for (unsigned i = 0; i < Data.size(); ++i) {
          Entry->Data.push_back(static_cast<uint8_t>(Data[i]));
        }
        Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
        Constant *ZeroInit = Constant::getNullValue(CDS->getType());
        GlobalVariable *DecGV = new GlobalVariable(M, CDS->getType(), false, GlobalValue::PrivateLinkage,
                                                   ZeroInit, obf::freshName(M, "dec" + std::to_string(Entry->ID)));
        GlobalVariable *DecStatus = new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
                                                   Zero, obf::freshName(M, "dec_status_" + std::to_string(Entry->ID)));
        DecGV->setAlignment(MaybeAlign(GV.getAlignment()));
        Entry->DecGV = DecGV;
        Entry->DecStatus = DecStatus;
        ConstantStringPool.push_back(Entry);
        CSPEntryMap[&GV] = Entry;
        collectConstantStringUser(&GV, ConstantStringUsers);
      } else {
        // treat arrays of i16 as UTF-16 constant strings
        Type *EltTy = CDS->getElementType();
        if (EltTy->isIntegerTy(16)) {
          CSPEntry *Entry = new CSPEntry();
          Entry->IsUTF16 = true;
          unsigned NumElems = CDS->getNumElements();
          Entry->Data16.reserve(NumElems);
          for (unsigned i = 0; i < NumElems; ++i) {
            // getElementAsInteger returns uint64_t, safe to cast to uint16_t
            uint64_t v = CDS->getElementAsInteger(i);
            Entry->Data16.push_back(static_cast<uint16_t>(v));
          }
          Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
          Constant *ZeroInit = Constant::getNullValue(CDS->getType());
          GlobalVariable *DecGV = new GlobalVariable(M, CDS->getType(), false, GlobalValue::PrivateLinkage,
                                                     ZeroInit, obf::freshName(M, "dec" + std::to_string(Entry->ID)));
          GlobalVariable *DecStatus = new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
                                                     Zero, obf::freshName(M, "dec_status_" + std::to_string(Entry->ID)));
          DecGV->setAlignment(MaybeAlign(GV.getAlignment()));
          Entry->DecGV = DecGV;
          Entry->DecStatus = DecStatus;
          ConstantStringPool.push_back(Entry);
          CSPEntryMap[&GV] = Entry;
          collectConstantStringUser(&GV, ConstantStringUsers);
        }
      }
    }
  }

  // encrypt those strings, build corresponding decrypt function
  for (CSPEntry *Entry: ConstantStringPool) {
    if (!Entry->IsUTF16) {
      getRandomBytes(Entry->EncKey, 16, 32);
      uint8_t LastPlainChar = 0;
      for (unsigned i = 0; i < Entry->Data.size(); ++i) {
        const uint32_t KeyIndex = i % Entry->EncKey.size();
        const uint8_t CurrentKey = Entry->EncKey[KeyIndex];
        const uint8_t CurrentPlainChar = Entry->Data[i];
        // 增加一个与位置 i 相关的扰动量，打破字符频率分析
        uint8_t val = static_cast<uint8_t>(CurrentPlainChar + i); 
        val ^= CurrentKey;
        if ((KeyIndex * CurrentKey) % 2 == 0) {
          val = ~val;
          val ^= CurrentKey;
          val = val - LastPlainChar;
        } else {
          val = -val;
          val ^= CurrentKey;
          val = val + LastPlainChar;
        }
        Entry->Data[i] = val;
        LastPlainChar = CurrentPlainChar;
      }
    } else {
      // 16-bit oriented keys for UTF-16
      getRandomBytes(Entry->EncKey16, 8, 16); // key length in 16-bit words
      uint16_t LastPlainChar = 0;
      for (unsigned i = 0; i < Entry->Data16.size(); ++i) {
        const uint32_t KeyIndex = i % Entry->EncKey16.size();
        const uint16_t CurrentKey = Entry->EncKey16[KeyIndex];
        const uint16_t CurrentPlainChar = Entry->Data16[i];
        // 同理，为 UTF-16 字符串增加 i 相关的偏移
        uint16_t val = static_cast<uint16_t>(CurrentPlainChar + i);
        val ^= CurrentKey;
        if (((KeyIndex * CurrentKey) % 2) == 0) {
          val = ~val;
          val ^= CurrentKey;
          val = static_cast<uint16_t>(val - LastPlainChar);
        } else {
          val = static_cast<uint16_t>(-static_cast<int16_t>(val));
          val ^= CurrentKey;
          val = static_cast<uint16_t>(val + LastPlainChar);
        }
        Entry->Data16[i] = val;
        LastPlainChar = CurrentPlainChar;
      }
    }
    Entry->DecFunc = SharedDecrypt ? buildSharedDecryptFunction(&M, Entry->IsUTF16)
                                   : buildDecryptFunction(&M, Entry);
  }

  // build initialization function for supported constant string users
  unsigned UserID = 0;
  for (GlobalVariable *GV: ConstantStringUsers) {
    if (isValidToEncrypt(GV)) {
      Type *EltType = GV->getValueType();
      Constant *ZeroInit = Constant::getNullValue(EltType);
      const std::string UID = std::to_string(UserID++);
      GlobalVariable *DecGV = new GlobalVariable(M, EltType, false, GlobalValue::PrivateLinkage,
                                                 ZeroInit, obf::freshName(M, "dec_user" + UID));
      DecGV->setAlignment(MaybeAlign(GV->getAlignment()));
      GlobalVariable *DecStatus = new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
          Zero, obf::freshName(M, "dec_status_user" + UID));
      CSUser *User = new CSUser(EltType, GV, DecGV);
      User->DecStatus = DecStatus;
      User->InitFunc = buildInitFunction(&M, User);
      CSUserMap[GV] = User;
    }
  }

  // emit the constant string pool
  // | junk bytes | key 1 | encrypted string 1 | junk bytes | key 2 | encrypted string 2 | ...
  std::vector<uint8_t> Data;
  std::vector<uint8_t> JunkBytes;

  JunkBytes.reserve(32);
  for (CSPEntry *Entry: ConstantStringPool) {
    JunkBytes.clear();
    getRandomBytes(JunkBytes, 16, 32);
    Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());

    // For UTF-16: ensure 2-byte alignment to avoid misaligned i16 loads
    if (Entry->IsUTF16 && (Data.size() % 2) != 0) {
      Data.push_back(0);
    }

    Entry->Offset = static_cast<unsigned>(Data.size());
    if (!Entry->IsUTF16) {
      Data.insert(Data.end(), Entry->EncKey.begin(), Entry->EncKey.end());
      Data.insert(Data.end(), Entry->Data.begin(), Entry->Data.end());
    } else {
      // for UTF-16: write keys as little-endian uint16_t bytes
      for (uint16_t w : Entry->EncKey16) {
        Data.push_back(static_cast<uint8_t>(w & 0xff));
        Data.push_back(static_cast<uint8_t>((w >> 8) & 0xff));
      }
      // append Data16 as little-endian bytes
      for (uint16_t w : Entry->Data16) {
        Data.push_back(static_cast<uint8_t>(w & 0xff));
        Data.push_back(static_cast<uint8_t>((w >> 8) & 0xff));
      }
    }
  }

  Constant *CDA = ConstantDataArray::get(M.getContext(), ArrayRef<uint8_t>(Data));
  EncryptedStringTable = new GlobalVariable(M, CDA->getType(), false, GlobalValue::PrivateLinkage,
                                            CDA, obf::freshName(M, "EncryptedStringTable"));

  // decrypt string back at every use, change the plain string use to the decrypted one
  bool Changed = false;
  for (Function &F:M) {
    if (F.isDeclaration())
      continue;
    Changed |= processConstantStringUse(&F);
  }

  for (auto &I : CSUserMap) {
    CSUser *User = I.second;
    Changed |= processConstantStringUse(User->InitFunc);
  }

  // delete unused global variables.  In shared mode DecFunc points at the
  // module-wide decryptor, which must stay alive regardless of use counts.
  deleteUnusedGlobalVariable();
  if (!SharedDecrypt) {
    for (CSPEntry *Entry: ConstantStringPool) {
      if (Entry->DecFunc->use_empty()) {
        Entry->DecFunc->eraseFromParent();
      }
    }
  }
  return Changed;
}

template <typename T>
void StringEncryption::getRandomBytes(std::vector<T> &Bytes, uint32_t MinSize, uint32_t MaxSize) {
  uint32_t N = cryptoutils->get_uint32_t();
  uint32_t Len;

  assert(MaxSize >= MinSize);

  if (MinSize == MaxSize) {
    Len = MinSize;
  } else {
    Len = MinSize + (N % (MaxSize - MinSize));
  }

  char *Buffer = new char[Len * sizeof(T)];
  cryptoutils->get_bytes(Buffer, Len * sizeof(T));
  for (uint32_t i = 0; i < Len; ++i) {
    if constexpr (std::is_same_v<T, uint8_t>) {
      Bytes.push_back(static_cast<uint8_t>(Buffer[i]));
    } else {
      uint8_t b0 = static_cast<uint8_t>(Buffer[i * 2]);
      uint8_t b1 = static_cast<uint8_t>(Buffer[i * 2 + 1]);
      // little-endian combine
      uint16_t w = static_cast<uint16_t>(b0 | (b1 << 8));
      Bytes.push_back(w);
    }
  }

  delete[] Buffer;
}

//
//static void goron_decrypt_string(uint8_t *plain_string, const uint8_t *data)
//{
//  const uint8_t *key = data;
//  uint32_t key_size = 1234;
//  uint8_t *es = (uint8_t *) &data[key_size];
//  uint32_t i;
//  uint8_t last_decrypted_char = 0;
//  for (i = 0;i < 5678;i ++) {
//    uint32_t key_index = i % key_size;
//    uint8_t current_key = key[key_index];
//    uint8_t ds;
//    if ((key_index * current_key) % 2 == 0) {
//      ds = es[i] + last_decrypted_char;
//      ds = ds ^ current_key;
//      ds = ~ds;
//    } else {
//      ds = es[i] - last_decrypted_char;
//      ds = ds ^ current_key;
//      ds = -ds;
//    }
//    ds = ds ^ current_key;
//    last_decrypted_char = ds;
//    plain_string[i] = ds;
//  }
//}

// Builds the decryption loop of DecFunc.  The data buffer layout is
// | key | ciphertext |.  KeyElemSize is the key length in elements, DataSize
// the ciphertext length in elements, StatusPtr the i32 flag that makes
// decryption idempotent.  Each of them is either a ConstantInt (one decryptor
// per string) or a function argument (one decryptor shared by every string of
// the same element width).
static void buildDecryptBody(Function *DecFunc, Value *PlainString, Value *Data,
                             Type *PlainEltTy, Value *KeyElemSize,
                             Value *DataSize, Value *StatusPtr, bool IsUTF16) {
  LLVMContext &Ctx = DecFunc->getContext();
  IRBuilder<> IRB(Ctx);

  BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", DecFunc);
  BasicBlock *LoopBody = BasicBlock::Create(Ctx, "LoopBody", DecFunc);
  BasicBlock *LoopBr0 = BasicBlock::Create(Ctx, "LoopBr0", DecFunc);
  BasicBlock *LoopBr1 = BasicBlock::Create(Ctx, "LoopBr1", DecFunc);
  BasicBlock *LoopEnd = BasicBlock::Create(Ctx, "LoopEnd", DecFunc);
  BasicBlock *UpdateDecStatus = BasicBlock::Create(Ctx, "UpdateDecStatus", DecFunc);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", DecFunc);

  IRB.SetInsertPoint(Enter);
  // The table stores the key as raw bytes right before the ciphertext, so the
  // GEP that skips the key needs the length in bytes, not in elements.  With
  // constant operands the multiply folds away.
  Value *KeySizeInBytes = KeyElemSize;
  if (IsUTF16)
    KeySizeInBytes = IRB.CreateMul(KeyElemSize, IRB.getInt32(2));

  Value *EncPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, KeySizeInBytes);
  Value *DecStatus = IRB.CreateLoad(IRB.getInt32Ty(), StatusPtr);
  Value *IsDecrypted = IRB.CreateICmpEQ(DecStatus, IRB.getInt32(1));
  IRB.CreateCondBr(IsDecrypted, Exit, LoopBody);

  IRB.SetInsertPoint(LoopBody);
  PHINode *LoopCounter = IRB.CreatePHI(IRB.getInt32Ty(), 2);
  LoopCounter->addIncoming(IRB.getInt32(0), Enter);

  PHINode *LastDecrypted = IRB.CreatePHI(PlainEltTy, 2);
  // incoming last decrypted initial is 0
  LastDecrypted->addIncoming(Constant::getNullValue(PlainEltTy), Enter);

  // Compute KeyIdx = LoopCounter % KeyElemSize
  Value *KeyIdx = IRB.CreateURem(LoopCounter, KeyElemSize);

  // Load KeyChar: for bytes load i8, for words load i16 (we'll bitcast data to the appropriate pointer)
  Value *KeyChar = nullptr;
  if (!IsUTF16) {
    Value *KeyCharPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, KeyIdx);
    KeyChar = IRB.CreateLoad(IRB.getInt8Ty(), KeyCharPtr);
  } else {
    // bitcast data to i16* and index by KeyIdx
    Value *KeyBase = IRB.CreateBitCast(Data, PointerType::getUnqual(Type::getInt16Ty(Ctx)));
    Value *KeyCharPtr = IRB.CreateInBoundsGEP(Type::getInt16Ty(Ctx), KeyBase, KeyIdx);
    KeyChar = IRB.CreateLoad(Type::getInt16Ty(Ctx), KeyCharPtr);
  }

  // Load EncChar (encrypted stream element)
  Value *EncChar = nullptr;
  if (!IsUTF16) {
    Value *EncCharPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncPtr, LoopCounter);
    EncChar = IRB.CreateLoad(IRB.getInt8Ty(), EncCharPtr, true);
  } else {
    // EncPtr is i8*, we need to load i16 at position LoopCounter * 2
    // Compute byte offset = LoopCounter * 2
    Value *Two = IRB.getInt32(2);
    Value *IdxBytes = IRB.CreateMul(LoopCounter, Two);
    Value *EncCharBytePtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncPtr, IdxBytes);
    // bitcast pointer to i16* then load
    Value *EncChar16Ptr = IRB.CreateBitCast(EncCharBytePtr, PointerType::getUnqual(Type::getInt16Ty(Ctx)));
    EncChar = IRB.CreateLoad(Type::getInt16Ty(Ctx), EncChar16Ptr, true);
  }

  //====================Initialized=========================
  // Create branch condition: (KeyIdx * KeyChar) % 2 == 0
  // Need to ensure operands are i32 for multiplication and remainder
  Value *KeyIdxZext = IRB.CreateZExt(KeyIdx, IRB.getInt32Ty());
  Value *KeyCharZext = IRB.CreateZExt(KeyChar, IRB.getInt32Ty());
  Value *Mul = IRB.CreateMul(KeyIdxZext, KeyCharZext);
  Value *BrKey = IRB.CreateAnd(Mul, IRB.getInt32(1));
  Value *BrCond = IRB.CreateICmpEQ(BrKey, IRB.getInt32(0));
  IRB.CreateCondBr(BrCond, LoopBr0, LoopBr1);

  // Loop0 Start - %2 == 0;
  IRB.SetInsertPoint(LoopBr0);
  Value *Tmp0 = IRB.CreateAdd(EncChar, LastDecrypted);
  Tmp0 = IRB.CreateXor(Tmp0, KeyChar);
  Tmp0 = IRB.CreateNot(Tmp0);
  Value *DecChar0 = Tmp0;
  IRB.CreateBr(LoopEnd);

  // Loop1 Start - %2 == 1;
  IRB.SetInsertPoint(LoopBr1);
  Value *Tmp1 = IRB.CreateSub(EncChar, LastDecrypted);
  Tmp1 = IRB.CreateXor(Tmp1, KeyChar);
  Tmp1 = IRB.CreateNeg(Tmp1);
  Value *DecChar1 = Tmp1;
  IRB.CreateBr(LoopEnd);

  // LoopEnd and finally decrypt current char
  IRB.SetInsertPoint(LoopEnd);
  PHINode *BrDecChar = IRB.CreatePHI(PlainEltTy, 2);
  BrDecChar->addIncoming(DecChar0, LoopBr0);
  BrDecChar->addIncoming(DecChar1, LoopBr1);
  // 执行核心外壳反演：(解密中间值 ^ Key) - i
  Value *Val_AfterXor = IRB.CreateXor(BrDecChar, KeyChar);
  Value *IdxTrunc = IRB.CreateTrunc(LoopCounter, PlainEltTy);
  Value *DecChar = IRB.CreateSub(Val_AfterXor, IdxTrunc);

  //Store
  LastDecrypted->addIncoming(DecChar, LoopEnd);
  Value *DecCharPtr = IRB.CreateInBoundsGEP(PlainEltTy,
      PlainString, LoopCounter);
  IRB.CreateStore(DecChar, DecCharPtr);

  Value *NewCounter = IRB.CreateAdd(LoopCounter, IRB.getInt32(1), "", true, true);
  LoopCounter->addIncoming(NewCounter, LoopEnd);

  Value *Cond = IRB.CreateICmpEQ(NewCounter, DataSize);
  IRB.CreateCondBr(Cond, UpdateDecStatus, LoopBody);

  IRB.SetInsertPoint(UpdateDecStatus);
  IRB.CreateStore(IRB.getInt32(1), StatusPtr);
  IRB.CreateBr(Exit);

  IRB.SetInsertPoint(Exit);
  IRB.CreateRetVoid();
}

// One decryptor per string, with every length baked in as a constant.
Function *StringEncryption::buildDecryptFunction(Module *M, const StringEncryption::CSPEntry *Entry) {
  LLVMContext &Ctx = M->getContext();

  // Decide plain element type and set up function signature accordingly
  Type *PlainEltTy = Entry->IsUTF16 ? Type::getInt16Ty(Ctx) : Type::getInt8Ty(Ctx);
  PointerType *PlainPtrTy = PointerType::getUnqual(PlainEltTy);
  PointerType *DataPtrTy = PointerType::getUnqual(Type::getInt8Ty(Ctx)); // data buffer is byte array

  FunctionType *FuncTy = FunctionType::get(
      Type::getVoidTy(Ctx),
      {PlainPtrTy, DataPtrTy},
      false);
  Function *DecFunc =
      Function::Create(FuncTy, GlobalValue::PrivateLinkage, obf::freshName(*M, "goron_decrypt_string_" + std::to_string(Entry->ID)), M);
  // Keep one decryptor per string instead of inlining the loop into every
  // use site: without NoInline, -O2 duplicates the whole chain per block and
  // the binary grows far beyond the shared-decryptor design.
  DecFunc->addFnAttr(Attribute::NoInline);
  DecFunc->addFnAttr(Attribute::OptimizeForSize);

  auto ArgIt = DecFunc->arg_begin();
  Argument *PlainString = ArgIt; // output
  ++ArgIt;
  Argument *Data = ArgIt;       // input

  AttrBuilder NoCaptureAttrBuilder{Ctx};
  NoCaptureAttrBuilder.addCapturesAttr(llvm::CaptureInfo(llvm::CaptureComponents::None));

  PlainString->setName("plain_string");
  PlainString->addAttrs(NoCaptureAttrBuilder);
  Data->setName("data");
  Data->addAttrs(NoCaptureAttrBuilder);

  const uint32_t KeyElems = Entry->IsUTF16 ? static_cast<uint32_t>(Entry->EncKey16.size())
                                           : static_cast<uint32_t>(Entry->EncKey.size());
  const uint32_t DataSize = Entry->IsUTF16 ? static_cast<uint32_t>(Entry->Data16.size())
                                           : static_cast<uint32_t>(Entry->Data.size());

  buildDecryptBody(DecFunc, PlainString, Data, PlainEltTy,
                   ConstantInt::get(Type::getInt32Ty(Ctx), KeyElems),
                   ConstantInt::get(Type::getInt32Ty(Ctx), DataSize),
                   Entry->DecStatus, Entry->IsUTF16);
  return DecFunc;
}

// One decryptor per element width for the whole module; key length and data
// length come in as arguments.  Config: "cse": {"shared": true}.
Function *StringEncryption::buildSharedDecryptFunction(Module *M, bool IsUTF16) {
  Function *&Slot = IsUTF16 ? SharedDecI16 : SharedDecI8;
  if (Slot)
    return Slot;

  LLVMContext &Ctx = M->getContext();
  Type *PlainEltTy = IsUTF16 ? Type::getInt16Ty(Ctx) : Type::getInt8Ty(Ctx);
  PointerType *PlainPtrTy = PointerType::getUnqual(PlainEltTy);
  PointerType *DataPtrTy = PointerType::getUnqual(Type::getInt8Ty(Ctx));
  Type *I32Ty = Type::getInt32Ty(Ctx);

  // void (ptr out, ptr data, i32 key_elems, i32 data_size, ptr status)
  FunctionType *FuncTy = FunctionType::get(
      Type::getVoidTy(Ctx),
      {PlainPtrTy, DataPtrTy, I32Ty, I32Ty, PointerType::getUnqual(Ctx)},
      false);
  Function *DecFunc = Function::Create(
      FuncTy, GlobalValue::PrivateLinkage,
      obf::freshName(*M, IsUTF16 ? "dec_w" : "dec_b"), M);
  DecFunc->addFnAttr(Attribute::NoInline);
  DecFunc->addFnAttr(Attribute::OptimizeForSize);

  auto ArgIt = DecFunc->arg_begin();
  Argument *PlainString = ArgIt++;
  Argument *Data = ArgIt++;
  Argument *KeyElems = ArgIt++;
  Argument *DataSize = ArgIt++;
  Argument *Status = ArgIt;

  AttrBuilder NoCaptureAttrBuilder{Ctx};
  NoCaptureAttrBuilder.addCapturesAttr(llvm::CaptureInfo(llvm::CaptureComponents::None));
  PlainString->setName("plain_string");
  PlainString->addAttrs(NoCaptureAttrBuilder);
  Data->setName("data");
  Data->addAttrs(NoCaptureAttrBuilder);
  Status->setName("status");
  Status->addAttrs(NoCaptureAttrBuilder);

  buildDecryptBody(DecFunc, PlainString, Data, PlainEltTy, KeyElems, DataSize,
                   Status, IsUTF16);
  Slot = DecFunc;
  return DecFunc;
}

void StringEncryption::emitDecryptCall(IRBuilder<> &IRB, CSPEntry *Entry,
                                       Value *OutBuf, Value *Data) {
  CallInst *CI;
  if (SharedDecrypt) {
    Function *DecFunc = Entry->IsUTF16 ? SharedDecI16 : SharedDecI8;
    const uint32_t KeyElems = Entry->IsUTF16
                                  ? static_cast<uint32_t>(Entry->EncKey16.size())
                                  : static_cast<uint32_t>(Entry->EncKey.size());
    const uint32_t DataSize = Entry->IsUTF16
                                  ? static_cast<uint32_t>(Entry->Data16.size())
                                  : static_cast<uint32_t>(Entry->Data.size());
    CI = IRB.CreateCall(DecFunc, {OutBuf, Data, IRB.getInt32(KeyElems),
                                  IRB.getInt32(DataSize), Entry->DecStatus});
  } else {
    CI = IRB.CreateCall(Entry->DecFunc, {OutBuf, Data});
  }
  fixEH(CI);
}

Function *StringEncryption::buildInitFunction(Module *M, const StringEncryption::CSUser *User) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> IRB(Ctx);
  FunctionType *FuncTy = FunctionType::get(Type::getVoidTy(Ctx), {User->DecGV->getType()}, false);
  Function *InitFunc =
      Function::Create(FuncTy, GlobalValue::PrivateLinkage, obf::freshName(*M, ("__global_variable_initializer_" + User->GV->getName()).str()), M);

  auto ArgIt = InitFunc->arg_begin();
  Argument *thiz = ArgIt;


  AttrBuilder NoCaptureAttrBuilder{Ctx};
  NoCaptureAttrBuilder.addCapturesAttr(llvm::CaptureInfo(llvm::CaptureComponents::None));
  thiz->setName("this");
  thiz->addAttrs(NoCaptureAttrBuilder);

  // convert constant initializer into a series of instructions
  BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", InitFunc);
  BasicBlock *InitBlock = BasicBlock::Create(Ctx, "InitBlock", InitFunc);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", InitFunc);

  IRB.SetInsertPoint(Enter);
  Value *DecStatus = IRB.CreateLoad(
      User->DecStatus->getValueType(), User->DecStatus);
  Value *IsDecrypted = IRB.CreateICmpEQ(DecStatus, IRB.getInt32(1));
  IRB.CreateCondBr(IsDecrypted, Exit, InitBlock);

  IRB.SetInsertPoint(InitBlock);
  Constant *Init = User->GV->getInitializer();
  lowerGlobalConstant(Init, IRB, User->DecGV, User->Ty);
  IRB.CreateStore(IRB.getInt32(1), User->DecStatus);
  IRB.CreateBr(Exit);

  IRB.SetInsertPoint(Exit);
  IRB.CreateRetVoid();
  return InitFunc;
}

void StringEncryption::lowerGlobalConstant(Constant *CV, IRBuilder<> &IRB, Value *Ptr, Type *Ty) {
  if (isa<ConstantAggregateZero>(CV)) {
    IRB.CreateStore(CV, Ptr);
    return;
  }

  if (ConstantArray *CA = dyn_cast<ConstantArray>(CV)) {
    lowerGlobalConstantArray(CA, IRB, Ptr, Ty);
  } else if (ConstantStruct *CS = dyn_cast<ConstantStruct>(CV)) {
    lowerGlobalConstantStruct(CS, IRB, Ptr, Ty);
  } else {
    IRB.CreateStore(CV, Ptr);
  }
}

void StringEncryption::lowerGlobalConstantArray(ConstantArray *CA, IRBuilder<> &IRB, Value *Ptr, Type *Ty) {
  for (unsigned i = 0, e = CA->getNumOperands(); i != e; ++i) {
    Constant *CV = CA->getOperand(i);
    Value *GEP = IRB.CreateGEP(Ty,
                      Ptr, {IRB.getInt32(0), IRB.getInt32(i)});
    lowerGlobalConstant(CV, IRB, GEP, CV->getType());
  }
}

void StringEncryption::lowerGlobalConstantStruct(ConstantStruct *CS, IRBuilder<> &IRB, Value *Ptr, Type *Ty) {
  for (unsigned i = 0, e = CS->getNumOperands(); i != e; ++i) {
    Constant* CV = CS->getOperand(i);
    Value *GEP = IRB.CreateGEP(Ty,
                      Ptr, {IRB.getInt32(0), IRB.getInt32(i)});
    lowerGlobalConstant(CV, IRB, GEP, CV->getType());
  }
}

bool StringEncryption::processConstantStringUse(Function *F) {
  auto opt = ArgsOptions->toObfuscate(ArgsOptions->cseOpt(), F);
  if (!opt.isEnabled()) {
    return false;
  }
  LLVMContext &Ctx = F->getContext();
  LowerConstantExpr(*F);
  SmallPtrSet<GlobalVariable *, 16> DecryptedGV; // if GV has multiple use in a block, decrypt only at the first use
  bool Changed = false;
  for (BasicBlock &BB : *F) {
    DecryptedGV.clear();
    for (Instruction &Inst: BB) {
      if (PHINode *PHI = dyn_cast<PHINode>(&Inst)) {
        for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(PHI->getIncomingValue(i))) {
            auto Iter1 = CSPEntryMap.find(GV);
            auto Iter2 = CSUserMap.find(GV);
            if (Iter2 != CSUserMap.end()) { // GV is a constant string user
              CSUser *User = Iter2->second;
              if (DecryptedGV.count(GV) > 0) {
                Inst.replaceUsesOfWith(GV, User->DecGV);
              } else {
                Instruction *InsertPoint = PHI->getIncomingBlock(i)->getTerminator();
                IRBuilder<> IRB(InsertPoint);
                fixEH(IRB.CreateCall(User->InitFunc, {User->DecGV}));
                Inst.replaceUsesOfWith(GV, User->DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
              }
              Changed = true;
            } else if (Iter1 != CSPEntryMap.end()) { // GV is a constant string
              CSPEntry *Entry = Iter1->second;
              if (DecryptedGV.count(GV) > 0) {
                Inst.replaceUsesOfWith(GV, Entry->DecGV);
              } else {
                Instruction *InsertPoint = PHI->getIncomingBlock(i)->getTerminator();
                IRBuilder<> IRB(InsertPoint);

                Value *OutBuf = IRB.CreateBitCast(Entry->DecGV,
                                                  PointerType::getUnqual(Ctx));
                Value *Data = IRB.CreateInBoundsGEP(
                    EncryptedStringTable->getValueType(),
                    EncryptedStringTable,
                    {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});
                emitDecryptCall(IRB, Entry, OutBuf, Data);

                Inst.replaceUsesOfWith(GV, Entry->DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
              }
              Changed = true;
            }
          }
        }
      } else {
        for (User::op_iterator op = Inst.op_begin(); op != Inst.op_end(); ++op) {
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(*op)) {
            auto Iter1 = CSPEntryMap.find(GV);
            auto Iter2 = CSUserMap.find(GV);
            if (Iter2 != CSUserMap.end()) {
              CSUser *User = Iter2->second;
              if (DecryptedGV.count(GV) > 0) {
                Inst.replaceUsesOfWith(GV, User->DecGV);
              } else {
                
                IRBuilder<> IRB(Inst.isEHPad() ? &*Inst.getParent()->getPrevNode()->getFirstInsertionPt() : &Inst);
                fixEH(IRB.CreateCall(User->InitFunc, {User->DecGV}));
                Inst.replaceUsesOfWith(GV, User->DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
              }
              Changed = true;
            } else if (Iter1 != CSPEntryMap.end()) {
              CSPEntry *Entry = Iter1->second;
              if (DecryptedGV.count(GV) > 0) {
                Inst.replaceUsesOfWith(GV, Entry->DecGV);
              } else {
                IRBuilder<> IRB(Inst.isEHPad() ? &*Inst.getParent()->getPrevNode()->getFirstInsertionPt() : &Inst);
                
                Value *OutBuf = IRB.CreateBitCast(Entry->DecGV,
                                                  PointerType::getUnqual(Ctx));
                Value *Data = IRB.CreateInBoundsGEP(
                    EncryptedStringTable->getValueType(),
                    EncryptedStringTable,
                    {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});
                emitDecryptCall(IRB, Entry, OutBuf, Data);

                Inst.replaceUsesOfWith(GV, Entry->DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
              }
              Changed = true;
            }
          }
        }
      }
    }
  }
  return Changed;
}

void StringEncryption::collectConstantStringUser(GlobalVariable *CString, std::set<GlobalVariable *> &Users) {
  SmallPtrSet<Value *, 16> Visited;
  SmallVector<Value *, 16> ToVisit;

  ToVisit.push_back(CString);
  while (!ToVisit.empty()) {
    Value *V = ToVisit.pop_back_val();
    if (Visited.count(V) > 0)
      continue;
    Visited.insert(V);
    for (Value *User:V->users()) {
      if (auto *GV = dyn_cast<GlobalVariable>(User)) {
        Users.insert(GV);
      } else {
        ToVisit.push_back(User);
      }
    }
  }
}

bool StringEncryption::isValidToEncrypt(GlobalVariable *GV) {
  if(GV->isConstant() && GV->hasInitializer()) {
    return GV->getInitializer() != nullptr;
  } else {
    return false;
  }
}

void StringEncryption::deleteUnusedGlobalVariable() {
  bool Changed = true;
  while (Changed) {
    Changed = false;
    for (auto Iter = MaybeDeadGlobalVars.begin(); Iter != MaybeDeadGlobalVars.end();) {
      GlobalVariable *GV = *Iter;
      if (!GV->hasLocalLinkage()) {
        ++Iter;
        continue;
      }

      GV->removeDeadConstantUsers();
      if (GV->use_empty()) {
        if (GV->hasInitializer()) {
          Constant *Init = GV->getInitializer();
          GV->setInitializer(nullptr);
          if (isSafeToDestroyConstant(Init))
            Init->destroyConstant();
        }
        Iter = MaybeDeadGlobalVars.erase(Iter);
        GV->eraseFromParent();
        Changed = true;
      } else {
        ++Iter;
      }
    }
  }
}

ModulePass *llvm::createStringEncryptionPass(ObfuscationOptions *argsOptions) {
  return new StringEncryption(argsOptions);
}

INITIALIZE_PASS(StringEncryption, "string-encryption", "Enable IR String Encryption", false, false)
