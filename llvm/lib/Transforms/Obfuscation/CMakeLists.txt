add_llvm_library(LLVMObfuscation
  BogusControlFlow.cpp
  CryptoUtils.cpp
  Utils.cpp
  ObfuscationPassManager.cpp
  ObfuscationOptions.cpp
  IndirectBranch.cpp
  IndirectCall.cpp
  IndirectGlobalVariable.cpp
  Flattening.cpp
  StringEncryption.cpp
  LegacyLowerSwitch.cpp
  ConstantIntEncryption.cpp
  ConstantFPEncryption.cpp
  MicrosoftRTTIEraser.cpp
  
  ADDITIONAL_HEADER_DIRS
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms/Obfuscation
  
  DEPENDS
  LLVMLinker

  LINK_COMPONENTS
  Demangle
  )

add_dependencies(LLVMObfuscation intrinsics_gen LLVMLinker)

# 本目录源码含中文注释，文件为 UTF-8 无 BOM。MSVC 默认按系统代码页
# （中文 Windows 为 GBK）解析源码，会把注释里的多字节序列误读成语法
# 字符（典型症状：注释行被吞、C2059/C2143/C2447 大量假错误）。
# 显式指定 UTF-8 源码字符集；clang-cl 同样接受该选项。
if(MSVC)
  target_compile_options(LLVMObfuscation PRIVATE /utf-8)
endif()
