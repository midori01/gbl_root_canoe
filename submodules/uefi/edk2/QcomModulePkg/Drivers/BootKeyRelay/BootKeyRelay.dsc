# SPDX-License-Identifier: BSD-3-Clause
# Build separately, then embed the EFI driver in BDS. It must outlive BDS.
[Defines]
  PLATFORM_NAME           = BootKeyRelay
  PLATFORM_GUID           = 2D713558-DF43-4E28-9945-3CCB35F3994B
  PLATFORM_VERSION        = 1.0
  DSC_SPECIFICATION       = 0x00010005
  OUTPUT_DIRECTORY       = Build/BootKeyRelay
  SUPPORTED_ARCHITECTURES = AARCH64
  BUILD_TARGETS           = DEBUG|RELEASE
  SKUID_IDENTIFIER        = DEFAULT

[LibraryClasses]
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  BaseMemoryLibOptDxe|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf

[BuildOptions]
  *_CLANG35_AARCH64_DLINK_FLAGS = -Wl,-Ttext=0x0
  *_CLANG35_AARCH64_DLINK_FLAGS = $(CLANG_EXTRA_DLINK_FLAGS)

[Components]
  QcomModulePkg/Drivers/BootKeyRelay/BootKeyRelay.inf
