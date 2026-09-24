/** @file
  Replay one consumed Volume Down key to the calling stock ABL.

  This must be a separately loaded UEFI_DRIVER, not a callback in BDS: the
  firmware unloads an application when it returns from StartImage. A successful
  driver remains resident, so its callback is still valid after BDS returns.
  No partition, boot reason or persistent variable is changed.

  SPDX-License-Identifier: BSD-3-Clause
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SimpleTextInEx.h>

STATIC EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL  *mInput;
STATIC EFI_INPUT_READ_KEY_EX              mReadKey;

STATIC
EFI_STATUS
EFIAPI
ReplayKey (IN EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
           OUT EFI_KEY_DATA                    *KeyData)
{
  if (This != mInput || KeyData == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  /* Restore before returning the key. Subsequent reads and the stock ABL's
   * following Reset(FALSE) use the firmware's unmodified implementation. */
  This->ReadKeyStrokeEx = mReadKey;
  mInput = NULL;
  KeyData->Key.ScanCode = SCAN_DOWN;
  KeyData->Key.UnicodeChar = 0;
  KeyData->KeyState.KeyShiftState = 0;
  KeyData->KeyState.KeyToggleState = 0;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyRelayUnload (IN EFI_HANDLE ImageHandle)
{
  /* Also safe if somebody unloads the driver before the pending key is read. */
  if (mInput != NULL) {
    if (mInput->ReadKeyStrokeEx != ReplayKey) {
      /* Another hook may still call ours. Do not leave a dangling callback. */
      return EFI_ACCESS_DENIED;
    }
    mInput->ReadKeyStrokeEx = mReadKey;
    mInput = NULL;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyRelayEntry (IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_STATUS                         Status;
  EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL   *Input;

  if (SystemTable->ConsoleInHandle == NULL || mInput != NULL) {
    return EFI_UNSUPPORTED;
  }
  Status = gBS->HandleProtocol (SystemTable->ConsoleInHandle,
                               &gEfiSimpleTextInputExProtocolGuid,
                               (VOID **)&Input);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  if (Input == NULL || Input->ReadKeyStrokeEx == NULL) {
    return EFI_UNSUPPORTED;
  }

  mReadKey = Input->ReadKeyStrokeEx;
  mInput = Input;
  Input->ReadKeyStrokeEx = ReplayKey;
  return EFI_SUCCESS;
}
