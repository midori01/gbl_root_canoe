/* SPDX-License-Identifier: BSD-3-Clause */
#include "SuperFbBootKeys.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/Security.h>
#include <Protocol/Security2.h>
#include <BootKeyRelayImage.h>

STATIC
EFI_STATUS
EFIAPI
AllowRelayState (IN CONST EFI_SECURITY_ARCH_PROTOCOL *This,
                  IN UINT32 AuthenticationStatus,
                  IN CONST EFI_DEVICE_PATH_PROTOCOL *File)
{
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
AllowRelayImage (IN CONST EFI_SECURITY2_ARCH_PROTOCOL *This,
                  IN CONST EFI_DEVICE_PATH_PROTOCOL *DevicePath,
                  IN VOID *FileBuffer, IN UINTN FileSize,
                  IN BOOLEAN BootPolicy)
{
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
PrepareStockFastboot (VOID)
{
  EFI_STATUS                              Status;
  EFI_HANDLE                              Driver = NULL;
  EFI_LOADED_IMAGE_PROTOCOL                *LoadedImage;
  EFI_SECURITY_ARCH_PROTOCOL               *Security = NULL;
  EFI_SECURITY2_ARCH_PROTOCOL              *Security2 = NULL;
  EFI_SECURITY_FILE_AUTHENTICATION_STATE   OriginalState = NULL;
  EFI_SECURITY2_FILE_AUTHENTICATION        OriginalAuth = NULL;

  /* Authorise only this built-in image load, restoring both callbacks before
   * starting the relay. Never use SfbBypassSecurity here: its callbacks reside
   * in BDS, which will be unloaded on the return to the stock ABL. */
  if (!EFI_ERROR (gBS->LocateProtocol (&gEfiSecurityArchProtocolGuid, NULL,
                                       (VOID **)&Security)) && Security != NULL) {
    OriginalState = Security->FileAuthenticationState;
    Security->FileAuthenticationState = AllowRelayState;
  } else {
    Security = NULL;
  }
  if (!EFI_ERROR (gBS->LocateProtocol (&gEfiSecurity2ArchProtocolGuid, NULL,
                                       (VOID **)&Security2)) && Security2 != NULL) {
    OriginalAuth = Security2->FileAuthentication;
    Security2->FileAuthentication = AllowRelayImage;
  } else {
    Security2 = NULL;
  }

  Status = gBS->LoadImage (FALSE, gImageHandle, NULL,
                           (VOID *)mBootKeyRelayImage, sizeof (mBootKeyRelayImage),
                           &Driver);
  if (Security2 != NULL) {
    Security2->FileAuthentication = OriginalAuth;
  }
  if (Security != NULL) {
    Security->FileAuthenticationState = OriginalState;
  }
  if (EFI_ERROR (Status)) {
    /* SECURITY_VIOLATION is allowed to return a loaded, unstarted image. */
    if (Driver != NULL) {
      gBS->UnloadImage (Driver);
    }
    return Status;
  }

  /* UEFI_DRIVER + EFI_SUCCESS keeps the callback resident. An entry-point
   * error unloads the driver, but StartImage may fail before entering it (e.g.
   * allocation failure). Only unload if the handle is still a loaded image. */
  Status = gBS->StartImage (Driver, NULL, NULL);
  if (EFI_ERROR (Status) &&
      !EFI_ERROR (gBS->HandleProtocol (Driver, &gEfiLoadedImageProtocolGuid,
                                       (VOID **)&LoadedImage))) {
    gBS->UnloadImage (Driver);
  }
  return Status;
}

STATIC
SFB_BOOT_ACTION
ReadBootKey (IN UINT32 TimeoutMs)
{
  EFI_STATUS       Status;
  EFI_EVENT        Timer;
  EFI_EVENT        Events[2];
  EFI_INPUT_KEY    Key;
  UINTN            Index;
  SFB_BOOT_ACTION  Action = SfbBootDefault;

  if (gST->ConIn == NULL || gST->ConIn->ReadKeyStroke == NULL ||
      gST->ConIn->WaitForKey == NULL) {
    return Action;
  }

  /* Do not Reset(): a volume key held before BDS starts may already be queued,
   * and the hardware need not emit repeat events for a held key. */
  Status = gBS->CreateEvent (EVT_TIMER, TPL_CALLBACK, NULL, NULL, &Timer);
  if (EFI_ERROR (Status)) {
    return Action;
  }
  Status = gBS->SetTimer (Timer, TimerRelative, (UINT64)TimeoutMs * 10000);
  if (!EFI_ERROR (Status)) {
    /* Timer first bounds the scan even if a non-volume key repeats forever. */
    Events[0] = Timer;
    Events[1] = gST->ConIn->WaitForKey;
    while (TRUE) {
      Status = gBS->WaitForEvent (2, Events, &Index);
      if (EFI_ERROR (Status) || Index == 0) {
        break;
      }
      Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
      if (Status == EFI_NOT_READY) {
        continue;
      }
      if (EFI_ERROR (Status)) {
        break;
      }
      if (Key.ScanCode == SCAN_UP) {
        Action = SfbBootMenu;
        break;
      }
      if (Key.ScanCode == SCAN_DOWN) {
        Action = SfbBootStockFastboot;
        break;
      }
      /* Ignore power/other keys, without shortening the volume-key window. */
    }
  }
  gBS->CloseEvent (Timer);
  return Action;
}

SFB_BOOT_ACTION
SfbCheckBootKeys (IN BOOLEAN AllowUnlock, IN UINT32 TimeoutMs,
                  OUT EFI_STATUS *HandoffStatus)
{
  SFB_BOOT_ACTION Action;

  *HandoffStatus = EFI_SUCCESS;
  if (!AllowUnlock) {
    return SfbBootDefault;
  }
  Action = ReadBootKey (TimeoutMs);
  if (Action == SfbBootStockFastboot) {
    *HandoffStatus = PrepareStockFastboot ();
    if (EFI_ERROR (*HandoffStatus)) {
      return SfbBootMenu;
    }
  }
  return Action;
}
