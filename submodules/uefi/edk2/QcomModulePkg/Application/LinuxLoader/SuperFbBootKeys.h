/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef SUPER_FB_BOOT_KEYS_H
#define SUPER_FB_BOOT_KEYS_H

#include <Uefi.h>

typedef enum {
  SfbBootDefault,
  SfbBootMenu,
  SfbBootStockFastboot
} SFB_BOOT_ACTION;

/* OEM off performs no input, image loading or waiting. StockFastboot means
 * the relay is armed: the caller must return to ABL without starting FAT/USB
 * or launching any other EFI image. A failed handoff requests the menu. */
SFB_BOOT_ACTION
SfbCheckBootKeys (IN BOOLEAN AllowUnlock, IN UINT32 TimeoutMs,
                  OUT EFI_STATUS *HandoffStatus);

#endif
