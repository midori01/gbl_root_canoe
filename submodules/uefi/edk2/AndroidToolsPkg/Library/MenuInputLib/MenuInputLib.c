/* SPDX-License-Identifier: BSD-3-Clause */
#include <Library/MenuInputLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SimpleTextIn.h>

#define REPEAT_DELAY_MS      450
#define REPEAT_INTERVAL_MS   150
#define QUIET_MS             200
#define POLL_US              10000
#define DRAIN_LIMIT          64

STATIC MENU_INPUT_KEY mDirection;
STATIC MENU_INPUT_KEY mLastKey;
STATIC UINT64         mPressStart;
STATIC UINT64         mLastMove;
STATIC BOOLEAN        mSelectBlocked;
STATIC UINT64         mLastSelect;
STATIC BOOLEAN        mQuiet;
STATIC UINT64         mQuietStart;
STATIC BOOLEAN        mSelectQuiet;
STATIC UINT64         mSelectQuietStart;
STATIC BOOLEAN        mDiscardUntilQuiet;
STATIC BOOLEAN        mDiscardBurst;
STATIC MENU_INPUT_KEY mPending;

STATIC
UINT64
ElapsedMs (IN UINT64 Now, IN UINT64 Start)
{
  /* ARM TimerLib uses an increasing counter; unsigned subtraction also handles
   * wrap. Convert a delta, not absolute uptime, to avoid conversion overflow. */
  return GetTimeInNanoSecond (Now - Start) / 1000000;
}

STATIC
MENU_INPUT_KEY
DecodeKey (IN CONST EFI_INPUT_KEY *Key)
{
  if (Key->ScanCode == SCAN_UP) {
    return MenuInputUp;
  }
  if (Key->ScanCode == SCAN_DOWN) {
    return MenuInputDown;
  }
  /* Keep the existing handset power-key mapping, including vendor scan codes. */
  return MenuInputSelect;
}

STATIC
VOID
InputActivity (VOID)
{
  mQuiet = FALSE;
  mSelectQuiet = FALSE;
}

STATIC
VOID
ObserveQuiet (IN UINT64 Now)
{
  if (!mQuiet) {
    mQuiet = TRUE;
    mQuietStart = Now;
  }
  if (ElapsedMs (Now, mQuietStart) >= QUIET_MS) {
    mDirection = MenuInputNone;
    mDiscardUntilQuiet = FALSE;
  }

  /* Do not count the initial hardware repeat delay as a released power key.
   * Require 200 ms of observed silence AFTER the 450 ms guard. SimpleTextIn
   * has no key-up signal, so this is deliberately a conservative heuristic,
   * not a claim that we can determine the physical key state. */
  if (mSelectBlocked && ElapsedMs (Now, mLastSelect) >= REPEAT_DELAY_MS) {
    if (!mSelectQuiet) {
      mSelectQuiet = TRUE;
      mSelectQuietStart = Now;
    }
    if (ElapsedMs (Now, mSelectQuietStart) >= QUIET_MS) {
      mSelectBlocked = FALSE;
    }
  }
}

STATIC
VOID
DrainDuplicates (IN MENU_INPUT_KEY Accepted)
{
  EFI_INPUT_KEY Key;
  EFI_STATUS    Status;
  UINTN         Count;
  MENU_INPUT_KEY Next;

  /* Drain before returning to a potentially slow redraw: otherwise queued
   * copies of a short press can look like a long hold after rendering. Retain
   * the first different key, so a quick direction change is not discarded. */
  for (Count = 0; Count < DRAIN_LIMIT; ++Count) {
    Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
    if (EFI_ERROR (Status)) {
      return;
    }
    Next = DecodeKey (&Key);
    if (Next != Accepted) {
      mPending = Next;
      return;
    }
  }
  /* Bound a misbehaving/always-ready driver. Discard the remaining burst in
   * later polls, rather than turning the backlog into new menu actions. */
  mDiscardBurst = TRUE;
}

VOID
MenuInputFlush (VOID)
{
  mPending = MenuInputNone;
  mDirection = MenuInputNone;
  mLastKey = MenuInputNone;
  mDiscardBurst = FALSE;
  mDiscardUntilQuiet = TRUE;
  mSelectBlocked = TRUE;
  /* Retain the last accepted Select's guard across a page boundary. An entry
   * delay already spent in the caller need not be imposed a second time. */
  InputActivity ();
  if (gST->ConIn != NULL && gST->ConIn->Reset != NULL) {
    gST->ConIn->Reset (gST->ConIn, FALSE);
  }
}

MENU_INPUT_KEY
MenuInputWaitForKey (IN UINT32 TimeoutMs)
{
  return MenuInputWaitForKeyWithIdle (TimeoutMs, NULL);
}

MENU_INPUT_KEY
MenuInputWaitForKeyWithIdle (IN UINT32 TimeoutMs,
                           IN MENU_INPUT_IDLE_CALLBACK Idle OPTIONAL)
{
  UINT64         Start;
  UINT64         Now;
  EFI_INPUT_KEY  Raw;
  EFI_STATUS     Status;
  MENU_INPUT_KEY Key;
  BOOLEAN        Accept;
  BOOLEAN        FirstPoll = TRUE;

  if (gST->ConIn == NULL || gST->ConIn->ReadKeyStroke == NULL) {
    return MenuInputNone;
  }
  Start = GetPerformanceCounter ();
  /* Time spent drawing/executing a child is NOT evidence of key release. */
  InputActivity ();

  while (TRUE) {
    Now = GetPerformanceCounter ();
    if (TimeoutMs != 0 && ElapsedMs (Now, Start) >= TimeoutMs) {
      return MenuInputNone;
    }
    if (mPending != MenuInputNone) {
      Key = mPending;
      mPending = MenuInputNone;
      Status = EFI_SUCCESS;
    } else {
      Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Raw);
      Key = EFI_ERROR (Status) ? MenuInputNone : DecodeKey (&Raw);
    }
    if (Status == EFI_NOT_READY) {
      mDiscardBurst = FALSE;
      ObserveQuiet (Now);
    } else if (EFI_ERROR (Status)) {
      return MenuInputNone;
    } else {
      InputActivity ();
      Accept = FALSE;
      if (FirstPoll && Key == mLastKey &&
          (Key == MenuInputUp || Key == MenuInputDown)) {
        /* Same-key events already queued when a redraw ends may have arrived
         * just AFTER our previous drain. Discard that backlog and require a
         * fresh sample during this wait before treating it as a held key. */
        DrainDuplicates (Key);
      } else if (!mDiscardUntilQuiet && !mDiscardBurst) {
        if (Key == MenuInputSelect) {
          if (!mSelectBlocked) {
            mSelectBlocked = TRUE;
            mLastSelect = Now;
            mDirection = MenuInputNone;
            Accept = TRUE;
          }
        } else if (Key != mDirection) {
          mDirection = Key;
          mPressStart = Now;
          mLastMove = Now;
          Accept = TRUE;
        } else if (ElapsedMs (Now, mPressStart) >= REPEAT_DELAY_MS &&
                   ElapsedMs (Now, mLastMove) >= REPEAT_INTERVAL_MS) {
          mLastMove = Now;
          Accept = TRUE;
        }
      }
      if (Accept) {
        mLastKey = Key;
        DrainDuplicates (Key);
        return Key;
      }
    }
    FirstPoll = FALSE;
    if (Idle != NULL) {
      UINT64 IdleStart = GetPerformanceCounter ();
      UINT64 IdleTicks;

      Idle (ElapsedMs (IdleStart, Start));
      IdleTicks = GetPerformanceCounter () - IdleStart;
      /* Drawing can be slow. Only polled silence, not time inside a frame,
       * may release a navigation/confirmation guard. Preserve accumulated
       * silence across frames rather than resetting it on each animation. */
      if (mQuiet) {
        mQuietStart += IdleTicks;
      }
      if (mSelectQuiet) {
        mSelectQuietStart += IdleTicks;
      }
    }
    /* Poll only inside interactive waits. No timer callbacks survive a return
     * or image unload; unlike a fixed post-key Stall this also drains repeats
     * while waiting and does not delay the initial accepted event. */
    Status = gBS->Stall (POLL_US);
    if (EFI_ERROR (Status)) {
      return MenuInputNone;
    }
  }
}
