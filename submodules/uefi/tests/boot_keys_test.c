/* Test the actual BDS key scanner and resident relay against mocked firmware. */
/* Declare libc before EDK2's X64 headers push hidden symbol visibility. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#undef NULL
#include <Uefi.h>
#include <Protocol/SimpleTextInEx.h>
#include <Protocol/Security.h>
#include <Protocol/Security2.h>
#include <Protocol/LoadedImage.h>
#include <Library/UefiBootServicesTableLib.h>

EFI_BOOT_SERVICES *gBS;
EFI_SYSTEM_TABLE *gST;
EFI_HANDLE gImageHandle;
EFI_GUID gEfiSimpleTextInputExProtocolGuid = EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID;
EFI_GUID gEfiSecurityArchProtocolGuid = EFI_SECURITY_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiSecurity2ArchProtocolGuid = EFI_SECURITY2_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiLoadedImageProtocolGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;

#include "../edk2/QcomModulePkg/Drivers/BootKeyRelay/BootKeyRelay.c"
#include "../edk2/QcomModulePkg/Application/LinuxLoader/SuperFbBootKeys.c"

static EFI_BOOT_SERVICES bs;
static EFI_SYSTEM_TABLE st;
static EFI_SIMPLE_TEXT_INPUT_PROTOCOL input;
static EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL input_ex;
static EFI_SECURITY_ARCH_PROTOCOL security;
static EFI_SECURITY2_ARCH_PROTOCOL security2;
static UINT16 keys[16];
static unsigned key_count, key_pos, calls, closes, loads, starts, unloads, forwards;
static EFI_STATUS create_status, timer_status, wait_status, read_status;
static EFI_STATUS load_status, handle_status, start_status;
static BOOLEAN with_security, error_handle, expire;
static const EFI_EVENT timer_event = (EFI_EVENT)(UINTN)1;
static const EFI_EVENT key_event = (EFI_EVENT)(UINTN)2;
static const EFI_HANDLE driver_handle = (EFI_HANDLE)(UINTN)3;

static EFI_STATUS EFIAPI OriginalRead(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
                                     EFI_KEY_DATA *Data)
{
  assert(This == &input_ex);
  forwards++;
  return EFI_NOT_READY;
}

static EFI_STATUS EFIAPI OriginalState(CONST EFI_SECURITY_ARCH_PROTOCOL *This,
                                      UINT32 Auth, CONST EFI_DEVICE_PATH_PROTOCOL *Path)
{
  return EFI_SECURITY_VIOLATION;
}

static EFI_STATUS EFIAPI OriginalAuth(CONST EFI_SECURITY2_ARCH_PROTOCOL *This,
                                     CONST EFI_DEVICE_PATH_PROTOCOL *Path,
                                     VOID *Buffer, UINTN Size, BOOLEAN BootPolicy)
{
  return EFI_SECURITY_VIOLATION;
}

static EFI_STATUS EFIAPI MockCreate(UINT32 Type, EFI_TPL Tpl,
                                   EFI_EVENT_NOTIFY Notify, VOID *Context, EFI_EVENT *Event)
{
  calls++;
  assert(Type == EVT_TIMER && Tpl == TPL_CALLBACK && Notify == NULL);
  *Event = timer_event;
  return create_status;
}

static EFI_STATUS EFIAPI MockSetTimer(EFI_EVENT Event, EFI_TIMER_DELAY Type, UINT64 Time)
{
  calls++;
  assert(Event == timer_event && Type == TimerRelative && Time == 10000000);
  return timer_status;
}

static EFI_STATUS EFIAPI MockWait(UINTN Number, EFI_EVENT *Events, UINTN *Index)
{
  calls++;
  assert(Number == 2 && Events[0] == timer_event && Events[1] == key_event);
  *Index = (!expire && key_pos < key_count) ? 1 : 0;
  return wait_status;
}

static EFI_STATUS EFIAPI MockClose(EFI_EVENT Event)
{
  calls++;
  closes++;
  assert(Event == timer_event);
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI MockRead(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This, EFI_INPUT_KEY *Key)
{
  calls++;
  assert(This == &input && key_pos < key_count);
  Key->ScanCode = keys[key_pos++];
  Key->UnicodeChar = 0;
  return read_status;
}

static EFI_STATUS EFIAPI NoReset(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This, BOOLEAN Verify)
{
  assert(!"The scan must retain keys queued before entry");
  return EFI_DEVICE_ERROR;
}

static EFI_STATUS EFIAPI MockLocate(EFI_GUID *Guid, VOID *Registration, VOID **Result)
{
  calls++;
  *Result = NULL;
  if (!with_security) return EFI_NOT_FOUND;
  if (Guid == &gEfiSecurityArchProtocolGuid) *Result = &security;
  else if (Guid == &gEfiSecurity2ArchProtocolGuid) *Result = &security2;
  else assert(!"unexpected LocateProtocol");
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI MockHandle(EFI_HANDLE Handle, EFI_GUID *Guid, VOID **Result)
{
  calls++;
  if (Guid == &gEfiLoadedImageProtocolGuid) {
    assert(Handle == driver_handle);
    *Result = NULL; /* The production caller only checks for handle existence. */
    return EFI_ERROR(start_status) ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
  }
  assert(Handle == st.ConsoleInHandle && Guid == &gEfiSimpleTextInputExProtocolGuid);
  *Result = &input_ex;
  return handle_status;
}

static EFI_STATUS EFIAPI MockLoad(BOOLEAN BootPolicy, EFI_HANDLE Parent,
                                 EFI_DEVICE_PATH_PROTOCOL *Path, VOID *Buffer,
                                 UINTN Size, EFI_HANDLE *Handle)
{
  calls++;
  loads++;
  assert(!BootPolicy && Parent == gImageHandle && Path == NULL);
  assert(Buffer == mBootKeyRelayImage && Size == sizeof(mBootKeyRelayImage));
  if (with_security) {
    assert(security.FileAuthenticationState(&security, 0, NULL) == EFI_SUCCESS);
    assert(security2.FileAuthentication(&security2, NULL, Buffer, Size, FALSE) == EFI_SUCCESS);
  }
  *Handle = (!EFI_ERROR(load_status) || error_handle) ? driver_handle : NULL;
  return load_status;
}

static EFI_STATUS EFIAPI MockStart(EFI_HANDLE Handle, UINTN *Size, CHAR16 **Data)
{
  calls++;
  starts++;
  assert(Handle == driver_handle && Size == NULL && Data == NULL);
  /* All BDS callbacks must be removed before the resident driver starts. */
  assert(security.FileAuthenticationState == OriginalState);
  assert(security2.FileAuthentication == OriginalAuth);
  if (EFI_ERROR(start_status)) return start_status;
  return BootKeyRelayEntry(Handle, &st);
}

static EFI_STATUS EFIAPI MockUnload(EFI_HANDLE Handle)
{
  calls++;
  unloads++;
  assert(Handle == driver_handle);
  return EFI_SUCCESS;
}

static void Init(void)
{
  assert(BootKeyRelayUnload(driver_handle) == EFI_SUCCESS);
  memset(&bs, 0, sizeof(bs));
  memset(&st, 0, sizeof(st));
  memset(&input, 0, sizeof(input));
  memset(&input_ex, 0, sizeof(input_ex));
  gBS = &bs; gST = &st; gImageHandle = (EFI_HANDLE)(UINTN)4;
  st.ConsoleInHandle = (EFI_HANDLE)(UINTN)5; st.ConIn = &input;
  input.Reset = NoReset; input.ReadKeyStroke = MockRead; input.WaitForKey = key_event;
  input_ex.ReadKeyStrokeEx = OriginalRead;
  security.FileAuthenticationState = OriginalState;
  security2.FileAuthentication = OriginalAuth;
  bs.CreateEvent = MockCreate; bs.SetTimer = MockSetTimer;
  bs.WaitForEvent = MockWait; bs.CloseEvent = MockClose;
  bs.LocateProtocol = MockLocate; bs.HandleProtocol = MockHandle;
  bs.LoadImage = MockLoad; bs.StartImage = MockStart; bs.UnloadImage = MockUnload;
  /* ResetSystem/SetVariable and all disk/FAT/USB APIs are intentionally absent. */
  key_count = key_pos = calls = closes = loads = starts = unloads = forwards = 0;
  create_status = timer_status = wait_status = read_status = EFI_SUCCESS;
  load_status = handle_status = start_status = EFI_SUCCESS;
  with_security = TRUE; error_handle = expire = FALSE;
}

static SFB_BOOT_ACTION Check(BOOLEAN Enabled, EFI_STATUS Expected)
{
  EFI_STATUS status = EFI_ABORTED;
  SFB_BOOT_ACTION action = SfbCheckBootKeys(Enabled, 1000, &status);
  assert(status == Expected);
  assert(security.FileAuthenticationState == OriginalState);
  assert(security2.FileAuthentication == OriginalAuth);
  return action;
}

int main(void)
{
  EFI_KEY_DATA data;
  Init();
  keys[0] = SCAN_DOWN; key_count = 1;
  assert(Check(FALSE, EFI_SUCCESS) == SfbBootDefault && calls == 0);

  Init();
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootDefault && closes == 1 && loads == 0);

  Init();
  keys[0] = SCAN_ESC; keys[1] = SCAN_UP; key_count = 2;
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootMenu && key_pos == 2 && loads == 0);

  /* A pre-held Down key, with no repeat event, is delivered exactly once to
   * the stock ABL's extended input reader after the BDS scanner has returned. */
  Init();
  keys[0] = SCAN_DOWN; key_count = 1;
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootStockFastboot);
  assert(closes == 1 && loads == 1 && starts == 1 && unloads == 0);
  assert(input_ex.ReadKeyStrokeEx != OriginalRead);
  assert(input_ex.ReadKeyStrokeEx(&input_ex, NULL) == EFI_INVALID_PARAMETER);
  assert(input_ex.ReadKeyStrokeEx(NULL, &data) == EFI_INVALID_PARAMETER);
  memset(&data, 0xff, sizeof(data));
  assert(input_ex.ReadKeyStrokeEx(&input_ex, &data) == EFI_SUCCESS);
  assert(data.Key.ScanCode == SCAN_DOWN && data.Key.UnicodeChar == 0);
  assert(data.KeyState.KeyShiftState == 0 && data.KeyState.KeyToggleState == 0);
  assert(input_ex.ReadKeyStrokeEx == OriginalRead);
  assert(input_ex.ReadKeyStrokeEx(&input_ex, &data) == EFI_NOT_READY && forwards == 1);

  Init();
  keys[0] = SCAN_ESC; keys[1] = SCAN_DOWN; key_count = 2;
  with_security = FALSE;
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootStockFastboot && key_pos == 2);
  assert(BootKeyRelayUnload(driver_handle) == EFI_SUCCESS);
  assert(input_ex.ReadKeyStrokeEx == OriginalRead);

  Init();
  keys[0] = SCAN_DOWN; key_count = 1;
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootStockFastboot);
  /* Refuse unloading if an intervening hook could still reference the relay. */
  input_ex.ReadKeyStrokeEx = OriginalRead;
  assert(BootKeyRelayUnload(driver_handle) == EFI_ACCESS_DENIED);
  input_ex.ReadKeyStrokeEx = ReplayKey;
  assert(BootKeyRelayUnload(driver_handle) == EFI_SUCCESS);
  assert(input_ex.ReadKeyStrokeEx == OriginalRead);

  Init();
  keys[0] = SCAN_DOWN; key_count = 1; load_status = EFI_SECURITY_VIOLATION;
  error_handle = TRUE;
  assert(Check(TRUE, load_status) == SfbBootMenu);
  assert(starts == 0 && unloads == 1 && input_ex.ReadKeyStrokeEx == OriginalRead);

  Init();
  keys[0] = SCAN_DOWN; key_count = 1; load_status = EFI_OUT_OF_RESOURCES;
  assert(Check(TRUE, load_status) == SfbBootMenu && starts == 0 && unloads == 0);

  Init();
  keys[0] = SCAN_DOWN; key_count = 1; handle_status = EFI_UNSUPPORTED;
  assert(Check(TRUE, handle_status) == SfbBootMenu && unloads == 0);
  assert(input_ex.ReadKeyStrokeEx == OriginalRead);

  Init();
  keys[0] = SCAN_DOWN; key_count = 1; start_status = EFI_OUT_OF_RESOURCES;
  assert(Check(TRUE, start_status) == SfbBootMenu && unloads == 1);
  assert(input_ex.ReadKeyStrokeEx == OriginalRead);

  Init();
  keys[0] = SCAN_DOWN; key_count = 1; input_ex.ReadKeyStrokeEx = NULL;
  assert(Check(TRUE, EFI_UNSUPPORTED) == SfbBootMenu);

  Init();
  keys[0] = SCAN_DOWN; key_count = 1; expire = TRUE;
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootDefault && key_pos == 0);

  Init();
  create_status = EFI_OUT_OF_RESOURCES;
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootDefault && closes == 0);

  Init();
  timer_status = EFI_DEVICE_ERROR;
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootDefault && closes == 1);

  Init();
  wait_status = EFI_DEVICE_ERROR;
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootDefault && closes == 1);

  Init();
  keys[0] = SCAN_DOWN; key_count = 1; read_status = EFI_DEVICE_ERROR;
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootDefault && loads == 0);

  Init();
  keys[0] = SCAN_DOWN; key_count = 1; read_status = EFI_NOT_READY;
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootDefault && closes == 1);

  Init(); st.ConIn = NULL;
  assert(Check(TRUE, EFI_SUCCESS) == SfbBootDefault && calls == 0);
  puts("boot key scanner and resident relay tests passed");
  return 0;
}
