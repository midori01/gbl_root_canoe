#!/bin/sh
set -eu
test_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_tmp=$(mktemp -d)
trap 'rm -f "$test_tmp/menu_input_test"; rmdir "$test_tmp"' EXIT HUP INT TERM
case $(uname -m) in
  arm64|aarch64) test_arch=AArch64 ;;
  x86_64) test_arch=X64 ;;
  *) echo 'Unsupported host architecture' >&2; exit 1 ;;
esac
"${CC:-clang}" -fshort-wchar -DNO_MSABI_VA_FUNCS -Wall -Wextra -Werror \
  -Wno-unused-parameter -fsanitize=address,undefined -O1 \
  -I "$test_root/edk2/MdePkg/Include" \
  -I "$test_root/edk2/MdePkg/Include/$test_arch" \
  -I "$test_root/edk2/AndroidToolsPkg/Include" \
  "$test_root/tests/menu_input_test.c" -o "$test_tmp/menu_input_test"
"$test_tmp/menu_input_test"
