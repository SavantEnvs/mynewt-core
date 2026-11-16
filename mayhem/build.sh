#!/usr/bin/env bash
#
# mayhem/build.sh — builds the fuzz harnesses (sanitized, with libFuzzer and standalone drivers) and
# the pre-built self-test binaries that mayhem/test.sh runs. Everything mynewt-core is compiled
# directly with clang, never through `newt` (which needs go and the network): only the host-portable
# packages are built, against a hand-written syscfg in mayhem/shim, so the harnesses fuzz upstream's
# own, unmodified sources.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/build"
rm -rf "$B"
mkdir -p "$B/fuzz" "$B/test"

INC=(
  -I"$SRC/mayhem/shim"
  -I"$SRC/kernel/os/include" -I"$SRC/kernel/os/include/os/arch/sim"
  -I"$SRC/hw/mcu/native/include" -I"$SRC/hw/hal/include"
  -I"$SRC/sys/defs/include" -I"$SRC/sys/sys/include" -I"$SRC/sys/console/stub/include"
  -I"$SRC/test/testutil/include" -I"$SRC/util/mem/include" -I"$SRC/util/parse/include"
  -I"$SRC/encoding/json/include" -I"$SRC/encoding/base64/include" -I"$SRC/encoding/base62/include"
  -I"$SRC/net/ip/mn_socket/include"
)

# 1) The fuzzed packages, instrumented, as one archive.
LIB_SRCS=(
  encoding/json/src/json_decode.c
  encoding/json/src/json_encode.c
  encoding/base64/src/base64.c
  encoding/base64/src/hex.c
  encoding/base62/src/base62.c
  util/parse/src/parse.c
  net/ip/mn_socket/src/mn_socket_aconv.c
)
objs=()
for s in "${LIB_SRCS[@]}"; do
  o="$B/fuzz/$(echo "$s" | tr / _).o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 -w "${INC[@]}" -c "$SRC/$s" -o "$o"
  objs+=("$o")
done
ar rcs "$B/fuzz/libmynewt.a" "${objs[@]}"

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/fuzz/standalone_main.o"

# 2) Each harness twice: with the fuzzing engine, and with the run-once standalone driver.
for t in fuzz_json fuzz_base64 fuzz_base62 fuzz_parse; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 -w "${INC[@]}" \
      -c "$SRC/mayhem/$t.c" -o "$B/fuzz/$t.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/fuzz/$t.o" "$B/fuzz/libmynewt.a" \
      "$B/fuzz/lsan_off.o" -lm -o "/mayhem/$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/fuzz/$t.o" "$B/fuzz/standalone_main.o" "$B/fuzz/libmynewt.a" \
      "$B/fuzz/lsan_off.o" -lm -o "/mayhem/$t-standalone"
done

# 3) The upstream self-tests and the KAT probe, with the project's normal flags (no sanitizers).
TEST_COMMON=(
  test/testutil/src/case.c test/testutil/src/suite.c test/testutil/src/testutil.c
  util/mem/src/mem.c
  kernel/os/src/os_mbuf.c kernel/os/src/os_mempool.c kernel/os/src/os_msys.c
  mayhem/shim/os_shim.c
)
TEST_INC=("${INC[@]}"
  -I"$SRC/encoding/base64/selftest/src" -I"$SRC/encoding/base62/selftest/src"
  -I"$SRC/encoding/json/selftest/src" -I"$SRC/encoding/json/selftest/include"
  -I"$SRC/net/ip/mn_socket/selftest/src")

build_test() {
  local name="$1"; shift
  local d="$B/test/$name" o
  mkdir -p "$d"
  objs=()
  for s in "${TEST_COMMON[@]}" "$@"; do
    o="$d/$(echo "$s" | tr / _).o"
    $CC -O1 -w $COVERAGE_FLAGS -DMAYHEM_SELFTEST -DUNITTEST "${TEST_INC[@]}" -c "$SRC/$s" -o "$o"
    objs+=("$o")
  done
  $CC $COVERAGE_FLAGS "${objs[@]}" -lm -o "$B/test/$name.bin"
}

build_test base64_selftest encoding/base64/src/base64.c encoding/base64/src/hex.c \
  encoding/base64/selftest/src/base64_test.c encoding/base64/selftest/src/testcases/*.c
build_test base62_selftest encoding/base62/src/base62.c \
  encoding/base62/selftest/src/encoding_test.c encoding/base62/selftest/src/testcases/*.c
build_test json_selftest encoding/json/src/json_decode.c encoding/json/src/json_encode.c \
  encoding/json/selftest/src/test_json.c encoding/json/selftest/src/test_json_utils.c \
  encoding/json/selftest/src/testcases/*.c
# Upstream's mn_socket address-converter cases; mayhem/selftest/mn_socket_selftest.c is the suite
# (upstream's own main also runs socket_tests, which needs the scheduler the shim lacks).
build_test mn_socket_selftest net/ip/mn_socket/src/mn_socket_aconv.c \
  net/ip/mn_socket/selftest/src/testcases/inet*.c mayhem/selftest/mn_socket_selftest.c
build_test kat encoding/base64/src/base64.c encoding/base64/src/hex.c encoding/base62/src/base62.c \
  encoding/json/src/json_decode.c util/parse/src/parse.c net/ip/mn_socket/src/mn_socket_aconv.c \
  mayhem/kat.c
