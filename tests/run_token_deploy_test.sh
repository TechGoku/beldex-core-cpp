#!/usr/bin/env bash
# Build and run the HF21 "deploy a new asset" end-to-end test under Emscripten + node.
#
#   ./tests/run_token_deploy_test.sh <path-to-BeldexLibAppCpp_WASM-build-dir>
#
# Requires an activated emsdk (source <emsdk>/emsdk_env.sh) and node.
#
# The test links against the object files the beldex-libapp-js WASM target has
# already produced, minus the two translation units that carry the embind
# bindings and the EM_ASM bridge (index.cpp, emscr_SendFunds_bridge.cpp) -- those
# define a main/module shape of their own and expect a JS host. Everything else,
# including the whole vendored core, is reused as-is, so the test exercises the
# same binaries the module ships rather than a separate build of the sources.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-}"
if [[ -z "$BUILD_DIR" || ! -d "$BUILD_DIR/CMakeFiles/BeldexLibAppCpp_WASM.dir" ]]; then
  echo "usage: $0 <path-to-BeldexLibAppCpp_WASM-build-dir>" >&2
  exit 2
fi

OUT="${2:-/tmp/bcc-token-deploy-test}"
mkdir -p "$OUT"

CORE="$ROOT/contrib/beldex-core-custom"
LIBAPP_CPP="$(cd "$ROOT/.." && pwd)"   # .../beldex-libapp-cpp/src

INC="-I$ROOT/src -I$LIBAPP_CPP -I$LIBAPP_CPP/SendFunds/Controllers
     -I$CORE -I$CORE/epee/include -I$CORE/external -I$CORE/external/fmt/include
     -I$CORE/external/loki-mq -I$CORE/external/oxen-encoding -I$CORE/common
     -I$CORE/vtlogger -I$CORE/crypto -I$CORE/cryptonote_basic -I$CORE/multisig
     -I$CORE/cryptonote_core -I$CORE/cryptonote_protocol -I$CORE/wallet -I$CORE/rpc
     -I$CORE/mnemonics -I$CORE/contrib/libsodium/include
     -I$CORE/contrib/libsodium/include/sodium"

# -fexceptions must be set at COMPILE time, not just link time, or the wallet
# exceptions thrown by the construction path abort instead of propagating.
CXXFLAGS="-std=c++17 -w -O1 -fexceptions -DBELDEX_CORE_CUSTOM
          -D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION
          -DBOOST_ASIO_HAS_PTHREADS -DBOOST_HAS_PTHREADS -DBOOST_HAS_THREADS
          -sUSE_BOOST_HEADERS=1"

em++ $CXXFLAGS $INC -c "$ROOT/tests/token_deploy_test.cpp" -o "$OUT/token_deploy_test.o"

# Everything the module compiles, except the two JS-host translation units.
mapfile -t OBJS < <(find "$BUILD_DIR/CMakeFiles/BeldexLibAppCpp_WASM.dir" -name '*.o' \
  ! -name 'index.cpp.o' ! -name 'emscr_SendFunds_bridge.cpp.o' | sort)
echo "linking ${#OBJS[@]} object files from the module build"

em++ -O1 -fexceptions -o "$OUT/token_deploy_test.js" \
  "$OUT/token_deploy_test.o" "${OBJS[@]}" \
  -sALLOW_MEMORY_GROWTH=1 -sEXIT_RUNTIME=1 -sTOTAL_STACK=8MB

node "$OUT/token_deploy_test.js"
