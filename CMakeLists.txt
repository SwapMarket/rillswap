cmake_minimum_required(VERSION 3.25)
project(rill_crypto VERSION 0.1.0 LANGUAGES C)

include(CTest)
include(FetchContent)
find_package(Threads REQUIRED)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static dependencies" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "Enable extrakeys" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "Enable Schnorr" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG ON CACHE BOOL "Enable MuSig2" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "Disable upstream benchmarks" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "Disable upstream tests in facade build" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "Disable exhaustive tests" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "Disable upstream examples" FORCE)

if(EMSCRIPTEN)
  set(SECP256K1_ASM OFF CACHE STRING "Disable assembly for WASM" FORCE)
endif()

FetchContent_Declare(
  secp256k1
  URL https://github.com/bitcoin-core/secp256k1/releases/download/v0.8.0/libsecp256k1-0.8.0.tar.gz
  URL_HASH SHA256=dd685546f9e717b9adde329acd5a4cd8083d40f710fdb0a603ee5a83f908132b
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(secp256k1)

add_library(rill_crypto c/src/rill_crypto.c)
add_library(RillSwap::crypto ALIAS rill_crypto)
target_compile_features(rill_crypto PUBLIC c_std_11)
target_include_directories(
  rill_crypto
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/c/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(rill_crypto PRIVATE secp256k1)

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(rill_crypto PRIVATE -Wall -Wextra -Wconversion -Werror)
endif()

if(EMSCRIPTEN)
  add_executable(rill_crypto_wasm wasm/rill_crypto_wasm.c)
  target_link_libraries(rill_crypto_wasm PRIVATE rill_crypto)
  set_target_properties(rill_crypto_wasm PROPERTIES SUFFIX ".mjs")
  target_link_options(
    rill_crypto_wasm
    PRIVATE
      --no-entry
      -O3
      "-sMODULARIZE=1"
      "-sEXPORT_ES6=1"
      "-sEXPORT_NAME=RillCrypto"
      "-sFILESYSTEM=0"
      "-sENVIRONMENT=web,worker,node"
      "-sEXPORTED_RUNTIME_METHODS=['HEAPU8']"
      "-sEXPORTED_FUNCTIONS=['_malloc','_free','_rill_crypto_abi_version','_rill_crypto_context_create','_rill_crypto_context_destroy','_rill_public_key_create','_rill_schnorr_sign','_rill_schnorr_verify','_rill_musig_output_key','_rill_musig_begin','_rill_musig_public_nonce_validate','_rill_musig_partial_sign_once','_rill_musig_partial_verify','_rill_musig_aggregate','_rill_musig_attempt_destroy']"
  )
endif()

if(BUILD_TESTING AND NOT EMSCRIPTEN)
  add_executable(rill_crypto_ffi_test tests/ffi/test_rill_crypto.c)
  target_link_libraries(rill_crypto_ffi_test PRIVATE rill_crypto Threads::Threads)
  add_test(NAME rill_crypto_ffi_test COMMAND rill_crypto_ffi_test)
endif()
