# stolen from relic, ATM we do not need any newer features
cmake_minimum_required(VERSION 3.1)

project(poba)
message("Source directory: ${CMAKE_SOURCE_DIR}")
set(MPSPDZ_DIR "${CMAKE_SOURCE_DIR}/lib/MP-SPDZ")
file(GLOB_RECURSE MPSPDZ_SOURCES "${MPSPDZ_DIR}/Networking/*.cpp" "${MPSPDZ_DIR}/Networking/*.c"  "${MPSPDZ_DIR}/Networking/*.hpp" "${MPSPDZ_DIR}/Tools/*.cpp" "${MPSPDZ_DIR}/Tools/*.hpp" "${MPSPDZ_DIR}/Tools/*.c" "${MPSPDZ_DIR}/Processor/*.cpp" "${MPSPDZ_DIR}/Processor/*.hpp" "${MPSPDZ_DIR}/Processor/*.c" "${MPSPDZ_DIR}/Math/*.cpp" "${MPSPDZ_DIR}/Math/*.c" "${MPSPDZ_DIR}/Math/*.hpp" "${MPSPDZ_DIR}/Protocols/Share.hpp"  "${MPSPDZ_DIR}/ExternalIO/Client.hpp" "${MPSPDZ_DIR}/Protocols/*.cpp"  "${MPSPDZ_DIR}/Protocols/*.hpp"  "${MPSPDZ_DIR}/Protocols/*.c")
file(GLOB_RECURSE MPSPDZ_HEADERS "${MPSPDZ_DIR}/Networking/*.h" "${MPSPDZ_DIR}/Networking/*.hpp" "${MPSPDZ_DIR}/Tools/*.h"  "${MPSPDZ_DIR}/Math/*.h"  "${MPSPDZ_DIR}/Processor/*.h" "${MPSPDZ_DIR}/ExternalIO/Client.h" "${MPSPDZ_DIR}/Protocols/*.h" ) 
add_library(mpspdz ${MPSPDZ_SOURCES} ${MPSPDZ_HEADERS})
target_compile_options(mpspdz PUBLIC
"-DMAX_MOD_SZ=12"
"-DGFP_MOD_SZ=6"
)
option(ENABLE_GDORAM "Enable Feature GIGADORAM" ON)
message(STATUS "ENABLE_GDORAM = ${ENABLE_GDORAM}")
find_package(OpenSSL REQUIRED)

if(ENABLE_GDORAM)
  set(GIGADORAM_DIR "${CMAKE_SOURCE_DIR}/lib/GigaDORAM/doram")
  list(APPEND CMAKE_PREFIX_PATH "/app/lib/emp-tool")
  file(GLOB_RECURSE GIGADORAM_HEADERS "${GIGADORAM_DIR}/*.h") 
  file(GLOB_RECURSE GIGADORAM_SOURCES "${GIGADORAM_DIR}/*.cpp")
  add_library(gigadoram ${GIGADORAM_HEADERS} ${GIGADORAM_SOURCES})
    #target_compile_definitions(my_app PRIVATE FEATURE_X_ENABLED)
endif()
# Find Boost

# Specify the include directories for the mp-spdz library
list(APPEND CMAKE_PREFIX_PATH "$ENV{HOME}/.local/lib/cmake")
list(APPEND CMAKE_PREFIX_PATH "$ENV{HOME}/.local/lib/cmake/protobuf")
list(APPEND CMAKE_PREFIX_PATH "/external/protobuf/protobuf_code/cmake")
find_package(Protobuf CONFIG REQUIRED)
set(PROTO_PATH "${CMAKE_CURRENT_SOURCE_DIR}/protos")
set(PROTO_SRC_DIR "${CMAKE_CURRENT_BINARY_DIR}/protos")
file(GLOB PROTO_FILES "${PROTO_PATH}/*.proto")
find_package(gRPC CONFIG REQUIRED)
### RELIC START ###
# Configure relic
if(ENABLE_GDORAM)
  set(CMAKE_PREFIX_PATH "/app/lib/emp-tool;/app/lib/emp-ot;/app/lib/emp-sh2pc" CACHE STRING "CMake prefix path")
  # Set RPATH and LD_LIBRARY_PATH
  set(CMAKE_BUILD_RPATH "/app/lib/emp-tool;/app/lib/emp-ot;/app/lib/emp-sh2pc;${CMAKE_BUILD_RPATH}")
  set(CMAKE_INSTALL_RPATH "/app/lib/emp-tool;/app/lib/emp-ot;/app/lib/emp-sh2pc")
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
  set(ENV{LD_LIBRARY_PATH} "/app/lib/emp-tool:/app/lib/emp-ot:/app/lib/emp-sh2pc:$ENV{LD_LIBRARY_PATH}")
  find_package(emp-tool)
  find_package(emp-ot REQUIRED)
  find_package(emp-sh2pc REQUIRED)
  include_directories(${EMP-TOOL_INCLUDE_DIRS})
  include_directories(${EMP-OT_INCLUDE_DIR})
  include_directories(${EMP-SH2PC_INCLUDE_DIR})
endif()

option(DEBUG "Relic: Build with debugging support" off)
option(PROFL "Relic: Build with profiling support" off)
option(CHECK "Relic: Build with error-checking support" on)
option(VERBS "Relic: Build with detailed error messages" on)
option(OVERH "Relic: Build with overhead estimation" off)
option(DOCUM "Relic: Build documentation" off)
option(STRIP "Relic: Build only the selected algorithms" off)
option(QUIET "Relic: Build with printing disabled" off)
option(COLOR "Relic: Build with colored output" on)
option(BIGED "Relic: Build with big-endian support" off)
option(SHLIB "Relic: Build shared library" off)                             # Do not build a shared library
option(STLIB "Relic: Build static library" on)
option(STBIN "Relic: Build static binaries" off)
option(AMALG "Relic: Build amalgamation" off)
# Number of tests and benchmarks
set(TESTS "0" CACHE STRING "Relic: Number of times each test is ran.")      # Do not build tests
set(BENCH "0" CACHE STRING "Relic: Number of times each benchmark is ran.") # Do not build benchmarks
# Choose the memory-allocation policy.
set(ALLOC "AUTO" CACHE STRING "Relic: Allocation policy")
# Use BN-382 curve
set(FP_PRIME 382)
set(MD_METHD "SH256")


set(FP_QNRES on)
# set(Strip on)
set(FP_METHD "INTEG;INTEG;INTEG;MONTY;JMPDS;JMPDS;SLIDE")
set(FPX_METHD "INTEG;INTEG;LAZYR")
set(TIMER "CYCLE")
set(RAND "UDEV")

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
  set(WSIZE 64)
  set(FP_METHD "INTEG;INTEG;INTEG;MONTY;JMPDS;JMPDS;SLIDE")
  set(ENV{COMP} "-O3 -funroll-loops -fomit-frame-pointer -finline-small-functions -march=native -mtune=native")
  # Use optimized code for x64
  set(ARITH "x64-asm-6l")
  set(FP_PMERS off)
  set(EP_PLAIN off)
  set(EP_SUPER off)
  set(PP_METHD="LAZYR;OATEP")


endif()
if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "armv7l")
  set(WSIZE 32)
  set(FP_METHD "INTEG;INTEG;INTEG;MONTY;EXGCD;SLIDE")
  set(ENV{COMP} "-O3 -funroll-loops -fomit-frame-pointer -mcpu=cortex-a7")
  set(ARCH "ARM")
  set(ARITH "arm-asm-254" CACHE STRING "Arithmetic backend" FORCE)
endif()
set(CMAKE_C_FLAGS_TEMP "${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
#set(DEBUG "SET_THIS_TO_SOMETHING_FOR_RELIC")
#TODO USE ALLOC DYNAMIC WITH SANITIZERS
#set(ALLOC "DYNAMIC")
add_subdirectory("${CMAKE_SOURCE_DIR}/lib/relic" "${CMAKE_BINARY_DIR}/relic_build" EXCLUDE_FROM_ALL)
target_include_directories(relic_s INTERFACE "${CMAKE_BINARY_DIR}/relic_build/include/")
#unset(ALLOC)
#unset(DEBUG)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_TEMP}")
### RELIC END ###

# C++ Interface class for Pairing Operations (c) Max Hoffmann
add_subdirectory("./src/crypto/bilinear_group" "${CMAKE_BINARY_DIR}/pairing_build")
# Groth--Sahai Proofs generated by GS-Transpiler from Julian Herr in /src/crypto/bookkeeping_proofs and /inc/crypto/proofs/
include_directories(/usr/include/libsodium)
include_directories(/usr/include/)
link_directories(/usr/lib/x86_64-linux-gnu/libsodium.a)
link_directories(/usr/lib/x86_64-linux-gnu/libgmpxx.a)
if(ENABLE_GDORAM)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
endif()
add_executable(poba "")
target_compile_options(poba PUBLIC
  "-Wall"
  "-Wextra"
  "-Wpedantic"
  "-Wno-conversion"
  "-Wno-sign-conversion"
  "-Wno-sign-compare"
  "${OpenMP_CXX_FLAGS}"
  "$<$<CONFIG:Debug>:-g3>"
  "$<$<BOOL:${USE_PROFILE}>:-pg>"
  "$<$<CONFIG:Debug>:-Og>"
  "$<$<CONFIG:Release>:-Ofast>"
  "-g"
)
target_link_options(poba PUBLIC
  "-pthread"
)
set_property(TARGET poba PROPERTY CXX_STANDARD 17)
set_property(TARGET poba PROPERTY C_STANDARD 99)

include(src/CMakeLists.txt)
file(MAKE_DIRECTORY ${PROTO_SRC_DIR})
target_include_directories(poba PUBLIC inc/)
protobuf_generate(
    TARGET poba
    LANGUAGE cpp
    PROTOS ${PROTO_FILES}
    PROTOC_OUT_DIR ${PROTO_SRC_DIR})

protobuf_generate(
    LANGUAGE grpc
    TARGET poba
    GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
    PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
    PROTOS ${PROTO_FILES}
    PROTOC_OUT_DIR ${PROTO_SRC_DIR}
)
target_include_directories(poba PUBLIC "${PROTO_SRC_DIR}")
target_include_directories(mpspdz PUBLIC "${MPSPDZ_DIR}")
if(ENABLE_GDORAM)
  target_include_directories(gigadoram PUBLIC "${GIGADORAM_DIR}")
  target_link_libraries(poba PUBLIC /app/lib/emp-tool/libemp-tool.so gigadoram)
  target_compile_definitions(poba PRIVATE ENABLE_GDORAM)
endif()
#grpc++ caueses segmentation faults, when used with mp-spdz
target_link_libraries(poba PUBLIC pairing mpspdz OpenSSL::SSL OpenSSL::Crypto sodium gmpxx gmp gRPC::grpc++_unsecure gRPC::grpc++_reflection)