cmake_minimum_required (VERSION 3.0)
project (doram)
set(GIGADORAM_DIR "${CMAKE_SOURCE_DIR}/doram")

list(APPEND CMAKE_PREFIX_PATH "/app/lib/emp-tool")
# Set CMake prefix path
file(GLOB_RECURSE GIGADORAM_HEADERS "${GIGADORAM_DIR}/*.h") 
file(GLOB_RECURSE GIGADORAM_SOURCES "${GIGADORAM_DIR}/*.cpp")
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

add_library(gigadoram ${GIGADORAM_HEADERS} ${GIGADORAM_SOURCES})
list(APPEND CMAKE_PREFIX_PATH "$ENV{HOME}/.local/lib/cmake")

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
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=bounds")
# Installation: Not yet
# install(FILES cmake/emp-ot-config.cmake DESTINATION cmake/)
# install(DIRECTORY emp-ot DESTINATION include/)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)
add_executable(doram "")

target_compile_options(doram PUBLIC
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

target_link_options(doram PUBLIC
  "-pthread"
)
set_property(TARGET doram PROPERTY CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
include(src/CMakeLists.txt)

target_include_directories(gigadoram PUBLIC "${GIGADORAM_DIR}")

target_link_libraries(doram PUBLIC /app/lib/emp-tool/libemp-tool.so)
target_link_libraries(doram PUBLIC OpenSSL::SSL OpenSSL::Crypto gigadoram CURL::libcurl)
target_link_libraries(doram PRIVATE ${JSONCPP_LIBRARIES})
target_include_directories(doram PRIVATE ${JSONCPP_INCLUDE_DIRS})