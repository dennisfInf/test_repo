add_library(pairing
  STATIC
    group.cpp
    serializer.cpp
    deserializer.cpp
    matrix.cpp
)

# Relic does not check for libgmp if using it, and due to some c/c++ incompatibilities,
# we also need to include libgmp directly
#find_library(LIB_GMP gmp)
#if(NOT LIB_GMP)
#  message(FATAL_ERROR "gmp library not found")
#endif()

target_include_directories(pairing
  PUBLIC
    "${PROJECT_SOURCE_DIR}/inc/crypto/bilinear_group"
  PRIVATE
    "${PROJECT_SOURCE_DIR}/lib/relic/include/"
)
target_link_libraries(pairing
  PRIVATE
    relic_s
)
