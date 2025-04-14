target_sources(poba
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/bootstrapping.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/server.cpp"
)

include(${CMAKE_CURRENT_LIST_DIR}/grpc/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/mpc/CMakeLists.txt)
