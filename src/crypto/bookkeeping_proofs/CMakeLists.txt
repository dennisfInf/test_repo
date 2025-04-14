target_sources(poba
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/setup.cpp"
)

include(${CMAKE_CURRENT_LIST_DIR}/prove_entry/CMakeLists.txt)

include(${CMAKE_CURRENT_LIST_DIR}/create_entry/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/u_reg/CMakeLists.txt)
