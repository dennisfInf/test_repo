target_sources(poba
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/protocol.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/create_entry.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/u_reg.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/prove_entry.cpp"

)

if(ENABLE_GDORAM)
  target_sources(poba
    PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/insert_entry_giga.cpp"
)
else()
  target_sources(poba
    PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/insert_entry.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/insert_entry_mal.cpp"
)
endif()
