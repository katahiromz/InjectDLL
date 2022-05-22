add_library(payload SHARED payload.cpp)
set_target_properties(payload PROPERTIES PREFIX "")
set_target_properties(payload PROPERTIES OUTPUT_NAME "${PAYLOAD_NAME}")
target_link_libraries(payload PRIVATE hackKit_static shlwapi psapi)
