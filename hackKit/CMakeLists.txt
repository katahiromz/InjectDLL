# libhackKit.a
add_library(hackKit SHARED hackKit.cpp)
target_link_libraries(hackKit PRIVATE shlwapi psapi imagehlp)
set_target_properties(hackKit PROPERTIES PREFIX "")
set_target_properties(hackKit PROPERTIES OUTPUT_NAME "hackKit")

# libhackKit_static.a
add_library(hackKit_static STATIC hackKit.cpp)
target_link_libraries(hackKit_static PRIVATE shlwapi psapi imagehlp)
