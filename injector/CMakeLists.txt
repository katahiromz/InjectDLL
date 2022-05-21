add_executable(injector WIN32 injector.cpp injector_res.rc)
set_target_properties(injector PROPERTIES OUTPUT_NAME "${INJECTOR_NAME}")
target_link_libraries(injector PRIVATE hackKit_static shlwapi psapi)
