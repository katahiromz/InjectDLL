add_executable(injector WIN32 injector.cpp injector_res.rc)
target_link_libraries(injector PRIVATE hackKit_static shlwapi psapi)
