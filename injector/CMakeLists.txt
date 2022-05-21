add_executable(injector WIN32 injector.cpp injector_res.rc)
target_link_libraries(injector shlwapi psapi)
