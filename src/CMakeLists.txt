add_library(md5 md5.c md5.h global.h)
target_link_libraries(md5 PRIVATE project_warnings)

add_executable(mddriver mddriver.c global.h md5)
target_compile_definitions(mddriver PRIVATE MD=5) # MD=5 required to use MD5 algorithm
target_link_libraries(mddriver PRIVATE project_warnings)
