add_library(md5 md5c.c)
target_link_libraries(md5 PRIVATE project_warnings)

add_executable(mddriver mddriver.c)
target_compile_definitions(mddriver PRIVATE MD=5) # MD=5 required to use MD5 algorithm
target_link_libraries(mddriver PRIVATE md5 project_warnings)
