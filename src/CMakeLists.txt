add_library(md5 md5c.c)
target_include_directories(md5 INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(md5 PRIVATE project_warnings)

add_executable(mddriver mddriver.c)
target_compile_definitions(mddriver PRIVATE)
target_link_libraries(mddriver PRIVATE md5 project_warnings)
