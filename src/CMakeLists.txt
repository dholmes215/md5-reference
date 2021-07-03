add_executable(hello hello.cpp)
target_link_libraries(hello PRIVATE project_warnings fmt::fmt)

add_library(factorial factorial.cpp)
target_include_directories(factorial INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(factorial PRIVATE project_warnings)
