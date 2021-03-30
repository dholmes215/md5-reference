cmake_minimum_required(VERSION 3.17)

project(hello LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Single variable to tell CMake to use /WX (on MSVC) or -Werror (on other compilers)
set(WARNINGS_AS_ERRORS OFF CACHE STRING "Whether to treat warnings as errors")

if(MSVC)
    add_compile_options(/W4)
    if(WARNINGS_AS_ERRORS)
        add_compile_options(/WX)
    endif(WARNINGS_AS_ERRORS)
else(MSVC)
    add_compile_options(-Wall -Wextra -Wshadow -pedantic)
    if(WARNINGS_AS_ERRORS)
        add_compile_options(-Werror)
    endif(WARNINGS_AS_ERRORS)
endif(MSVC)

add_subdirectory(src)
