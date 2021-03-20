cmake_minimum_required(VERSION 3.17)

project(hello LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /WX)
else(MSVC)
    add_compile_options(-Wall -Wextra -pedantic)
endif(MSVC)

add_subdirectory(src)
