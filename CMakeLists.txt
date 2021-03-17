cmake_minimum_required(VERSION 3.17)

project(hello LANGUAGES CXX)

if(MSVC)
    add_compile_options(/W4 /WX)
else(MSVC)
    add_compile_options(-Wall -Wextra)
endif(MSVC)

add_subdirectory(src)
