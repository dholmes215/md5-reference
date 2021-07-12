cmake_minimum_required(VERSION 3.20.3)

option(BUILD_TESTING "Build unit tests (requires C++ and uses vcpkg)" ON)

if(BUILD_TESTING)
    # Update submodules
    include(cmake/UpdateSubmodule.cmake)
    option(GIT_SUBMODULE "Check submodules during build" ON)
    update_submodule("${CMAKE_CURRENT_LIST_DIR}/vcpkg")

    # Configure vcpkg (requires vcpkg submodule)
    include(cmake/ConfigureVcpkg.cmake)
    configure_vcpkg("${CMAKE_CURRENT_LIST_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")

    project(md5 LANGUAGES CXX)

    find_package(Boost 1.75.0 REQUIRED)
    find_package(Catch2 REQUIRED)
    find_package(Microsoft.GSL REQUIRED CONFIG)
else()
    project(md5 LANGUAGES CXX)
endif()

# Link this 'library' to use the warnings specified in CompilerWarnings.cmake
add_library(project_warnings INTERFACE)

# Configure compiler warnings.
include(cmake/CompilerWarnings.cmake)
set_project_warnings(project_warnings)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(src)

if(BUILD_TESTING)
    include(CTest)
    include(Catch)
    add_subdirectory(tests)
endif()
