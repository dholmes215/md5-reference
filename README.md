# cpp-template

![Build](https://github.com/dholmes215/cpp-template/actions/workflows/build.yml/badge.svg) ![clang-format](https://github.com/dholmes215/cpp-template/actions/workflows/clang-format.yml/badge.svg)

Template for David's C++ projects.

To build this project you will need:

* **A C++17 compiler** (one of MSVC, g++, or clang++)
* **CMake 3.17 or later**.  You could use an older version, but you'll need to modify your CMakeLists.txt accordingly.  "Modern CMake" has recommendations on where to get CMake here: <https://cliutils.gitlab.io/modern-cmake/chapters/intro/installing.html>
* **clang-format** and an editor that supports it.  You don't strictly _need_ this, but the GitHub Actions will bark at you if you push code that doesn't match .clang_format.
