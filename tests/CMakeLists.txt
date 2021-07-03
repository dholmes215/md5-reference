add_executable(tests tests.cpp factorial_test.cpp)
target_link_libraries(tests PRIVATE project_warnings Catch2::Catch2 factorial)

enable_testing()

include(CTest)
include(Catch)
catch_discover_tests(tests)
