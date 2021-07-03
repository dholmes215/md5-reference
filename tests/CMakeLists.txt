add_executable(tests tests.cpp md5_test.cpp)
target_link_libraries(tests PRIVATE project_warnings Catch2::Catch2 md5)

enable_testing()

include(CTest)
include(Catch)
catch_discover_tests(tests)
