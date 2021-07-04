add_executable(tests tests.cpp md5_test.cpp)
target_link_libraries(tests PRIVATE project_warnings Boost::boost Catch2::Catch2 Microsoft.GSL::GSL md5)

catch_discover_tests(tests)
