// Based on https://github.com/catchorg/Catch2/blob/devel/docs/tutorial.md
#include <factorial.hpp>

#include <catch2/catch.hpp>

TEST_CASE("Factorials are computed", "[factorial]")
{
    REQUIRE(factorial(1) == 1);
    REQUIRE(factorial(2) == 2);
    REQUIRE(factorial(3) == 6);
    REQUIRE(factorial(10) == 3628800);
}
