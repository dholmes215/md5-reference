// Based on https://github.com/catchorg/Catch2/blob/devel/docs/tutorial.md
#include <catch2/catch.hpp>

// Placeholder until real MD5 tests go here
unsigned int factorial( unsigned int number ) {
    return number <= 1 ? number : factorial(number-1)*number;
}

TEST_CASE("Factorials are computed", "[factorial]")
{
    REQUIRE(factorial(1) == 1);
    REQUIRE(factorial(2) == 2);
    REQUIRE(factorial(3) == 6);
    REQUIRE(factorial(10) == 3628800);
}
