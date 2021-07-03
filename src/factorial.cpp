// Based on https://github.com/catchorg/Catch2/blob/devel/docs/tutorial.md
unsigned int factorial(unsigned int number)
{
    return number <= 1 ? number : factorial(number - 1) * number;
}
