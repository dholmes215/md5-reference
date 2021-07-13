/* MDDRIVER.C - test driver for MD2, MD4 and MD5
 */

/* Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
rights reserved.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#include "md5.h"

#include <fmt/format.h>

#include <gsl/gsl>

#include <chrono>
#include <cstdio>
#include <cstring>

/* Length of test block, number of test blocks.
 */
constexpr auto test_block_len{100000};
constexpr auto test_block_count{100000};

static void MDString(const char*);
static void MDTimeTrial(void);
static void MDTestSuite(void);
static void MDFile(char*);
static void MDFilter(void);
static void MDPrint(unsigned char[16]);

/* Main driver.

Arguments (may be any combination):
  -sstring - digests string
  -t       - runs time trial
  -x       - runs test script
  filename - digests file
  (none)   - digests standard input
 */
int main(int argc, char** argv)
{
    int i;

    if (argc > 1)
        for (i = 1; i < argc; i++)
            if (argv[i][0] == '-' && argv[i][1] == 's')
                MDString(argv[i] + 2);
            else if (strcmp(argv[i], "-t") == 0)
                MDTimeTrial();
            else if (strcmp(argv[i], "-x") == 0)
                MDTestSuite();
            else
                MDFile(argv[i]);
    else
        MDFilter();

    return (0);
}

/* Digests a string and prints the result.
 */
static void MDString(const char* string)
{
    MD5_CTX context;
    unsigned char digest[16];
    unsigned int len = gsl::narrow<unsigned int>(strlen(string));

    MD5Init(&context);
    MD5Update(&context, reinterpret_cast<const uint8_t*>(string), len);
    MD5Final(digest, &context);

    printf("MD5 (\"%s\") = ", string);
    MDPrint(digest);
    printf("\n");
}

/* Measures the time to digest TEST_BLOCK_COUNT TEST_BLOCK_LEN-byte blocks. */
static void MDTimeTrial()
{
    using std::chrono::duration;
    using std::chrono::duration_cast;
    using std::chrono::high_resolution_clock;
    using std::chrono::milliseconds;

    MD5_CTX context;
    unsigned char block[test_block_len], digest[16];
    unsigned int i;
    printf("MD5 time trial. Digesting %d %d-byte blocks ...", test_block_len,
           test_block_count);

    /* Initialize block */
    for (i = 0; i < test_block_len; i++)
        block[i] = i & 0xff;

    /* Start timer */
    auto startTime = high_resolution_clock::now();

    /* Digest blocks */
    MD5Init(&context);
    for (i = 0; i < test_block_count; i++)
        MD5Update(&context, block, test_block_len);
    MD5Final(digest, &context);

    /* Stop timer */
    auto endTime = high_resolution_clock::now();
    milliseconds elapsed = duration_cast<milliseconds>(endTime - startTime);

    printf(" done\n");
    printf("Digest = ");
    MDPrint(digest);
    printf("\nTime = %ld ms\n", elapsed.count());
    fmt::print("Speed = {} bytes/ms\n",
               static_cast<double>(test_block_len) *
                   (static_cast<double>(test_block_count) /
                    static_cast<double>(elapsed.count())));
}

/* Digests a reference suite of strings and prints the results.
 */
static void MDTestSuite()
{
    printf("MD5 test suite:\n");

    MDString("");
    MDString("a");
    MDString("abc");
    MDString("message digest");
    MDString("abcdefghijklmnopqrstuvwxyz");
    MDString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    MDString(
        "1234567890123456789012345678901234567890\
1234567890123456789012345678901234567890");
}

/* Digests a file and prints the result.
 */
static void MDFile(char* filename)
{
    FILE* file;
    MD5_CTX context;
    unsigned int len;
    unsigned char buffer[1024], digest[16];

// MSVC doesn't like fopen, but we still support C99 so we're not guaranteed to
// have fopen_s, so suppress this warning.
#if (defined(_MSC_VER) && (_MSC_VER >= 1400))
#pragma warning(disable : 4996)
#endif

    if ((file = fopen(filename, "rb")) == NULL)
        printf("%s can't be opened\n", filename);

    else {
        MD5Init(&context);
        while ((len = static_cast<unsigned int>(
                    fread(buffer, 1, 1024, file))) != 0)
            MD5Update(&context, buffer, len);
        MD5Final(digest, &context);

        fclose(file);

        printf("MD5 (%s) = ", filename);
        MDPrint(digest);
        printf("\n");
    }
}

/* Digests the standard input and prints the result.
 */
static void MDFilter()
{
    MD5_CTX context;
    unsigned int len;
    unsigned char buffer[16], digest[16];

    MD5Init(&context);
    while ((len = static_cast<unsigned int>(fread(buffer, 1, 16, stdin))) != 0)
        MD5Update(&context, buffer, len);
    MD5Final(digest, &context);

    MDPrint(digest);
    printf("\n");
}

/* Prints a message digest in hexadecimal.

  @param digest a 16-byte MD5 digest
 */
static void MDPrint(unsigned char* digest)
{
    unsigned int i;

    for (i = 0; i < 16; i++)
        printf("%02x", digest[i]);
}
