// "md5.h" requires "global.h" to be previously included but does not include
// it, and both files don't have include guards.  clang-format has to be off so
// it doesn't reorder them.

// clang-format off
extern "C" {
#include "global.h"
#include "md5.h"
}
// clang-format on

#include <catch2/catch.hpp>

#include <boost/algorithm/hex.hpp>

#include <gsl/gsl>

#include <array>
#include <cstring>

namespace {
using digest_array = std::array<unsigned char, 16>;

/* Digests a string and prints the result.
 */
digest_array MDString(const char* string)
{
    MD5_CTX context;
    digest_array out;
    unsigned int len = gsl::narrow<unsigned int>(strlen(string));

    MD5Init(&context);
    MD5Update(&context,
              reinterpret_cast<unsigned char*>(const_cast<char*>(string)), len);
    MD5Final(out.data(), &context);

    return out;
}

digest_array from_hex(const char (&hex)[33])
{
    digest_array out;
    boost::algorithm::unhex(hex, std::prev(std::end(hex)), out.begin());
    return out;
}

}  // namespace

TEST_CASE("MD5 test strings")
{
    // clang-format off
    CHECK(MDString("")
          == from_hex("e4c23762ed2823a27e62a64b95c024e7"));
    CHECK(MDString("a")
          == from_hex("793a9bc07e209b286fa416d6ee29a85d"));
    CHECK(MDString("abc")
          == from_hex("7999dc75e8da648c6727e137c5b77803"));
    CHECK(MDString("message digest")
          == from_hex("840793371ec58a6cc84896a5153095de"));
    CHECK(MDString("abcdefghijklmnopqrstuvwxyz")
          == from_hex("98ef94f1f01ac7b91918c6747fdebd96"));
    CHECK(MDString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
          == from_hex("dabcd637cde443764c4f8aa099cf23be"));
    CHECK(MDString("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
          == from_hex("e29c01a1e2a663c26b4a68bf7ec42df7"));
    // clang-format on
}
