
extern "C" {
#include "md5.h"
}

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
          == from_hex("d41d8cd98f00b204e9800998ecf8427e"));
    CHECK(MDString("a")
          == from_hex("0cc175b9c0f1b6a831c399e269772661"));
    CHECK(MDString("abc")
          == from_hex("900150983cd24fb0d6963f7d28e17f72"));
    CHECK(MDString("message digest")
          == from_hex("f96b697d7cb7938d525a2f31aaf161d0"));
    CHECK(MDString("abcdefghijklmnopqrstuvwxyz")
          == from_hex("c3fcd3d76192e4007dfb496cca67e13b"));
    CHECK(MDString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
          == from_hex("d174ab98d277d9f5a5611c2c9f419d9f"));
    CHECK(MDString("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
          == from_hex("57edf4a22be3c955ac49da2e2107b67a"));
    // clang-format on
}
