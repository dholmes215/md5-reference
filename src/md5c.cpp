/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#include "md5.h"

#include <stdint.h>
#include <algorithm>
#include <bit>
#include <cstring>

namespace {

// Constants for MD5Transform routine.
constexpr auto S11{7};
constexpr auto S12{12};
constexpr auto S13{17};
constexpr auto S14{22};
constexpr auto S21{5};
constexpr auto S22{9};
constexpr auto S23{14};
constexpr auto S24{20};
constexpr auto S31{4};
constexpr auto S32{11};
constexpr auto S33{16};
constexpr auto S34{23};
constexpr auto S41{6};
constexpr auto S42{10};
constexpr auto S43{15};
constexpr auto S44{21};

void MD5Transform(uint32_t[4], const unsigned char[64]);
void encode(uint8_t* output, const uint32_t* input, uint32_t len);
auto decode(const uint8_t* input) -> std::array<uint32_t, 16>;

constexpr std::array<uint8_t, 64> padding{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* F, G, H and I are basic MD5 functions.
 */

constexpr uint32_t f(uint32_t x, uint32_t y, uint32_t z) noexcept
{
    return (x & y) | (~x & z);
}

constexpr uint32_t g(uint32_t x, uint32_t y, uint32_t z) noexcept
{
    return (x & z) | (y & ~z);
}

constexpr uint32_t h(uint32_t x, uint32_t y, uint32_t z) noexcept
{
    return x ^ y ^ z;
}

constexpr uint32_t i(uint32_t x, uint32_t y, uint32_t z) noexcept
{
    return y ^ (x | ~z);
}

}  // namespace

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
// [[gnu::always_inline]] void FF(auto& a, auto b, auto c, auto d, auto x, auto
// s, uint32_t ac, auto func)
// {
//     a += func(b, c, d) + x + ac;
//     a = std::rotl(a, s);
//     a += b;
// }
#define FF(a, b, c, d, x, s, ac)                      \
    {                                                 \
        (a) += f((b), (c), (d)) + (x) + uint32_t{ac}; \
        (a) = std::rotl((a), (s));                    \
        (a) += (b);                                   \
    }
#define GG(a, b, c, d, x, s, ac)                      \
    {                                                 \
        (a) += g((b), (c), (d)) + (x) + uint32_t{ac}; \
        (a) = std::rotl((a), (s));                    \
        (a) += (b);                                   \
    }
#define HH(a, b, c, d, x, s, ac)                      \
    {                                                 \
        (a) += h((b), (c), (d)) + (x) + uint32_t{ac}; \
        (a) = std::rotl((a), (s));                    \
        (a) += (b);                                   \
    }
#define II(a, b, c, d, x, s, ac)                      \
    {                                                 \
        (a) += i((b), (c), (d)) + (x) + uint32_t{ac}; \
        (a) = std::rotl((a), (s));                    \
        (a) += (b);                                   \
    }

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void MD5Init(MD5_CTX* context)
{
    md5::context c{};
    std::memcpy(context, &c, sizeof(MD5_CTX));
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.

  @param context  context
  @param input    input block
  @param inputLen input block length in bytes
 */
void MD5Update(MD5_CTX* context, const uint8_t* input, uint32_t inputLen)
{
    /* Compute number of bytes mod 64 */
    unsigned int index = (context->count[0] >> 3) & 0x3F;

    /* Update number of bits */
    if ((context->count[0] += (inputLen * 8)) < (inputLen * 8)) {
        context->count[1]++;
    }
    context->count[1] += (inputLen >> 29);

    unsigned int partLen = 64 - index;

    /* Transform as many times as possible.
     */
    unsigned int i;
    if (inputLen >= partLen) {
        const auto output_begin = context->buffer + index;
        std::copy(input, input + partLen, output_begin);
        MD5Transform(context->state, context->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64)
            MD5Transform(context->state, &input[i]);

        index = 0;
    }
    else {
        i = 0;
    }

    /* Buffer remaining input */
    const auto input_begin = input + i;
    const auto input_end = input_begin + inputLen - i;
    const auto output_begin = context->buffer + index;
    std::copy(input_begin, input_end, output_begin);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.

  @param digest   The MD5 digest output (must be 16 bytes)
  @param context  The context.
 */
void MD5Final(uint8_t* digest, MD5_CTX* context)
{
    unsigned char bits[8];
    uint32_t index;
    unsigned int padLen;

    /* Save number of bits */
    encode(bits, context->count, 8);

    /* Pad out to 56 mod 64.
     */
    index = (context->count[0] >> 3) & 0x3f;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(context, padding.data(), padLen);

    /* Append length (before padding) */
    MD5Update(context, bits, 8);

    /* Store state in digest */
    encode(digest, context->state, 16);

    /* Zeroize sensitive information. */
    memset(context, 0, sizeof(*context));
}

namespace {

/* MD5 basic transformation. Transforms state based on block.

  @param state The current state (must be four words)
  @param block  The block being processed (must be 64 bytes)
 */
void MD5Transform(uint32_t* state, const unsigned char* block)
{
    uint32_t a{state[0]};
    uint32_t b{state[1]};
    uint32_t c{state[2]};
    uint32_t d{state[3]};
    const std::array<uint32_t, 16> x{decode(block)};

    /* Round 1 */
    FF(a, b, c, d, x[0], S11, 0xd76aa478);  /* 1 */
    FF(d, a, b, c, x[1], S12, 0xe8c7b756);  /* 2 */
    FF(c, d, a, b, x[2], S13, 0x242070db);  /* 3 */
    FF(b, c, d, a, x[3], S14, 0xc1bdceee);  /* 4 */
    FF(a, b, c, d, x[4], S11, 0xf57c0faf);  /* 5 */
    FF(d, a, b, c, x[5], S12, 0x4787c62a);  /* 6 */
    FF(c, d, a, b, x[6], S13, 0xa8304613);  /* 7 */
    FF(b, c, d, a, x[7], S14, 0xfd469501);  /* 8 */
    FF(a, b, c, d, x[8], S11, 0x698098d8);  /* 9 */
    FF(d, a, b, c, x[9], S12, 0x8b44f7af);  /* 10 */
    FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[1], S21, 0xf61e2562);  /* 17 */
    GG(d, a, b, c, x[6], S22, 0xc040b340);  /* 18 */
    GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);  /* 20 */
    GG(a, b, c, d, x[5], S21, 0xd62f105d);  /* 21 */
    GG(d, a, b, c, x[10], S22, 0x2441453);  /* 22 */
    GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);  /* 24 */
    GG(a, b, c, d, x[9], S21, 0x21e1cde6);  /* 25 */
    GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[3], S23, 0xf4d50d87);  /* 27 */
    GG(b, c, d, a, x[8], S24, 0x455a14ed);  /* 28 */
    GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[2], S22, 0xfcefa3f8);  /* 30 */
    GG(c, d, a, b, x[7], S23, 0x676f02d9);  /* 31 */
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[5], S31, 0xfffa3942);  /* 33 */
    HH(d, a, b, c, x[8], S32, 0x8771f681);  /* 34 */
    HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[1], S31, 0xa4beea44);  /* 37 */
    HH(d, a, b, c, x[4], S32, 0x4bdecfa9);  /* 38 */
    HH(c, d, a, b, x[7], S33, 0xf6bb4b60);  /* 39 */
    HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[0], S32, 0xeaa127fa);  /* 42 */
    HH(c, d, a, b, x[3], S33, 0xd4ef3085);  /* 43 */
    HH(b, c, d, a, x[6], S34, 0x4881d05);   /* 44 */
    HH(a, b, c, d, x[9], S31, 0xd9d4d039);  /* 45 */
    HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[2], S34, 0xc4ac5665);  /* 48 */

    /* Round 4 */
    II(a, b, c, d, x[0], S41, 0xf4292244);  /* 49 */
    II(d, a, b, c, x[7], S42, 0x432aff97);  /* 50 */
    II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[5], S44, 0xfc93a039);  /* 52 */
    II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[3], S42, 0x8f0ccc92);  /* 54 */
    II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[1], S44, 0x85845dd1);  /* 56 */
    II(a, b, c, d, x[8], S41, 0x6fa87e4f);  /* 57 */
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[6], S43, 0xa3014314);  /* 59 */
    II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[4], S41, 0xf7537e82);  /* 61 */
    II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[2], S43, 0x2ad7d2bb);  /* 63 */
    II(b, c, d, a, x[9], S44, 0xeb86d391);  /* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    // /* Zeroize sensitive information.
    //  */
    // memset(x, 0, sizeof(x));
}

void encode_word(uint8_t* output, const uint32_t input)
{
    output[0] = static_cast<uint8_t>((input >> 0) & 0xff);
    output[1] = static_cast<uint8_t>((input >> 8) & 0xff);
    output[2] = static_cast<uint8_t>((input >> 16) & 0xff);
    output[3] = static_cast<uint8_t>((input >> 24) & 0xff);
}

// Encodes input (uint32_t) into output (unsigned char). Assumes len is a
// multiple of 4.
void encode(uint8_t* output, const uint32_t* input, uint32_t len)
{
    for (size_t i{0}; i < len / 4; i++) {
        const auto j{i * 4};
        encode_word(output + j, input[i]);
    }
}

// Endian-independent decode of 4 bytes into a uint32_t.
auto decode_word(const uint8_t* input) -> uint32_t
{
    return (static_cast<uint32_t>(input[0]) << 0) |
           (static_cast<uint32_t>(input[1]) << 8) |
           (static_cast<uint32_t>(input[2]) << 16) |
           (static_cast<uint32_t>(input[3]) << 24);
}

// Decodes 64-byte input (unsigned char) into output (uint32_t).
auto decode(const uint8_t* input) -> std::array<uint32_t, 16>
{
    std::array<uint32_t, 16> output;
    for (size_t i{0}; i < output.size(); i++) {
        const auto j{i * 4};
        output[i] = decode_word(input + j);
    }
    return output;
}

}  // namespace

namespace md5 {

context::context() noexcept
    : state{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}, count{}, buffer{}
{
}

// void update(context& context, const uint8_t* input, uint32_t inputLen)
// {

// }

// auto final(context& context) -> std::array<uint8_t, 16>
// {

// }

}  // namespace md5
