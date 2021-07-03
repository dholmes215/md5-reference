# RSA MD5 Reference Implementation

![Build](../../actions/workflows/build.yml/badge.svg) ![clang-format](../../actions/workflows/clang-format.yml/badge.svg)

This is the reference implementation in C of the MD5 algorithm as it appears in the appendices of [RFC 1321 ("The MD5 Message-Digest Algorithm)"](https://datatracker.ietf.org/doc/html/rfc1321).  The RFC includes four files:

- `global.h` -- global header file
- `md5.h` -- header file for MD5
- `md5.c` -- source code for MD5
- `mddriver.c` -- test driver for MD2, MD4 and MD5

## License

The copyright notice and license from md5.h is:

```text
Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
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
```

After cloning this project you will need to init/update the `vcpkg` submodule by running: `git submodule update --init --recursive`

To build this project you will need:

- **A C11 & C++20 compiler** (one of MSVC, g++, or clang++)
- **CMake 3.20.3 or later**.  "Modern CMake" has recommendations on where to get CMake here: <https://cliutils.gitlab.io/modern-cmake/chapters/intro/installing.html>
- **clang-format** and an editor that supports it.  You don't strictly _need_ this, but the GitHub Actions will bark at you if you push code that doesn't match .clang_format.
- On Linux `vcpkg`'s bootstrap process will want several tools installed: `sudo apt-get install curl zip unzip tar`
