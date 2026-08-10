// xhash: C/C++ implementation of XHash, the Ethereum Proof of Work algorithm.
// Copyright 2021 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "difficulty.h"
#include "../../lib/xhash/endianness.hpp"

#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#endif

inline int clz(uint32_t x) noexcept
{
#if defined(_MSC_VER) && !defined(__clang__)
    unsigned long most_significant_bit;
    _BitScanReverse(&most_significant_bit, x);
    return 31 - (int)most_significant_bit;
#else
    return x != 0 ? __builtin_clz(x) : 32;
#endif
}


extern "C" {
// Reduce complexity of this function and enable `readability-function-cognitive-complexity`
// in clang-tidy.
[[clang::no_sanitize("unsigned-integer-overflow", "unsigned-shift-base")]] xhash_hash256
xhash_difficulty_to_boundary(const xhash_hash256* difficulty) noexcept
{
    constexpr size_t num_words = sizeof(*difficulty) / sizeof(difficulty->word32s[0]);

    // Find actual divisor size by omitting leading zero words.
    int n = 0;
    for (size_t i = 0; i < num_words; ++i)
    {
        if (difficulty->word32s[i] != 0)
        {
            n = static_cast<int>(num_words - i);
            break;
        }
    }

    // Bring divisor to native form: native words in little-endian word order.
    uint32_t d[num_words];
    for (size_t i = 0; i < num_words; ++i)
        d[i] = xhash::be::uint32(difficulty->word32s[num_words - 1 - i]);

    // For difficulty of 0 (division by 0) or 1 (256-bit overflow) return max boundary value.
    if (n == 0 || (n == 1 && d[0] == 1))
    {
        return xhash_hash256{
            {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}};
    }

    // XHash boundary semantics: boundary = floor((2^256 - 1) / difficulty),
    // matching the consensus target in the Parallax client (kernel/xhash).
    // This equals floor(2^256 / difficulty) unless the difficulty is a power
    // of two (the only divisors of 2^256); handle that case directly as
    // (2^256 - 1) >> log2(difficulty) and let the long division below cover
    // the rest.
    {
        int nonzero_word = -1;
        bool single_bit = true;
        for (size_t i = 0; i < num_words; ++i)
        {
            if (d[i] != 0)
            {
                if (nonzero_word >= 0 || (d[i] & (d[i] - 1)) != 0)
                {
                    single_bit = false;
                    break;
                }
                nonzero_word = static_cast<int>(i);
            }
        }
        if (single_bit && nonzero_word >= 0)
        {
            int bit = 0;
            while ((d[nonzero_word] & (uint32_t{1} << bit)) == 0)
                ++bit;
            const int log2_d = nonzero_word * 32 + bit;  // difficulty = 2^log2_d, log2_d >= 1
            xhash_hash256 boundary = {};
            for (int i = 0; i < 256 - log2_d; ++i)
                boundary.bytes[31 - i / 8] |= static_cast<uint8_t>(1u << (i % 8));
            return boundary;
        }
    }

    // Normalize d.
    uint32_t dn[num_words];
    const int shift = clz(d[n - 1]);
    for (int i = n - 1; i > 0; i--)
        dn[i] = shift ? (d[i] << shift) | (d[i - 1] >> (32 - shift)) : d[i];
    dn[0] = d[0] << shift;

    // Normalized 2^256.
    constexpr int m = 9;
    uint32_t un[m + 1]{};  // Requires one more leading word for n != 1 division.
    un[m - 1] = uint32_t{1} << shift;

    uint32_t q[num_words]{};

    if (n == 1)
    {
        uint32_t d0 = dn[0];
        uint32_t rhat = un[m - 1];
        for (int j = m - 2; j >= 0; --j)
        {
            uint64_t numerator = (uint64_t{rhat} << 32) | un[j];
            q[j] = static_cast<uint32_t>(numerator / d0);
            rhat = static_cast<uint32_t>(numerator % d0);
        }
    }
    else
    {
        // Based on the older implementation in intx.
        // https://github.com/chfast/intx/blob/aceda3f8a2b5baafa718ebc435133e7a55e3c77b/lib/intx/div.cpp#L114

        const uint32_t d1 = dn[n - 1];
        const uint32_t d0 = dn[n - 2];
        for (int j = m - n; j >= 0; j--)  // Main loop.
        {
            const auto u2 = un[j + n];
            const auto u1 = un[j + n - 1];
            const auto u0 = un[j + n - 2];
            const uint64_t numerator = (uint64_t{u2} << 32) | u1;

            uint32_t qhat = ~uint32_t{0};
            if (u2 < d1)  // No overflow.
            {
                qhat = static_cast<uint32_t>(numerator / d1);
                const uint64_t rhat = numerator % d1;

                const auto p = uint64_t{qhat} * d0;
                if (p > ((rhat << 32) | u0))
                    --qhat;
            }

            // Multiply and subtract.
            uint32_t borrow = 0;
            for (int i = 0; i < n; i++)
            {
                const uint32_t s = un[i + j] - borrow;
                const bool k1 = un[i + j] < borrow;

                const uint64_t p = uint64_t{qhat} * dn[i];
                const uint32_t ph = static_cast<uint32_t>(p >> 32);
                const uint32_t pl = static_cast<uint32_t>(p);

                const uint32_t t = s - pl;
                const bool k2 = s < pl;

                un[i + j] = t;
                borrow = ph + k1 + k2;
            }
            un[j + n] = u2 - borrow;

            if (u2 < borrow)  // Too much subtracted, add back.
            {
                --qhat;

                bool carry = false;
                for (int i = 0; i < n - 1; ++i)
                {
                    const uint32_t s1 = un[i + j] + dn[i];
                    const bool k1 = s1 < un[i + j];
                    const uint32_t s2 = s1 + carry;
                    const bool k2 = s2 < s1;
                    un[i + j] = s2;
                    carry = k1 || k2;
                }
                un[j + n - 1] += d1 + carry;
            }

            q[j] = qhat;  // Store quotient digit.
        }
    }

    // Convert to big-endian.
    xhash_hash256 boundary = {};
    for (size_t i = 0; i < num_words; ++i)
        boundary.word32s[i] = xhash::be::uint32(q[num_words - 1 - i]);
    return boundary;
}
}
