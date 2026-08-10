// xhash: C/C++ implementation of XHash, the Ethereum Proof of Work algorithm.
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#ifdef _MSC_VER
#pragma warning(disable : 4127)
#endif

#include <xhash/endianness.hpp>
#include <xhash/keccak.hpp>
#include <xhash/sha3.hpp>
#include <xhash/xhash-internal.hpp>
#include <xhash/xhash.hpp>

#include "../experimental/difficulty.h"
#include "helpers.hpp"
#include "test_cases.hpp"

#include <gtest/gtest.h>

#include <array>
#include <future>

using namespace xhash;

namespace
{
constexpr uint8_t PARALLAX_MAGIC[] = {'P', 'A', 'R', 'A', 'L', 'L', 'A', 'X', 0x01};
struct test_context_full : epoch_context
{
    hash1024* full_dataset;
};

/// Creates the epoch context of the correct size but filled with fake data.
epoch_context_ptr create_epoch_context_mock(int epoch_number)
{
    // Prepare a constant endianness-independent cache item.
    hash512 fill;
    static constexpr uint64_t fill_word = 0xe14a54a1b2c3d4e5;
    std::fill_n(fill.word64s, sizeof(hash512) / sizeof(uint64_t), le::uint64(fill_word));

    static const size_t context_alloc_size = std::max(sizeof(epoch_context), sizeof(hash512));

    // The copy of xhash_create_epoch_context() but without light cache building:

    const int light_cache_num_items = calculate_light_cache_num_items(epoch_number);
    const size_t light_cache_size = get_light_cache_size(light_cache_num_items);
    const size_t alloc_size = context_alloc_size + light_cache_size;

    char* const alloc_data = static_cast<char*>(std::malloc(alloc_size));
    hash512* const light_cache = reinterpret_cast<hash512*>(alloc_data + context_alloc_size);
    std::fill_n(light_cache, light_cache_num_items, fill);

    epoch_context* const context = new (alloc_data) epoch_context{
        epoch_number,
        light_cache_num_items,
        light_cache,
        calculate_full_dataset_num_items(epoch_number),
    };
    return {context, xhash_destroy_epoch_context};
}

hash512 copy(const hash512& h) noexcept
{
    return h;
}
}  // namespace

TEST(xhash, revision)
{
    static_assert(xhash::revision[0] == '2', "");
    static_assert(xhash::revision[1] == '3', "");
    EXPECT_EQ(xhash::revision, "23");
    EXPECT_EQ(xhash::revision, (std::string{"23"}));
}

TEST(xhash, error_code)
{
    std::ostringstream os;
    std::error_code ec = XHASH_SUCCESS;
    EXPECT_FALSE(ec);
    EXPECT_EQ(ec.message(), "");

    ec = XHASH_INVALID_FINAL_HASH;
    EXPECT_TRUE(ec);
    EXPECT_EQ(ec.message(), "invalid final hash");
    os.str({});
    os << ec;
    EXPECT_EQ(os.str(), "xhash:1");

    ec = XHASH_INVALID_MIX_HASH;
    EXPECT_TRUE(ec);
    EXPECT_EQ(ec.message(), "invalid mix hash");
    os.str({});
    os << ec;
    EXPECT_EQ(os.str(), "xhash:2");

    ec = static_cast<xhash_errc>(3);
    EXPECT_TRUE(ec);
    EXPECT_EQ(ec.message(), "unknown error");
    os.str({});
    os << ec;
    EXPECT_EQ(os.str(), "xhash:3");
}

TEST(hash, hash256_from_bytes)
{
    const uint8_t bytes[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    auto h = hash256_from_bytes(bytes);
    EXPECT_EQ(to_hex(h), "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
}

TEST(hash, hash512_init)
{
    hash512 hash = {};
    for (auto w : hash.word64s)
        EXPECT_EQ(w, 0);

    hash512 hash2 = copy({});
    for (auto w : hash2.word64s)
        EXPECT_EQ(w, 0);
}

TEST(hash, hash1024_init)
{
    hash1024 hash = {};
    for (auto w : hash.word64s)
        EXPECT_EQ(w, 0);
}

struct dataset_size_test_case
{
    int epoch_number;
    uint64_t light_cache_size;
    uint64_t full_dataset_size;
};

/// Test cases for dataset sizes are random picked from generated xhash sizes.
/// See https://github.com/ethereum/wiki/wiki/XHash#data-sizes.
static dataset_size_test_case dataset_size_test_cases[] = {
    {0, 16776896, 1073739904},
    {14, 18611392, 1191180416},
    {17, 19004224, 1216345216},
    {56, 24116672, 1543503488},
    {158, 37486528, 2399139968},
    {203, 43382848, 2776625536},
    {211, 44433344, 2843734144},
    {272, 52427968, 3355440512},
    {350, 62651584, 4009751168},
    {412, 70778816, 4529846144},
    {464, 77593664, 4966054784},
    {530, 86244416, 5519703424},
    {656, 102760384, 6576662912},
    {657, 102890432, 6585055616},
    {658, 103021888, 6593443456},
    {739, 113639104, 7272921472},
    {751, 115212224, 7373585792},
    {798, 121372352, 7767849088},
    {810, 122945344, 7868512384},
    {862, 129760832, 8304715136},
    {882, 132382528, 8472492928},
    {920, 137363392, 8791260032},
    {977, 144832448, 9269411456},
    {1093, 160038464, 10242489472},
    {1096, 160430656, 10267656064},
    {1119, 163446592, 10460589952},
    {1125, 164233024, 10510923392},
    {1165, 169475648, 10846469248},
    {1168, 169866304, 10871631488},
    {1174, 170655424, 10921964672},
    {1211, 175504832, 11232345728},
    {1244, 179830208, 11509169024},
    {1410, 201588544, 12901672832},
    {1418, 202636352, 12968786816},
    {1436, 204996544, 13119782528},
    {1502, 213645632, 13673430656},
    {1512, 214956992, 13757316224},
    {1535, 217972672, 13950253696},
    {1538, 218364736, 13975417216},
    {1554, 220461632, 14109635968},
    {1571, 222690368, 14252243072},
    {1602, 226754368, 14512291712},
    {1621, 229243328, 14671675264},
    {1630, 230424512, 14747172736},
    {1698, 239335232, 15317596544},
    {1746, 245628736, 15720251264},
    {1790, 251395136, 16089346688},
    {1818, 255065792, 16324230016},
    {1912, 267386432, 17112759424},
    {1928, 269482688, 17246976896},
    {1956, 273153856, 17481857408},
    {2047, 285081536, 18245220736},
    {30000, 3948936512, 252731976832},
    {max_epoch_number, 4294836032, 274'869'514'624},
    {max_epoch_number + 1, 0, 0},
    {max_epoch_number * 2, 0, 0},
    {-1, 0, 0},
};

TEST(xhash, light_cache_size)
{
    for (const auto& t : dataset_size_test_cases)
    {
        int num_items = calculate_light_cache_num_items(t.epoch_number);
        size_t size = get_light_cache_size(num_items);
        EXPECT_EQ(size, t.light_cache_size) << "epoch: " << t.epoch_number;
    }
}

TEST(xhash, full_dataset_size)
{
    for (const auto& t : dataset_size_test_cases)
    {
        const int num_items = calculate_full_dataset_num_items(t.epoch_number);
        const uint64_t size = get_full_dataset_size(num_items);
        EXPECT_EQ(size, t.full_dataset_size) << "epoch: " << t.epoch_number;
    }
}


struct epoch_seed_test_case
{
    const int epoch_number;
    const char* const epoch_seed_hex;
};

constexpr epoch_seed_test_case epoch_seed_test_cases[] = {
    {0, "0000000000000000000000000000000000000000000000000000000000000000"},
    {1, "98ad90833060d50f880b5eb465849d897ccfaebc9416082f97900ddd539a7e53"},
    {171, "b16823d6fe8aa7e87a22f25763227e8d1e8dfd064f668d6f5027d5b2e3d7a4e0"},
    {2048, "b8c95f49f8d32e58ad12a67fb16983a19ced40d40e331d30960437d742239b26"},
    {718, "220972f38803f15fe0c16297de0e1489c553223393327bce9f580e691a57ab14"},
    {719, "37beac41a318ee043c7032236f93c061dd747a3a6f877d80dc5d6d4afdf7a58a"},
    {max_epoch_number - 1, "1d8ce4fc1a432357e7cd5bc88bf4248c54bc07b1d200097fc09d3874964e9cbd"},
    {max_epoch_number, "8c6939a0e720fc95ac0f443d95e77990cacc7bb061b6a2a40f42164978652b10"},
};

TEST(xhash, calculate_epoch_seed)
{
    for (auto& t : epoch_seed_test_cases)
    {
        const hash256 epoch_seed = calculate_epoch_seed(t.epoch_number);
        EXPECT_EQ(to_hex(epoch_seed), t.epoch_seed_hex);
    }
}


TEST(xhash, find_epoch_number_double_ascending)
{
    const hash256 seed_718 = to_hash256(epoch_seed_test_cases[4].epoch_seed_hex);
    const hash256 seed_719 = to_hash256(epoch_seed_test_cases[5].epoch_seed_hex);

    int epoch = find_epoch_number(seed_718);
    EXPECT_EQ(epoch, 718);

    // The second call should be fast.
    epoch = find_epoch_number(seed_719);
    EXPECT_EQ(epoch, 719);
}

TEST(xhash, find_epoch_number_double_descending)
{
    const hash256 seed_718 = to_hash256(epoch_seed_test_cases[4].epoch_seed_hex);
    const hash256 seed_719 = to_hash256(epoch_seed_test_cases[5].epoch_seed_hex);

    int epoch = find_epoch_number(seed_719);
    EXPECT_EQ(epoch, 719);

    // The second call should be fast.
    epoch = find_epoch_number(seed_718);
    EXPECT_EQ(epoch, 718);
}

TEST(xhash, find_epoch_number_sequential)
{
    hash256 seed = {};
    for (int i = 0; i <= max_epoch_number; ++i)
    {
        auto e = find_epoch_number(seed);
        EXPECT_EQ(e, i);
        uint8_t buf[sizeof(PARALLAX_MAGIC) + sizeof(seed)];
        std::memcpy(buf, PARALLAX_MAGIC, sizeof(PARALLAX_MAGIC));
        std::memcpy(buf + sizeof(PARALLAX_MAGIC), seed.bytes, sizeof(seed));
        seed = sha3_256(buf, sizeof(buf));
    }
}

TEST(xhash, find_epoch_number_max)
{
    const auto seed_max = to_hash256(epoch_seed_test_cases[7].epoch_seed_hex);

    uint8_t buf[sizeof(PARALLAX_MAGIC) + sizeof(seed_max)];
    std::memcpy(buf, PARALLAX_MAGIC, sizeof(PARALLAX_MAGIC));
    std::memcpy(buf + sizeof(PARALLAX_MAGIC), seed_max.bytes, sizeof(seed_max));
    const auto seed_out_of_range = sha3_256(buf, sizeof(buf));

    find_epoch_number({});  // Reset cache.
    EXPECT_EQ(find_epoch_number(seed_out_of_range), -1);
    find_epoch_number({});  // Reset cache.
    EXPECT_EQ(find_epoch_number(seed_max), max_epoch_number);
}

TEST(xhash, find_epoch_number_sequential_gap)
{
    constexpr int start_epoch = 200;
    hash256 seed = calculate_epoch_seed(start_epoch);
    for (int i = start_epoch; i <= max_epoch_number; ++i)
    {
        auto e = find_epoch_number(seed);
        EXPECT_EQ(e, i);
        uint8_t buf[sizeof(PARALLAX_MAGIC) + sizeof(seed)];
        std::memcpy(buf, PARALLAX_MAGIC, sizeof(PARALLAX_MAGIC));
        std::memcpy(buf + sizeof(PARALLAX_MAGIC), seed.bytes, sizeof(seed));
        seed = sha3_256(buf, sizeof(buf));
    }
}

TEST(xhash, find_epoch_number_descending)
{
    for (int i = 2050; i >= 2000; --i)
    {
        auto seed = calculate_epoch_seed(i);
        auto e = find_epoch_number(seed);
        EXPECT_EQ(e, i);
    }

    for (int i = 50; i >= 0; --i)
    {
        auto seed = calculate_epoch_seed(i);
        auto e = find_epoch_number(seed);
        EXPECT_EQ(e, i);
    }
}

TEST(xhash, find_epoch_number_invalid)
{
    hash256 fake_seed = {};
    fake_seed.word32s[0] = 1;
    int epoch = find_epoch_number(fake_seed);
    EXPECT_EQ(epoch, -1);
}

TEST(xhash, find_epoch_number_epoch_too_high)
{
    hash256 seed = calculate_epoch_seed(max_epoch_number + 1);
    int epoch = find_epoch_number(seed);
    EXPECT_EQ(epoch, -1);
}

TEST(xhash_multithreaded, find_epoch_number_sequential)
{
    auto fn = [] {
        hash256 seed = {};
        for (int i = 0; i <= max_epoch_number; ++i)
        {
            auto e = find_epoch_number(seed);
            EXPECT_EQ(e, i);
            uint8_t buf[sizeof(PARALLAX_MAGIC) + sizeof(seed)];
            std::memcpy(buf, PARALLAX_MAGIC, sizeof(PARALLAX_MAGIC));
            std::memcpy(buf + sizeof(PARALLAX_MAGIC), seed.bytes, sizeof(seed));
            seed = sha3_256(buf, sizeof(buf));
        }
    };

    std::array<std::future<void>, 4> futures;
    for (auto& f : futures)
        f = std::async(std::launch::async, fn);
    for (auto& f : futures)
        f.wait();
}

TEST(xhash, get_epoch_number)
{
    EXPECT_EQ(get_epoch_number(0), 0);
    EXPECT_EQ(get_epoch_number(1), 0);
    EXPECT_EQ(get_epoch_number(719), 0);
    EXPECT_EQ(get_epoch_number(720), 1);
    EXPECT_EQ(get_epoch_number(721), 1);
    EXPECT_EQ(get_epoch_number(722), 1);
    EXPECT_EQ(get_epoch_number(120000), 166);
    EXPECT_EQ(get_epoch_number(max_epoch_number * epoch_length), max_epoch_number);
    constexpr auto max_block = max_epoch_number * epoch_length + epoch_length - 1;
    EXPECT_EQ(get_epoch_number(max_block), max_epoch_number);
}

TEST(xhash, light_cache)
{
    struct light_cache_test_case
    {
        const int epoch_number;
        const char* const hash;
    };

    light_cache_test_case test_cases[] = {
        {0, "76a346841e9a2767352eee04bae7886497764cf284dade2ddaa8e7ffc139b97e"},
        {171, "2c86d9b8f65d38c9e4805d40cdf6e5fc47d2db5e53a29be28556ef237141d87c"},
        {2047, "dd789434ba847d0e98e17f0b7f88b0b86e524498cb42beb59e952cfbea494e35"},
    };

    for (const auto& t : test_cases)
    {
        auto context = create_epoch_context(t.epoch_number);
        const uint8_t* const light_cache_data = context->light_cache[0].bytes;
        const size_t light_cache_size =
            static_cast<size_t>(context->light_cache_num_items) * sizeof(context->light_cache[0]);
        const hash256 light_cache_hash = sha3_256(light_cache_data, light_cache_size);
        EXPECT_EQ(light_cache_hash, to_hash256(t.hash));
    }
}

TEST(xhash, create_context_invalid_epoch)
{
    EXPECT_EQ(create_epoch_context(-1), nullptr);
    EXPECT_EQ(create_epoch_context(max_epoch_number + 1), nullptr);
}

TEST(xhash, fake_dataset_partial_items)
{
    struct full_dataset_item_test_case
    {
        uint32_t index;
        const char* hash_hex;
    };

    // clang-format off
    full_dataset_item_test_case test_cases[] = {
        {0,          "c95e4b68be203a94de0b34ec5bfab359de14e0b8a5dc4157d27c298275fef92073f7626b6b5f9e7fe235caced60cc4d95605087bf2c3d20fb2d66bf2a5a4c6df"},
        {1,          "3e6229146d275e30198424efa714da981c6ed7cc3fce0e7b89fcac588f9a95fa199e27c80abff551ea0433c209e6a6c68cfe1be22e3397979c35319a11b565dd"},
        {13,         "40f02ad6b0c26a188e0d708fd44f30f9363ffbd752da3beab4ced352a1cb88aa3ce6ebc602bb0dc9f56376f36944785d6a19523c85f112b91016a4d1090596f6"},
        {171,        "81d9e6acefb33121142035d3067ab8712398ef328c3c14138a76da28af0b0bf693bde42a5be1ccfc94ac77506904462b91df867da0aa0c817db1aaebf171f0fe"},
        {571,        "43ff08aab89cb926c674afae774bb724692e502a9cd2d51c218b058370151f278597f4c87100d24392f9be2299ee7fa590d6ded3667ca034365f129f96aaeb3b"},
        {620,        "cd183f4f63147b9585b81b1ed69c27ba033adfd39b97fccde8f87c194f7dcbc2cd54d435f728da82bc2cb22ba7345179343cd7229d39d95e5e29d60e19b5412e"},
        {514079,     "28b9bd01f80913551c26b607086b22b78835eaa3fa36ec6afa80eded519886c155882dc3c768cbd704a9c59c0d40e38e2b42b4d9e774fdbec2012eb1505aee86"},
        {852881,     "e33c34cacbbd18f978afed09cdd436666d0a2c10320265203ed3b035330d71cdfb9966f0d31146f18eb75c7647d8890d6fb9e34ff35b7c9cce22b33b5bab566a"},
        {6133492,    "e3248589c40e40df6f167efb915ca710b9e55c20d5aa0aa6cab93b5ac6b4a076bc359612c97ddc6ac12cfd441f0e052e089a22386bf945649b8a84a64615b0ad"},
        {6133493,    "43fc0a2485559592144cd4145185c08f697c70a8c1fcb775518a237324c0cc4342fbdbcc139192be495f9320a7b15ba7ba616bfd342e3e65cad1f7e14481ec51"},
        {211322105,  "265c90eb479114794871fd5f94274bed6b58029648815c9817b19b4c60006bbf93cf310cb5209bb06c7240b12d156381da0350ea9db0a142f18b091c5489d53c"},
        {740620450,  "97925c7c60b1c98ac98ca7632fba709cc72df24ae2a7fef90471f38f4891de7ab74d6bdb5957e3103fb9315fd1df61ee7955b6c515d074fea52e1da0ad8c9a0e"},
        {4294967295, "d99078774a6307bf06342ca1bc1827a3aef153c32ac958fb1a7db68b6524904bc635b529c198cc1238a4c19eb587679f0438b32191a7e47541d0bc51043b009d"},
    };
    // clang-format on

    // Mock the epoch context.
    auto context = create_epoch_context_mock(0);

    for (const auto& t : test_cases)
    {
        const auto full_index = t.index / 2;
        const auto part_index = t.index % 2;

        const auto full_item = calculate_dataset_item_1024(*context, full_index);
        const auto& part_item = full_item.hash512s[part_index];
        EXPECT_EQ(to_hex(part_item), t.hash_hex) << "index: " << t.index;
    }
}

TEST(xhash, fake_dataset_items)
{
    struct full_dataset_item_test_case
    {
        uint32_t index;
        const char* hash1_hex;
        const char* hash2_hex;
    };

    // clang-format off
    full_dataset_item_test_case test_cases[] = {
        {0,
            "c95e4b68be203a94de0b34ec5bfab359de14e0b8a5dc4157d27c298275fef92073f7626b6b5f9e7fe235caced60cc4d95605087bf2c3d20fb2d66bf2a5a4c6df",
            "3e6229146d275e30198424efa714da981c6ed7cc3fce0e7b89fcac588f9a95fa199e27c80abff551ea0433c209e6a6c68cfe1be22e3397979c35319a11b565dd"},
        {1,
            "9ca372cfef7f3ebf87cabafe0f9df49eca9e3b52b3e59b485fcba2980328251f7caf42529028ee63fc6f7eb30f8969ea8400bd42c5d125f63eb9d838a37ea82d",
            "59f8321e7fb553926adf6efdb9397143fce854b61289d90d9ae88e5b08fb27f4469612e9bbaf804601459c9815e03266f1df04a28ce3167f8b9caeb26d7b71e2"},
        {13,
            "36c13de9e8d9c40d82e416b828c3f1bfcac0bdbcd1a5f06f4b4383aa7bf58adcbe3a0bb99263baaff9e5c301681d29c3777c330186aa2f3a2545648bc48b3af1",
            "234691eca9ab5b9f85a49bc0ecfa793ff98fd0116d7d454aa873b37e772573123ead0aab5a4b1e909d9e4cb805257790f6c039f9f28b38479c08fbfc04c11d82"},
        {171,
            "eeabbd6b9296081782e64ec0463b61e8d771795b55dbb2bebe393cf8568699e87abefa785274fb625c54b5286bdb551cd8b2fd6ff6c3dcfb91338727a1f7e8ea",
            "1b98d80d4fbcfa83e2fde4f824b8c078f03869f8602582b17d7f759a8aea8461624d5938d769f7810744861ea92470d005a4bad484e577045fbf8701cdd92d53"},
        {571,
            "7311ae4a846877dcd9a3ee734afe54f448adcbb5bb0edf964f504e6766d9683d87e42f481e5f1f2faf044ecba8fdd6608cd178eeaa8578084d158cd5ee4cdc35",
            "e052e0d96aaa1d02246f85824ce4c473a4eccb1653b94ef4b439006805ba0d7fe5bf256da5bd1fc73ce7d290153ed4c6eb8d4e38911e262d2883b6555d9fb3a8"},
        {620,
            "090f667258b0f5bc6b9c18db12f6e58779750f54e25fb2da2c10307a97ee81daa2dc3b3e46ea0617a406e2274966f365b193e094a80a5b4b900b2500cc64744d",
            "c69c16440f742c5a33aa02b853543a41e32dd9fa44d7f319c265cb385f08ffc73b5618be1c0c8bb1602a7463fe193114e91ed7c74ebad98129b48406349aba38"},
        {514079,
            "3be6d70216aef525c1abc95bfe505589f92820854d9e1a18aaa82e329d21b814e6c81860a6c5e18f72c2f99829cc327abbcd846579ed16d3ecd7ed920624548e",
            "3fc2a19bbfec0e15b404242722fad30f824dfdade37315af055f51b88618fb9765556eaedd22ea4c884dc1e51e205e51b047a40e6c6d2f566762761977d58f82"},
        {852881,
            "541f810c7421dd8a1da1b620e2ad9200990155d4e616a963be7d0af21f1891be2d634c4d28c4cd56631ae71d0d728f57a634210b061842437d7c840a497a05dd",
            "e397d4be5cb5fc1611cce1f07172b8ca9202ccef90c0ba0fe236afb9cd535b50f19bc128a8f996837aa64dcbdd7345a06dfbe6bc278f3fd57829926c000672e7"},
        {6133492,
            "42bd69b29fa74b0ca55848f28ab8285b00cfb07af5f1091f6b5f72337f40639f45099cd68804b5790e64a4533af120da496fddca24475831c4dba61fc4a8b3b0",
            "84b858f4db6c06038ee38df5d1e395cd3141467618bd955fa911fa01a2056f4d14c077c408e6bf02b347c3d5667fada9ddef26522457b3513738737f22c3b0c4"},
        {6133493,
            "d235feb460cfde6e5523141ab84fabe1b4f5cae31bab5dee698d1c7bb2d7fffd3194a76299e81a9621714896041620f417342bb144b6b9499bd77d53e4a6c59f",
            "84c07fa63ec15cdab769d9ba8fcbeab3012817d6f982c10a004cfaa372f11f0b67a65fe509f629e681df354fd08c7820abf0714012b698266012bdad32a993c7"},
        {211322105,
            "c801c185e0931dc8ce4f773c16673246cc3fc78b2b3daf9aa81588d593f9ca51d2b6a1b3f3dfa813bba6f5dcd8ddeb91c83cc559610739bde756b4a3d3691e4f",
            "6d22e3ce654a1f87067ffa4fdf18b60c60a8d598f15aa2774f7c81032f72a3ff6cf1e2bcc9fbcf33738bc325ef070865ffc9fa0b64d3754fd00eef09222d8fef"},
        {740620450,
            "59f0f0b21ad3f3d6d06a55a9cfede463a97670e7c723a948c13182072a6e6199399e34c55e233960cea0cbccd2165d1a93ee62689d147833598434b72fc395eb",
            "410a7763aa1f180e9a737f8e92de4f487f477dff97d67e7f018a1ce8ebd1f958de5461e3af25c3c185e8f392590057befcdc1cea2ebb77e92c5f25a0d7c601fe"},
        {2147418082,  // Max index for epoch 32639.
            "a3d5eb0634e7365cccdc45ce67bbba6c468378efda61b5c414ecd4cd35d4b85e4ea12f9b56fc811c03a990b34cd5c325bd460bc6d9c9e3a0224da8a5073cb05c",
            "bb4f6a3732b08ac74e35dd0ade7076242cba621ca7638ff8c428fe435e4eef913b23bbd71fb1fbebc033f29ee904c7b868e0799b10ceb46ae31e30a9c785aeb2"},
        {0x7fffffff,  // Max allowed index value.
            "d96c881461d5ed6db5f8a630988bbed826d9ebabe48f40c03a02d09febf96d58ed11d58a4440e0e44a5e839d2ed8cf3cd434bec171cd3e24ecf4c6d1e5e1f177",
            "d99078774a6307bf06342ca1bc1827a3aef153c32ac958fb1a7db68b6524904bc635b529c198cc1238a4c19eb587679f0438b32191a7e47541d0bc51043b009d"},
    };
    // clang-format on

    // Mock the epoch context.
    auto context = create_epoch_context_mock(0);

    for (const auto& t : test_cases)
    {
        const hash1024 item1024 = calculate_dataset_item_1024(*context, t.index);
        EXPECT_EQ(to_hex(item1024.hash512s[0]), t.hash1_hex) << "index: " << t.index;
        EXPECT_EQ(to_hex(item1024.hash512s[1]), t.hash2_hex) << "index: " << t.index;
    }
}


TEST(xhash, dataset_items_epoch13)
{
    struct full_dataset_item_test_case
    {
        uint32_t index;
        const char* hash1_hex;
        const char* hash2_hex;
    };

    // clang-format off
    full_dataset_item_test_case test_cases[] = {
        {0,
            "e9c17d0340ae00062502c42ffeedfd25db195470a8373fe10592449e3b617b7f39607b988cd97142a323738d281ea5c1d2b59c1959731035e6c3c40ad6bd4a2b",
            "03565341645553633cc1b47b613fbd2e6fb0c44aee2942c80c414ebb5e5f011859a5fd5f372ba598ebe0878c6af178e1082fb4c4462ce1d37136d4ce5f695c4b"},
        {1,
            "7ca26b4b6c723e84fcbacecd30b282525bf1607b2ea54639ae5149f6fca6b98b7e697771222095f3df3844651af181cc99f761155c3413d234992fd2fbc4afe2",
            "86649d63b7f84e9da5e3af76aa1a64034a9845c5378568e0d5a3dfb1e8c966cd5e8b74236f554427985c9cafa3423cbe2f1bb7e376fd25ac4a9d14b82956f236"},
        {13,
            "5d5b18b95d7e7c6b3d6ed0002f88d76512418ac6f7a50fe903c2f0b439718bc0933b6b5eee4d38839ec497ab28b0c8f64e9726466a31301e4a216468af94b89b",
            "ecdb5aae7eca5637e23bdf2810b749cee22a7a8b251cdac9f03a75d3316895c07d41ed77715a86f79cc38d3a740c26f52b5cd5203fc4807c083af188038a0abb"},
        {171,
            "81c2f50a6f8f2f51743c33297af93d2942f4e95b7b55c63bfdc4845e0af5daef06804b26f6729d7ba6cb897a3eb6198c106534112ae527b25d77b610a5a56e94",
            "b1657ab18c2579311af2275adfe6009c78511e2e2f2acf1da9683a4e762600f2aa21c93a381c7f93603f2ce6f26e32ee5fe5d54fb22641021840c813442aef61"},
        {571,
            "71e791071dbff43da0e5b7d1691ab28329843ff86c5e79ffaebae11061363c16712d26c04095654d9957ec928cefe31818212f0f385d101c2c7f40996c8a8cbe",
            "005b8cf20ea77e5036d71b0f2bfe6b53f81b88f9710a4474cf6e3d026e3f0aecb4d4617268039ce99d6d5bb29b54dbbefc9cc68eba63061cfa7fcc830d574f7d"},
        {620,
            "10da9d2febc7d9e2acc961f4c8fa4d0f882a891ba613baca916075ec4f952dea054f61d0953dea3d7710ae96197f32315ba38dfc15d7fd337ce457732bd5891f",
            "5433baa621fa9405f36a6707ea21e0012bbf287d786f6e8b631b2d4c4b034b773963a3748e413775582e3caec35a8e5aa5f58a729ffcf00bb9b63deb7bc14cfd"},
        {514079,
            "9797cf39c74c1a56d99854834bd5db062183ee71cad66bbf984b59de972aadcd0dd2fa2b4e823a759987c58c86169bf3e923179c988e94221ca9e8cb05093762",
            "5e80774616ce45ec8e8d053df8e7d3d5b26e97a14f91105faee1c963376fefd0dd0971654d1305c939ee00970743c5c237ed7032de34ec3f82fb3f67aae832fd"},
        {852881,
            "dee6d890ee3420666bdbe8846ac8b2b0fe84b55bbed3ec2ca60da284c9a95eee0d59ac6d17b4fc1bb9a66450e89b11660657b25409eafec17c7b28dc18129fd9",
            "0a16249206eed0db4efcf5693b55349aa05f904665fb02463603383bb6a0d9ff8f1493e13fc0a37a5374c8e793b373c3f593b9897e9805e0f0bbd11f5d9bf800"},
        {6133492,
            "f41b76fa0b6baedb7cb16e8d2bc6517413875a4e1d5bbd3008ad14a44c6a98d52891b15881112e470d33e2a3a134e71eef6427e705846775b0f4ae05d1af3c24",
            "c1549115b84a45a8afd0a2c341e1b18a43ec988cadd7faade077dcaa91777e5c27b263eb158a92d1e365ac99e9d4c560d8f754f083519b33794d45e4443d0e1f"},
        {6133493,
            "2d86918df730a6b31ef323d218f6a23e7e2f15ea77268d90d6ec681253e7b1eea0dc2dce621ff6bac828aeef09ad161a312bb31041aa60fa2a255ee423709861",
            "aed77316b192e94737599435739faa2b11e69a3e7a6941aa6f6a51bad3dd848158f9292d6c29730efa088801aba710462f5400ff2adf66536f72493d7845ce6e"},
        {211322105,
            "4de951c62bc0059a4c2567162476275a4c20dfe6a889b2f29c43d4069b3c1b589be205187e7f4892e52bd764a28c339bc2695ef54050d7be5d7856dd37294e7d",
            "d07dd64024ffc6c3cb92f354b5104161f695c1f9c4b2fb313d63316e6a3a93105d47a5ae4edefcd2a5dd9655902fd387ee5b64da2352cb5ffff4f509ac07e508"},
        {740620450,
            "225a94508b50c8ae730fc8f2a8843e70b2b9904bbc8b170d3b2bf8e11bcbbbaa5e1201b943681d24db1e6bff0d4c4871b27bd5da49e4c460e57bdfc4403b2c91",
            "3b98105ab227f6024bd9deaa12973ecb084a1969b24c4941364ffc2dcc453f377611452b12fefc9f747f2f4e199b54cf967cd900021eb62cea3812bc90943a7d"},
        {2147418082,  // Max index for epoch 32639.
            "06f986b83aae7ff24025c405c1014d3aa3cc8a6ab20eb933cef266b10b747ad64e6a43cb1748740142f577923a11af2cd2896780a865c87f21ec24e9c5487e32",
            "b090512504a8f5e097792d41830d928cbbe6a4f1fe9c23b420b62b3f5d3e0753ae9073bbef1eccaf1d66d0b2c49183c91b62d2a5925cca37b359e6bef455756c"},
        {0x7fffffff,  // Max allowed index value.
            "72186ca1cc357f7269bd6776e471f8499234632b551ace0b20bddd41f4744d04dd700a4672bbe20ea577b356687719580c6b9d538da4f825551384145b9c52ce",
            "4de3f320c748510735b370d02e43aa7be061bf134deece724863894f7673403d7153efafe737786f5522106ec010ace9d466a6ae1f0f10c0a048f90f38824391"},
    };
    // clang-format on


    // Create example epoch context.
    const auto context = create_epoch_context(13);

    for (const auto& t : test_cases)
    {
        const hash1024 item = calculate_dataset_item_1024(*context, t.index);
        EXPECT_EQ(to_hex(item.hash512s[0]), t.hash1_hex) << "index: " << t.index;
        EXPECT_EQ(to_hex(item.hash512s[1]), t.hash2_hex) << "index: " << t.index;
    }
}

TEST(xhash, verify_hash_light)
{
    const hash256 zero{};
    const hash256 one = inc(zero);

    epoch_context_ptr context{nullptr, xhash_destroy_epoch_context};

    for (const auto& t : hash_test_cases)
    {
        const int epoch_number = t.block_number / epoch_length;
        const uint64_t nonce = std::stoull(t.nonce_hex, nullptr, 16);
        const hash256 header_hash = to_hash256(t.header_hash_hex);
        const hash256 mix_hash = to_hash256(t.mix_hash_hex);
        const hash256 boundary = to_hash256(t.final_hash_hex);
        const hash256 difficulty = xhash_difficulty_to_boundary(&boundary);

        if (!context || context->epoch_number != epoch_number)
            context = create_epoch_context(epoch_number);

        result r = hash(*context, header_hash, nonce);
        EXPECT_EQ(to_hex(r.final_hash), t.final_hash_hex);
        EXPECT_EQ(to_hex(r.mix_hash), t.mix_hash_hex);

        auto ec = verify_final_hash_against_difficulty(header_hash, mix_hash, nonce, difficulty);
        EXPECT_EQ(ec, XHASH_SUCCESS);
        EXPECT_FALSE(ec);
        EXPECT_EQ(ec.category(), xhash_category());

        ec = verify_final_hash_against_difficulty(header_hash, mix_hash, nonce, inc(difficulty));
        EXPECT_EQ(ec, XHASH_INVALID_FINAL_HASH);

        ec = verify_against_boundary(*context, header_hash, mix_hash, nonce, boundary);
        EXPECT_EQ(ec, XHASH_SUCCESS);

        ec = verify_against_boundary(*context, header_hash, mix_hash, nonce, dec(boundary));
        EXPECT_EQ(ec, XHASH_INVALID_FINAL_HASH);

        ec = verify_against_boundary(*context, header_hash, mix_hash, nonce, inc(boundary));
        EXPECT_EQ(ec, XHASH_SUCCESS);

        ec = verify_against_difficulty(*context, header_hash, mix_hash, nonce, difficulty);
        EXPECT_EQ(ec, XHASH_SUCCESS);

        ec = verify_against_difficulty(*context, header_hash, mix_hash, nonce, dec(difficulty));
        EXPECT_EQ(ec, XHASH_SUCCESS);

        ec = verify_against_difficulty(*context, header_hash, mix_hash, nonce, inc(difficulty));
        EXPECT_EQ(ec, XHASH_INVALID_FINAL_HASH);

        ec = verify_against_difficulty(*context, header_hash, mix_hash, nonce, zero);
        EXPECT_EQ(ec, XHASH_SUCCESS);

        ec = verify_against_difficulty(*context, header_hash, mix_hash, nonce, one);
        EXPECT_EQ(ec, XHASH_SUCCESS);

        const bool within_significant_boundary = r.final_hash.bytes[0] == 0;
        if (within_significant_boundary)
        {
            ec = verify_final_hash_against_difficulty(header_hash, mix_hash, nonce + 1, difficulty);
            EXPECT_EQ(ec, XHASH_INVALID_FINAL_HASH);

            ec = verify_against_boundary(*context, header_hash, mix_hash, nonce + 1, boundary);
            EXPECT_EQ(ec, XHASH_INVALID_FINAL_HASH);

            ec = verify_against_difficulty(*context, header_hash, mix_hash, nonce + 1, difficulty);
            EXPECT_EQ(ec, XHASH_INVALID_FINAL_HASH);
        }
        else
        {
            ec = verify_against_boundary(*context, header_hash, mix_hash, nonce + 1, boundary);
            EXPECT_EQ(ec, XHASH_INVALID_MIX_HASH);

            ec = verify_against_difficulty(*context, header_hash, mix_hash, nonce + 1, difficulty);
            EXPECT_EQ(ec, XHASH_INVALID_MIX_HASH);
        }
    }
}

TEST(xhash, verify_hash)
{
    epoch_context_full_ptr context{nullptr, xhash_destroy_epoch_context_full};

    for (const auto& t : hash_test_cases)
    {
        const int epoch_number = t.block_number / epoch_length;
        const uint64_t nonce = std::stoull(t.nonce_hex, nullptr, 16);
        const hash256 header_hash = to_hash256(t.header_hash_hex);

        const int full_dataset_num_items = calculate_full_dataset_num_items(epoch_number);
        const uint64_t full_dataset_size = get_full_dataset_size(full_dataset_num_items);

        if (!context || context->epoch_number != epoch_number)
            context = create_epoch_context_full(epoch_number);

        if (sizeof(void*) == 4)
        {
            // On 32-bit systems expect failures for allocations > 1GB of memory.
            static constexpr auto allocation_size_limit = uint64_t{1} * 1024 * 1024 * 1024;
            if (!context && full_dataset_size > allocation_size_limit)
                continue;
        }

        ASSERT_NE(context, nullptr) << full_dataset_size;
        EXPECT_GT(full_dataset_size, 0);

        result r = hash(*context, header_hash, nonce);
        EXPECT_EQ(to_hex(r.final_hash), t.final_hash_hex);
        EXPECT_EQ(to_hex(r.mix_hash), t.mix_hash_hex);
    }
}

TEST(xhash, verify_final_hash_only)
{
    auto& context = get_xhash_epoch_context_0();
    const hash256 header_hash = {};
    const hash256 mix_hash = {};
    uint64_t nonce = 36411953;
    const hash256 difficulty =
        to_hash256("0000000000000000000000000000000000000000000000000000000006cecc04");

    EXPECT_EQ(verify_final_hash_against_difficulty(header_hash, mix_hash, nonce, difficulty),
        XHASH_SUCCESS);
    EXPECT_EQ(verify_against_difficulty(context, header_hash, mix_hash, nonce, difficulty),
        XHASH_INVALID_MIX_HASH);
}

TEST(xhash, verify_boundary)
{
    const auto& context = get_xhash_epoch_context_0();
    const hash256 example_header_hash =
        to_hash256("e74e5e8688d3c6f17885fa5e64eb6718046b57895a2a24c593593070ab71f5fd");
    const uint64_t nonce = 6666;
    const auto r = hash(context, example_header_hash, nonce);
    const auto boundary_eq =
        to_hash256("3020cdf1e3dc9ff5d914be2b2060a4b0f7d666310ccceeb4b0fd3f1ac4c4d1a6");

    const auto boundary_gt = inc(boundary_eq);
    EXPECT_EQ(
        to_hex(boundary_gt), "3020cdf1e3dc9ff5d914be2b2060a4b0f7d666310ccceeb4b0fd3f1ac4c4d1a7");

    const auto boundary_lt = dec(boundary_eq);
    EXPECT_EQ(
        to_hex(boundary_lt), "3020cdf1e3dc9ff5d914be2b2060a4b0f7d666310ccceeb4b0fd3f1ac4c4d1a5");

    EXPECT_EQ(r.final_hash, boundary_eq);
    EXPECT_EQ(to_hex(r.final_hash), to_hex(boundary_eq));

    EXPECT_EQ(verify_against_boundary(context, example_header_hash, r.mix_hash, nonce, boundary_eq),
        XHASH_SUCCESS);
    EXPECT_EQ(verify_against_boundary(context, example_header_hash, r.mix_hash, nonce, boundary_gt),
        XHASH_SUCCESS);
    EXPECT_EQ(verify_against_boundary(context, example_header_hash, r.mix_hash, nonce, boundary_lt),
        XHASH_INVALID_FINAL_HASH);
}

TEST(xhash_multithreaded, small_dataset)
{
    // This test creates a tiny dataset for full search to discover sync issues between threads.

    constexpr size_t num_treads = 8;
    constexpr int num_dataset_items = 501;
    const hash256 boundary =
        to_hash256("0004000000000000000000000000000000000000000000000000000000000000");

    auto context = create_epoch_context_mock(0);
    const_cast<int&>(context->full_dataset_num_items) = num_dataset_items;

    std::unique_ptr<hash1024[]> full_dataset{new hash1024[num_dataset_items]{}};
    reinterpret_cast<test_context_full*>(context.get())->full_dataset = full_dataset.get();
    auto context_full = reinterpret_cast<epoch_context_full*>(context.get());

    std::array<std::future<search_result>, num_treads> futures;
    for (auto& f : futures)
    {
        f = std::async(
            std::launch::async, [&] { return search(*context_full, {}, boundary, 50000, 10000); });
    }

    for (auto& f : futures)
        EXPECT_EQ(f.get().nonce, 58271);
}

TEST(xhash, small_dataset)
{
    constexpr int num_dataset_items = 501;
    const hash256 boundary =
        to_hash256("0080000000000000000000000000000000000000000000000000000000000000");

    auto context = create_epoch_context_mock(0);
    const_cast<int&>(context->full_dataset_num_items) = num_dataset_items;

    std::unique_ptr<hash1024[]> full_dataset{new hash1024[num_dataset_items]{}};
    reinterpret_cast<test_context_full*>(context.get())->full_dataset = full_dataset.get();
    auto context_full = reinterpret_cast<epoch_context_full*>(context.get());

    auto solution = search_light(*context, {}, boundary, 1415, 10);
    EXPECT_TRUE(solution.solution_found);
    EXPECT_EQ(solution.nonce, 1420);
    const auto final_hash_hex = "00045dbb4b9526ced07a04dd4097224d72b48c0573d50d62a69a58a4bb80c074";
    EXPECT_EQ(to_hex(solution.final_hash), final_hash_hex);
    const auto mix_hash_hex = "32049005a71dffd2c3d89fb4fa4e59d4322fe9b1d85639dbd6f26d7322ff8c5f";
    EXPECT_EQ(to_hex(solution.mix_hash), mix_hash_hex);

    solution = search(*context_full, {}, boundary, 1415, 10);
    EXPECT_TRUE(solution.solution_found);
    EXPECT_EQ(solution.nonce, 1420);
    EXPECT_EQ(to_hex(solution.final_hash), final_hash_hex);
    EXPECT_EQ(to_hex(solution.mix_hash), mix_hash_hex);

    solution = search_light(*context, {}, boundary, 483, 10);
    EXPECT_FALSE(solution.solution_found);
    EXPECT_EQ(solution.final_hash, hash256{});
    EXPECT_EQ(solution.mix_hash, hash256{});
    EXPECT_EQ(solution.nonce, 0);

    solution = search(*context_full, {}, boundary, 483, 10);
    EXPECT_FALSE(solution.solution_found);
    EXPECT_EQ(solution.final_hash, hash256{});
    EXPECT_EQ(solution.mix_hash, hash256{});
    EXPECT_EQ(solution.nonce, 0);
}

#ifndef __APPLE__

// The Out-Of-Memory tests try to allocate huge memory buffers. This fails on
// Linux and Windows, but not on macOS. Because the macOS tries too hard
// the tests go forever.
// The tests are disabled on macOS at compile time (instead of using GTest
// filter) because we don't want developers using macOS to be hit by this
// behavior.

#ifdef __linux__
#include <sys/resource.h>

namespace
{
rlimit orig_limit;

bool set_memory_limit(size_t size)
{
    getrlimit(RLIMIT_AS, &orig_limit);
    rlimit limit = orig_limit;
    limit.rlim_cur = size;
    return setrlimit(RLIMIT_AS, &limit) == 0;
}

bool restore_memory_limit()
{
    return setrlimit(RLIMIT_AS, &orig_limit) == 0;
}
}  // namespace

#else

namespace
{
bool set_memory_limit(size_t)
{
    return true;
}

bool restore_memory_limit()
{
    return true;
}
}  // namespace

#endif

static constexpr bool arch64bit = sizeof(void*) == 8;

TEST(xhash, create_context_oom)
{
    static constexpr int epoch = arch64bit ? 3000 : 300;
    static constexpr size_t expected_size = arch64bit ? 26239565696 : 3590324096;
    const int num_items = calculate_full_dataset_num_items(epoch);
    const uint64_t full_dataset_size = get_full_dataset_size(num_items);
    const size_t size = static_cast<size_t>(full_dataset_size);
    ASSERT_EQ(size, full_dataset_size);
    ASSERT_EQ(size, expected_size);

    ASSERT_TRUE(set_memory_limit(1024 * 1024 * 1024));
    auto* context = xhash_create_epoch_context_full(epoch);
    ASSERT_TRUE(restore_memory_limit());
    EXPECT_EQ(context, nullptr);
}
#endif

namespace
{
struct less_equal_test_case
{
    const char* a_hex;
    const char* b_hex;
    bool expected_result;
};

less_equal_test_case less_equal_test_cases[] = {
    {"0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000", true},
    {"0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000000", false},
    {"0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001", true},
    {"0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000100", true},
    {"1000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001", false},
    {"1000000000000000000000000000000000000000000000000000000000000000",
        "0010000000000000000000000000000000000000000000000000000000000000", false},
    {"0000000000000000000000000010000000000000000000000000000000000000",
        "0000000000000000000000000001000000000000000000000000000000000000", false},
    {"0000000000000000000000000010000000000000000000000000000000000000",
        "0000000000000000000000000010000000000000000000000000000000000000", true},
    {"1000000000000000000000000000000000000000000000000000000000000001",
        "1000000000000000000000000000000000000000000000000000000000000002", true},
    {"2000000000000000000000000000000000000000000000000000000000000001",
        "1000000000000000000000000000000000000000000000000000000000000002", false},
    {"1000000000000000000000000000000000000000000000000000000000000000",
        "2000000000000000000000000000000000000000000000000000000000000000", true},
    {"1000000000000000200000000000000000000000000000000000000000000000",
        "2000000000000000100000000000000000000000000000000000000000000000", true},
    {"aaaaaaaaaaaaaaaa100000000000000000000000000000000000000000000000",
        "aaaaaaaaaaaaaaaa100000000000000000000000000000000000000000000000", true},
    {"aaaaaaaaaaaaaaaa100000000000000000000000000000000000000000000000",
        "aaaaaaaaaaaaaaaa200000000000000000000000000000000000000000000000", true},
    {"aaaaaaaaaaaaaaaa200000000000000000000000000000000000000000000000",
        "aaaaaaaaaaaaaaaa100000000000000000000000000000000000000000000000", false},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa10000000000000000000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa10000000000000000000000000000000", true},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa10000000000000000000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa20000000000000000000000000000000", true},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa20000000000000000000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa10000000000000000000000000000000", false},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1000000000000000", true},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2000000000000000", true},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1000000000000000", false},
};
}  // namespace

TEST(xhash, less_equal)
{
    for (const auto& t : less_equal_test_cases)
    {
        auto a = to_hash256(t.a_hex);
        auto b = to_hash256(t.b_hex);
        EXPECT_EQ(less_equal(a, b), t.expected_result);
    }
}

TEST(xhash, inc)
{
    const auto t = [](const char* s) { return to_hex(inc(to_hash256(s))); };

    EXPECT_EQ(t("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        "0000000000000000000000000000000000000000000000000000000000000000");
    EXPECT_EQ(t("0000000000000000000000000000000000000000000000000000000000000000"),
        "0000000000000000000000000000000000000000000000000000000000000001");
    EXPECT_EQ(t("000000000000000000000000000000000000000000000000ffffffffffffffff"),
        "0000000000000000000000000000000000000000000000010000000000000000");
    EXPECT_EQ(t("00000000000000000000000000000000ffffffffffffffffffffffffffffffff"),
        "0000000000000000000000000000000100000000000000000000000000000000");
    EXPECT_EQ(t("0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff"),
        "0000000000000001000000000000000000000000000000000000000000000000");
    EXPECT_EQ(t("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        "1000000000000000000000000000000000000000000000000000000000000000");
    EXPECT_EQ(t("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"),
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
}

TEST(xhash, dec)
{
    const auto t = [](const char* s) { return to_hex(dec(to_hash256(s))); };

    EXPECT_EQ(t("0000000000000000000000000000000000000000000000000000000000000000"),
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    EXPECT_EQ(t("0000000000000000000000000000000000000000000000000000000000000001"),
        "0000000000000000000000000000000000000000000000000000000000000000");
    EXPECT_EQ(t("0000000000000000000000000000000000000000000000010000000000000000"),
        "000000000000000000000000000000000000000000000000ffffffffffffffff");
    EXPECT_EQ(t("0000000000000000000000000000000100000000000000000000000000000000"),
        "00000000000000000000000000000000ffffffffffffffffffffffffffffffff");
    EXPECT_EQ(t("0000000000000001000000000000000000000000000000000000000000000000"),
        "0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff");
    EXPECT_EQ(t("1000000000000000000000000000000000000000000000000000000000000000"),
        "0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    EXPECT_EQ(t("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
}
