// XHash: C/C++ implementation of XHash, the Ethereum Proof of Work algorithm.
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

/// @file
/// Shared test cases.

#pragma once

// Put in anonymous namespace to allow be include in multiple files
// but also make iteration over test cases easy with range-based for loop.
namespace
{
struct hash_test_case
{
    int block_number;
    const char* header_hash_hex;
    const char* nonce_hex;
    const char* mix_hash_hex;
    const char* final_hash_hex;
};

// NOLINTNEXTLINE(misc-definitions-in-headers)
hash_test_case hash_test_cases[] = {
    {
        0,
        "2a8de2adf89af77358250bf908bf04ba94a6e8c3ba87775564a41d269a05e4ce",
        "4242424242424242",
        "761b72420f69ac3ee622e35f6a6aeb5caff5fe3c41b0a002cc1504107dcfec24",
        "4c95f631745bdf9f26299d9f49749e8fd2e420edcc36cfcb2b6eb0d2ccfbceca",
    },
    {
        2,
        "100cbec5e5ef82991290d0d93d758f19082e71f234cf479192a8b94df6da6bfe",
        "307692cf71b12f6d",
        "2d12a4555976e410f9989672f6d7b38d2f20733d8d2d8b36a1863fc51568a0b3",
        "7913bb30f11bbf36a162338dbee4ccc51894d43792d9234a1336e3dee9ca803e",
    },
    {
        64080,
        "0313d03c5ed78694c90ecb3d04190b82d5b222c75ba4cab83383dde4d11ed512",
        "8c5eaec00079f2f4",
        "894e795040ce97f361f56baece55ff7c90cf2fd19b1555ad570980a867e0a034",
        "0000beeb2ad5bf3445901d2f3fd25f8e5eb80a10442a010c4f908f6a9328e701",
    },
    {
        119520,
        "bc544c2baba832600013bd5d1983f592e9557d04b0fb5ef7a100434a5fc8d52a",
        "4617a20003bae4a1",
        "35d1347b6a85a25ef635b30bc4b3d0760721027972ca2cae506e08a909debcd3",
        "0000e30ba4a3ab15139ef938d07668e144dd54315fd0578f528c4feb993a8e5f",
    },
    {
        119521,
        "2cd14041cfc3bd13064cfd58e26c0bddf1e97a4202c4b8076444a7cd4515f8c3",
        "1af47f200792524e",
        "18c6e17ecb82b5626102919c6548e97561a3337937a4a5ab7cf7573c9dfe90c9",
        "0000710fa52fed8237d30367d8447a54eeb73b2eb3c18b40d983f54c0b69106d",
    },
    {
        119522,
        "9e79bced19062baf7c47e516ad3a1bd779222404d05b4205def30a13c7d87b5b",
        "c9a044201dd9d02c",
        "1955da00efb8d14c7e03093ef5246f2e73dc87c018c5e133a9f1993c91557149",
        "000077896dcb6cf6c2972ae3695ca8142969ac41909e6eeab51f5225f7738fdb",
    },
    {
        126720,
        "53a005f209a4dc013f022a5078c6b38ced76e767a30367ff64725f23ec652a9f",
        "d337f82001e9cb5b",
        "84cacc7d3ca43eeee2e5330967e2a8ed2b3cd4bc73b72afa3fddf65359a59cad",
        "0000721f8232f88e96e76b14c99e864098baa819e8a5ae4a1f4529b522318041",
    },
};
}  // namespace
