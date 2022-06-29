// License ?

#include <array>
#include <cstring>
#include <optional>
#include <string_view>

#include "crypto-utils.h"
#include "merkle.h"
#include "test-fixtures.h"

using namespace std::literals;

namespace libtransmission
{
namespace test
{

TEST(MerkleTreeTest, hashSimpleBlocks)
{
    // Leaf hashes (L0) can be full, partial, or empty.
    auto f = hashBlock(std::string{ "hello world" });
    auto e = tr_sha256_from_string("B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9");
    EXPECT_EQ(f, e);

    // Empty -> just a zero hash
    EXPECT_EQ(hashBlock(std::array<char, 0>{}), EMPTY_MERKLE_HASH);

    std::array<char, 16384> buf = {};
    // All 0
    auto f0 = hashBlock(buf);
    auto e0 = tr_sha256_from_string("4fe7b59af6de3b665b67788cc2f99892ab827efae3a467342b3bb4e3bc8e5bfe");
    EXPECT_EQ(f0, e0);

    // All '1'
    buf.fill('1');
    auto f1 = hashBlock(buf);
    auto e1 = tr_sha256_from_string("a0819c70c286c7bf0a12eb9e7d958db95e0f4812766609406ced2053ba271df8");
    EXPECT_EQ(f1, e1);

    // All 2
    buf.fill(2);
    auto f2 = hashBlock(buf);
    auto e2 = tr_sha256_from_string("746664dba900c81ef311c8456e15b02a5efeee3736a4f3827ce1eb1e0c24d8da");
    EXPECT_EQ(f2, e2);
    //auto const src_filename = tr_pathbuf{ LIBTRANSMISSION_TEST_ASSETS_DI
}

TEST(MerkleTreeTest, validateSomeEmptyHashes)
{
    // Lowest level is empty hash
    auto l0 = merkle_empty_hash(0);
    EXPECT_EQ(l0, EMPTY_MERKLE_HASH);

    // Should be able to advance
    auto l1 = merkle_empty_hash(1);
    EXPECT_EQ(l1, tr_sha256_from_string("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"sv));

    // Should be able to skip ahead without trouble
    auto l7 = merkle_empty_hash(7);
    EXPECT_EQ(l7, tr_sha256_from_string("87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"sv));
}

TEST(MerkleTreeTest, catchInvalidPieceLayersParse)
{
    using test_case = struct
    {
        std::string_view key;
        std::string_view values;
    };
    static auto constexpr Tests = std::array<test_case, 3>{
        // Simplest parseable test_case {"jjHTD54lxjNnaOl4JhIZyKnui6gfG/igfYuEZkQozMY="sv, ""sv},
        // Need to catch these issues:
        // bad key
        test_case{ "badkey=="sv, ""sv },
        // no key
        test_case{ ""sv, ""sv },
        // bad length for values
        test_case{ "jjHTD54lxjNnaOl4JhIZyKnui6gfG/igfYuEZkQozMY="sv, "badpiecelayers=="sv },
    };

    for (auto const& test : Tests)
    {
        auto ks = tr_base64_decode(test.key);
        auto vs = tr_base64_decode(test.values);
        auto r = parsePieceLayersEntry(ks, vs);
        EXPECT_FALSE(r);
    }
}

TEST(MerkleTreeTest, validatePieceLayers)
{
    using test_case = struct
    {
        int layer;
        std::string_view key;
        std::string_view values;
    };
    static auto constexpr Tests = std::array<test_case, 3>{
        // These have a piece length of 4 MiB => layer 8
        test_case{ 8,
                   "jjHTD54lxjNnaOl4JhIZyKnui6gfG/igfYuEZkQozMY="sv,
                   "6Rdd2Fu7yzUND0cRRVT/FL3wQwuD3nJxrx+MYQPt7JT/ABBrhlpdWYRGTPKLLT42M00OPco1T2vYY5OdXU4hnA=="sv },
        test_case{
            8,
            "gf0/7MXGw52wVukbfHO9e7EewgEaIQhGNMAb/iQF6vk="sv,
            "t7OpV+gNtijQ1J91aRFX2o57EKe42zd+pfEdl+ESSBxMyWGnNL24pe4MCm6GnS+iFWGYcK2tpcjX+sBPxQpwWarWlSMkFhBKhFzBLFIBVomBZGjlJ1RE1zrxA0z4JP5cZZxwmTeniGa6twe9p1YZKo6M535xfsS73g1nMkuBloWV8u8tEixSj/6x5MuAlMWTXfOJp8fx+VKDcByqSU9DmTV+w6TjSi6zanMaHYEJgDtY76uTkwViVjFJafw/Q4dZrs4X+hIPuGvidOV5FOys5rVfAShTZVGcoDVjMoikyAc="sv },
        test_case{
            8,
            "6z/eX8647aJV2y8higzsrJVxdc1USoOwKGUP1ER6F5E="sv,
            "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"sv },
    };

    for (auto const& test : Tests)
    {
        auto ks = tr_base64_decode(test.key);
        auto vs = tr_base64_decode(test.values);
        auto kv = parsePieceLayersEntry(ks, vs);
        EXPECT_TRUE(kv); // Expecting parse ok
        tr_sha256_digest_t root = kv.value().first;
        std::vector<tr_sha256_digest_t> hashes = kv.value().second;
        merkle_layer ml = { test.layer, hashes };

        EXPECT_TRUE(validatePieceLayers(root, ml));
    }
}

TEST(MerkleTreeTest, catchInvalidPieceLayersHash)
{
    using test_case = struct
    {
        int layer;
        std::string_view key;
        std::string_view values;
    };
    static auto constexpr Tests = std::array<test_case, 3>{
        // These have a piece length of 4 MiB => layer 8
        test_case{ 8,
                   "zzzzD54lxjNnaOl4JhIZyKnui6gfG/igfYuEZkQozMY="sv,
                   "6Rdd2Fu7yzUND0cRRVT/FL3wQwuD3nJxrx+MYQPt7JT/ABBrhlpdWYRGTPKLLT42M00OPco1T2vYY5OdXU4hnA=="sv },
        test_case{
            8,
            "zzzz7MXGw52wVukbfHO9e7EewgEaIQhGNMAb/iQF6vk="sv,
            "t7OpV+gNtijQ1J91aRFX2o57EKe42zd+pfEdl+ESSBxMyWGnNL24pe4MCm6GnS+iFWGYcK2tpcjX+sBPxQpwWarWlSMkFhBKhFzBLFIBVomBZGjlJ1RE1zrxA0z4JP5cZZxwmTeniGa6twe9p1YZKo6M535xfsS73g1nMkuBloWV8u8tEixSj/6x5MuAlMWTXfOJp8fx+VKDcByqSU9DmTV+w6TjSi6zanMaHYEJgDtY76uTkwViVjFJafw/Q4dZrs4X+hIPuGvidOV5FOys5rVfAShTZVGcoDVjMoikyAc="sv },
        test_case{
            8,
            "zzzzX8647aJV2y8higzsrJVxdc1USoOwKGUP1ER6F5E="sv,
            "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"sv },
    };

    for (auto const& test : Tests)
    {
        auto ks = tr_base64_decode(test.key);
        auto vs = tr_base64_decode(test.values);
        auto kv = parsePieceLayersEntry(ks, vs);
        EXPECT_TRUE(kv); // Expecting parse ok
        tr_sha256_digest_t root = kv.value().first;
        std::vector<tr_sha256_digest_t> hashes = kv.value().second;
        merkle_layer ml = { test.layer, hashes };

        EXPECT_FALSE(validatePieceLayers(root, ml));
    }
}

TEST(MerkleTreeTest, discernLayerFromPieceSize)
{
    using test_case = struct
    {
        std::optional<uint> layer_expected;
        int64_t piece_size;
    };
    static auto constexpr Tests = std::array<test_case, 5>{
        test_case{ 0, 16 * 1024 },
        test_case{ 8, 4 * 1024 * 1024 },
        test_case{ 9, 8 * 1024 * 1024 },
        test_case{ {}, 8 * 1024 }, // fail, too small
        test_case{ {}, 8 * 1024 * 1024 + 1 }, // fail, not power of two
    };

    for (auto const& test : Tests)
    {
        EXPECT_EQ(test.layer_expected, calculateLayerNumber(test.piece_size));
    }
}

} // namespace test
} // namespace libtransmission
