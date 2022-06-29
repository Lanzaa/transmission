// License

#pragma once

#include <algorithm>
#include <cstdint> // uint32_t, uint64_t
#include <optional>
#include <string_view>
#include <vector>

#include "crypto-utils.h"
#include "transmission.h"

/**
 * related: BEP-0052 http://www.bittorrent.org/beps/bep_0052.html
 *
 * Merkle tree related operations.
 */

/**
 * A layer needs to know how much data is represented, this is accomplished by including it's layer number.
 *
 * By knowing the layer number we can leave out extra hashes which represent no data.
 * layer 0 corresponds to the leaf hashes of the merkle tree
 * layer 1 corresponds to the layer above layer 0, etc
 */
using merkle_layer = std::pair<uint, std::vector<tr_sha256_digest_t>>;

// Set a MAX_LAYER just in case to avoid forever looping
constexpr int MAX_LAYER = 100; // 16*1024 * 2**(MAX_LAYER) is the max size we will handle

// The empty merkle tree hash is all zeros
constexpr tr_sha256_digest_t EMPTY_MERKLE_HASH = {};

/**
 * @brief hashBlock - hashes a single leaf block. size must be <= 16 KiB
 */
template<typename T>
static std::optional<tr_sha256_digest_t> hashBlock(T arg)
{
    auto length = std::size(arg);
    if (length == 0)
    {
        return EMPTY_MERKLE_HASH;
    }
    //assert(length <= 16 * 1024);  // This function works on a single block
    return tr_sha256(arg);
}

/**
 * @brief merkle_empty_hash Generate a hash which represents a merkle tree with no data at the given layer
 */
tr_sha256_digest_t merkle_empty_hash(uint layer);

// Each entry is [root, layer_hashes]
using piece_layer_entry = std::pair<tr_sha256_digest_t, std::vector<tr_sha256_digest_t>>;

/**
 * @brief parsePieceLayers Parse the string_views for a piece layers entry
 */
std::optional<piece_layer_entry> parsePieceLayersEntry(std::string_view k, std::string_view vs);

/**
 * @brief reduceMerkleLayerTo Reduce this layer of the merkle tree to a higher layer
 */
merkle_layer reduceMerkleLayerTo(uint layer_number, merkle_layer const& in);

/**
 * @brief reduceMerkleLayerToRoot Reduce this layer of the merkle tree al the way to the root hash
 * @return root_hash of the merkle tree
 */
tr_sha256_digest_t reduceMerkleLayerToRoot(merkle_layer const& in);

/**
 * @brief validatePieceLayers
 *
 *  TODO
 */
bool validatePieceLayers(tr_sha256_digest_t root, merkle_layer const& layer);

/**
 * @brief calculateLayerNumber - find which layer in the merkle tree the piece size corresponds to
 * @param piece_length - should be a power of two larger than 16 KiB
 */
std::optional<uint> calculateLayerNumber(int64_t piece_length);
