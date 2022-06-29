// License ?

#include "merkle.h"

tr_sha256_digest_t merkle_empty_hash(uint layer)
{
    static std::vector<tr_sha256_digest_t> empty_hashes = { EMPTY_MERKLE_HASH };

    // Expand memo'd hash list if needed
    while (layer >= empty_hashes.size())
    {
        auto h = tr_sha256(empty_hashes.back(), empty_hashes.back());
        if (h)
        {
            empty_hashes.push_back(h.value());
        }
        else
        {
            // ? not sure how this failed
        }
    }
    return empty_hashes[layer];
}

std::optional<piece_layer_entry> parsePieceLayersEntry(std::string_view k, std::string_view vs)
{
    auto y = tr_sha256_from_raw(k);

    if (!y || std::size(vs) % TR_SHA256_DIGEST_LEN != 0)
    {
        return {};  // k needs to be a hash and vs size needs to be a multiple of the digest size
    }

    auto const n = std::size(vs) / sizeof(tr_sha256_digest_t);
    std::vector<tr_sha256_digest_t> hashes = {};
    hashes.resize(n);
    std::copy_n(std::data(vs), std::size(vs), reinterpret_cast<char*>(std::data(hashes)));
    return std::pair {y.value(), hashes};
}

/**
 * @brief reduceMerkleLayer Generate the next layer of merkle hashes
 */
std::vector<tr_sha256_digest_t> reduceMerkleLayer(int layer_number, std::vector<tr_sha256_digest_t> in)
{
    std::vector<tr_sha256_digest_t> out = {};
    out.reserve((in.size()+1)/2);
    // TODO it probably makes sense to do this reduction in place.

    for (std::size_t i = 0; i < in.size(); i+=2)
    {
        tr_sha256_digest_t l = in[i];
        tr_sha256_digest_t r = merkle_empty_hash(layer_number);
        if (i + 1 < in.size())
        {
            r = in[i+1];
        }

        auto p = tr_sha256(l, r);
        if (p)
        {
            out.push_back(p.value());
        }
        else
        {
            return {};  // FAIL !?!?
        }
    }
    return out;
}

merkle_layer reduceMerkleLayerTo(uint layer_number, merkle_layer const& in)
{
    std::vector<tr_sha256_digest_t> a = in.second;
    std::vector<tr_sha256_digest_t> out (a);
    for (auto cur_layer = in.first; cur_layer < layer_number; cur_layer++)
    {
        out = reduceMerkleLayer(cur_layer, out);
    }
    return {layer_number, out};
}

tr_sha256_digest_t reduceMerkleLayerToRoot(merkle_layer const& in)
{
    std::vector<tr_sha256_digest_t> a = in.second;
    std::vector<tr_sha256_digest_t> out = (a);
    for (auto cur_layer = in.first; cur_layer < MAX_LAYER && out.size() > 1; cur_layer++)
    {
        out = reduceMerkleLayer(cur_layer, out);
    }
    if (out.size() != 1)
    {
        // FAIL !?!?
        // this could happen right now because of the max layer thing
    }
    return out[0];
}

bool validatePieceLayers(tr_sha256_digest_t root, merkle_layer const& layer)
{
    auto found_root = reduceMerkleLayerToRoot(layer);
    return root == found_root;
}

std::optional<uint> calculateLayerNumber(int64_t piece_length)
{
    int64_t bigga = 1 << 14; // Start at 2^14 == 16 KiB
    uint offset = 0;
    // 17 not 32, don't want to overflow int64_t
    if ((bigga << (17+offset)) <= piece_length)
    {
        offset += 17;
    }
    if ((bigga << (16+offset)) <= piece_length)
    {
        offset += 16;
    }
    if ((bigga << (8+offset)) <= piece_length)
    {
        offset += 8;
    }
    if ((bigga << (4+offset)) <= piece_length)
    {
        offset += 4;
    }
    if ((bigga << (2+offset)) <= piece_length)
    {
        offset += 2;
    }
    if ((bigga << (1+offset)) <= piece_length)
    {
        offset += 1;
    }

    if ((bigga << offset) == piece_length)
    {
        return offset;
    }
    return {}; // not a power of 2 < 2^63 == 8 EiB. No one wants EiB size pieces... yet
}
