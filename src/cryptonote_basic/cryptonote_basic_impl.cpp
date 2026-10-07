// Copyright (c) 2014-2024, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "cryptonote_basic_impl.h"
#include "string_tools.h"
#include "serialization/binary_utils.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "common/base58.h"
#include "crypto/hash.h"
#include "ringct/rctOps.h"
#include "int-util.h"
#include "common/dns_utils.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

using namespace epee;

namespace cryptonote {

  struct integrated_address {
    account_public_address adr;
    crypto::hash8 payment_id;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(adr)
      FIELD(payment_id)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(adr)
      KV_SERIALIZE(payment_id)
    END_KV_SERIALIZE_MAP()
  };

  /************************************************************************/
  /* Cryptonote helper functions                                          */
  /************************************************************************/
  //-----------------------------------------------------------------------------------------------
  size_t get_min_block_weight(uint8_t version)
  {
    if (version < 2)
      return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
    if (version < 5)
      return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2;
    return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  }
  //-----------------------------------------------------------------------------------------------
  size_t get_max_tx_size()
  {
    return CRYPTONOTE_MAX_TX_SIZE;
  }
  //-----------------------------------------------------------------------------------------------
  //-----------------------------------------------------------------------------------------------
  // Galimi v17 emission curve, anchored at three points:
  //   r = 255 (difficulty 1)            -> 255 GAL (maximum)
  //   r = 216 (Monero-scale difficulty) -> 128 GAL
  //   r = 0   (extreme difficulty)      ->   1 GAL (minimum)
  // R(r) = floor(1 + 254 * (r/255)^4.17596), r = floor(log2(target)).
  // Pure function of current difficulty: the reward falls when difficulty rises
  // and rises again when difficulty falls (no ratchet, no memory).
  // No floating point in consensus code: deterministic uint8 lookup table.
static const uint8_t GALIMI_CURVE[256] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 5,
    5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8,
    9, 9, 9, 10, 10, 10, 11, 11, 11, 12, 12, 13, 13, 13, 14, 14,
    15, 15, 16, 16, 17, 17, 18, 18, 19, 19, 20, 21, 21, 22, 23, 23,
    24, 25, 25, 26, 27, 27, 28, 29, 30, 31, 31, 32, 33, 34, 35, 36,
    37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 50, 51, 52, 53,
    54, 56, 57, 58, 60, 61, 63, 64, 66, 67, 69, 70, 72, 73, 75, 76,
    78, 80, 82, 83, 85, 87, 89, 91, 93, 95, 97, 99, 101, 103, 105, 107,
    109, 111, 113, 116, 118, 120, 123, 125, 128, 130, 132, 135, 138, 140, 143, 146,
    148, 151, 154, 157, 160, 163, 166, 169, 172, 175, 178, 181, 184, 188, 191, 194,
    198, 201, 205, 208, 212, 215, 219, 223, 227, 230, 234, 238, 242, 246, 250, 255,
};
  bool get_block_reward(size_t median_weight, size_t current_block_weight, uint64_t already_generated_coins, uint64_t &reward, uint8_t version, difficulty_type difficulty) {
    (void)already_generated_coins; // Galimi: the block reward is a function of the difficulty target, not of coins emitted so far
    // Galimi tokenomics: base_reward = floor(log2(target)) * COIN, where target = (2^256 - 1) / difficulty.
    // Computed with exact integer arithmetic (msb of the 256-bit target): deterministic on every node.
    // Properties: perpetual (target >= 1 for any real difficulty, so the reward never reaches zero),
    // and self-regulating (more hashrate -> higher difficulty -> lower target -> smaller reward).
    if (difficulty == 0)
      difficulty = 1;
    const boost::multiprecision::cpp_int max_target = (boost::multiprecision::cpp_int(1) << 256) - 1;
    const boost::multiprecision::cpp_int target = max_target / difficulty;
    const unsigned int log2_target = boost::multiprecision::msb(target); // floor(log2(target)); 255 at difficulty 1
    unsigned int reward_units = log2_target;
    if (version >= 17) // Galimi v17 (hardfork at height 100): anchored emission curve
      reward_units = GALIMI_CURVE[reward_units];
    uint64_t base_reward = (uint64_t)reward_units * COIN;

    uint64_t full_reward_zone = get_min_block_weight(version);

    //make it soft
    if (median_weight < full_reward_zone) {
      median_weight = full_reward_zone;
    }

    if (current_block_weight <= median_weight) {
      reward = base_reward;
      return true;
    }

    if(current_block_weight > 2 * median_weight) {
      MERROR("Block cumulative weight is too big: " << current_block_weight << ", expected less than " << 2 * median_weight);
      return false;
    }

    uint64_t product_hi;
    // BUGFIX: 32-bit saturation bug (e.g. ARM7), the result was being
    // treated as 32-bit by default.
    uint64_t multiplicand = 2 * median_weight - current_block_weight;
    multiplicand *= current_block_weight;
    uint64_t product_lo = mul128(base_reward, multiplicand, &product_hi);

    uint64_t reward_hi;
    uint64_t reward_lo;
    div128_64(product_hi, product_lo, median_weight, &reward_hi, &reward_lo, NULL, NULL);
    div128_64(reward_hi, reward_lo, median_weight, &reward_hi, &reward_lo, NULL, NULL);
    assert(0 == reward_hi);
    assert(reward_lo < base_reward);

    reward = reward_lo;
    return true;
  }
  //------------------------------------------------------------------------------------
  std::string get_account_address_as_str(
      network_type nettype
    , bool subaddress
    , account_public_address const & adr
    )
  {
    uint64_t address_prefix = subaddress ? get_config(nettype).CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : get_config(nettype).CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;

    return tools::base58::encode_addr(address_prefix, t_serializable_object_to_blob(adr));
  }
  //-----------------------------------------------------------------------
  std::string get_account_integrated_address_as_str(
      network_type nettype
    , account_public_address const & adr
    , crypto::hash8 const & payment_id
    )
  {
    uint64_t integrated_address_prefix = get_config(nettype).CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;

    integrated_address iadr = {
      adr, payment_id
    };
    return tools::base58::encode_addr(integrated_address_prefix, t_serializable_object_to_blob(iadr));
  }
  //-----------------------------------------------------------------------
  bool check_address(const account_public_address& adr)
  {
    const auto valid_key = [](const crypto::public_key& key) {
      const rct::key point = rct::pk2rct(key);
      return point != rct::identity() && rct::isInMainSubgroup(point);
    };
    return valid_key(adr.m_spend_public_key) && valid_key(adr.m_view_public_key);
  }

  bool get_account_address_from_str(
      address_parse_info& info
    , network_type nettype
    , std::string const & str
    )
  {
    uint64_t address_prefix = get_config(nettype).CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t integrated_address_prefix = get_config(nettype).CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t subaddress_prefix = get_config(nettype).CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;

    blobdata data;
    uint64_t prefix;
    if (!tools::base58::decode_addr(str, prefix, data))
    {
      LOG_PRINT_L2("Invalid address format");
      return false;
    }

    if (integrated_address_prefix == prefix)
    {
      info.is_subaddress = false;
      info.has_payment_id = true;
    }
    else if (address_prefix == prefix)
    {
      info.is_subaddress = false;
      info.has_payment_id = false;
    }
    else if (subaddress_prefix == prefix)
    {
      info.is_subaddress = true;
      info.has_payment_id = false;
    }
    else {
      LOG_PRINT_L1("Wrong address prefix: " << prefix << ", expected " << address_prefix
        << " or " << integrated_address_prefix
        << " or " << subaddress_prefix);
      return false;
    }

    if (info.has_payment_id)
    {
      integrated_address iadr;
      if (!::serialization::parse_binary(data, iadr))
      {
        LOG_PRINT_L1("Account public address keys can't be parsed");
        return false;
      }
      info.address = iadr.adr;
      info.payment_id = iadr.payment_id;
    }
    else
    {
      if (!::serialization::parse_binary(data, info.address))
      {
        LOG_PRINT_L1("Account public address keys can't be parsed");
        return false;
      }
    }

    if (!check_address(info.address))
    {
      LOG_PRINT_L1("Failed to validate address keys");
      return false;
    }

    return true;
  }
  //--------------------------------------------------------------------------------
  bool get_account_address_from_str_or_url(
      address_parse_info& info
    , network_type nettype
    , const std::string& str_or_url
    , std::function<std::string(const std::string&, const std::vector<std::string>&, bool)> dns_confirm
    )
  {
    return get_account_address_from_str_or_url(info, nettype, str_or_url, true, dns_confirm);
  }
  //--------------------------------------------------------------------------------
  bool get_account_address_from_str_or_url(
      address_parse_info& info
    , network_type nettype
    , const std::string& str_or_url
    , bool allow_dns
    , std::function<std::string(const std::string&, const std::vector<std::string>&, bool)> dns_confirm
    )
  {
    if (get_account_address_from_str(info, nettype, str_or_url))
      return true;
    if (!allow_dns)
      return false;
    bool dnssec_valid;
    std::string address_str = tools::dns_utils::get_account_address_as_str_from_url(str_or_url, dnssec_valid, dns_confirm);
    return !address_str.empty() &&
      get_account_address_from_str(info, nettype, address_str);
  }
  //--------------------------------------------------------------------------------
  const char* get_network_type_name(const network_type nettype)
  {
    switch (nettype)
    {
    case MAINNET:
      return "mainnet";
    case TESTNET:
      return "testnet";
    case STAGENET:
      return "stagenet";
    case FAKECHAIN:
      return "fakechain";
    default:
      return "unknown";
    };
  }
  //--------------------------------------------------------------------------------
  bool operator ==(const cryptonote::transaction& a, const cryptonote::transaction& b) {
    return cryptonote::get_transaction_hash(a) == cryptonote::get_transaction_hash(b);
  }

  bool operator ==(const cryptonote::block& a, const cryptonote::block& b) {
    return cryptonote::get_block_hash(a) == cryptonote::get_block_hash(b);
  }
  //--------------------------------------------------------------------------------
  int compare_hash32_reversed_nbits(const crypto::hash& ha, const crypto::hash& hb, unsigned int nbits)
  {
    static_assert(sizeof(uint64_t) * 4 == sizeof(crypto::hash), "hash is wrong size");

    // We have to copy these buffers b/c of the strict aliasing rule
    uint64_t va[4];
    memcpy(va, &ha, sizeof(crypto::hash));
    uint64_t vb[4];
    memcpy(vb, &hb, sizeof(crypto::hash));

    for (int n = 3; n >= 0 && nbits; --n)
    {
      const unsigned int msb_nbits = std::min<unsigned int>(64, nbits);
      const uint64_t lsb_nbits_dropped = static_cast<uint64_t>(64 - msb_nbits);
      const uint64_t van = SWAP64LE(va[n]) >> lsb_nbits_dropped;
      const uint64_t vbn = SWAP64LE(vb[n]) >> lsb_nbits_dropped;
      nbits -= msb_nbits;

      if (van < vbn) return -1; else if (van > vbn) return 1;
    }

    return 0;
  }

  crypto::hash make_hash32_loose_template(unsigned int nbits, const crypto::hash& h)
  {
    static_assert(sizeof(uint64_t) * 4 == sizeof(crypto::hash), "hash is wrong size");

    // We have to copy this buffer b/c of the strict aliasing rule
    uint64_t vh[4];
    memcpy(vh, &h, sizeof(crypto::hash));

    for (int n = 3; n >= 0; --n)
    {
      const unsigned int msb_nbits = std::min<unsigned int>(64, nbits);
      const uint64_t mask = msb_nbits ? (~((std::uint64_t(1) << (64 - msb_nbits)) - 1)) : 0;
      nbits -= msb_nbits;

      vh[n] &= SWAP64LE(mask);
    }

    crypto::hash res;
    memcpy(&res, vh, sizeof(crypto::hash));
    return res;
  }
  //--------------------------------------------------------------------------------
}

//--------------------------------------------------------------------------------
bool parse_hash256(const std::string &str_hash, crypto::hash& hash)
{
  std::string buf;
  bool res = epee::string_tools::parse_hexstr_to_binbuff(str_hash, buf);
  if (!res || buf.size() != sizeof(crypto::hash))
  {
    MERROR("invalid hash format, input size: " << str_hash.size());
    return false;
  }
  else
  {
    buf.copy(reinterpret_cast<char *>(&hash), sizeof(crypto::hash));
    return true;
  }
}
