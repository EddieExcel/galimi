// Galimi deterministic tokenomics tests.
//
// Covers the log-target perpetual reward formula
//   reward = floor(log2((2^256 - 1) / difficulty)) * COIN
// and the zero-premine genesis block construction.
//
// These tests do not depend on chain state: every assertion must hold on any
// node, which is what makes the tokenomics consensus-safe.

#include "gtest/gtest.h"

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_tx_utils.h"

using namespace cryptonote;

namespace
{

static uint64_t galimi_reward(difficulty_type difficulty, uint8_t version = 16)
{
  uint64_t reward = 0;
  // median/current block weight under the full-reward zone: no penalty scaling
  const bool ok = get_block_reward(0, 1, 0, reward, version, difficulty);
  EXPECT_TRUE(ok);
  return reward;
}

TEST(galimi_curve_v17, anchors)
{
  // r = 255 (difficulty 1, minimal) -> maximum 255 GAL
  ASSERT_EQ(galimi_reward(1, 17), UINT64_C(255) * COIN);
  // r = 216 (Monero-scale difficulty ~7.4e11) -> 128 GAL
  ASSERT_EQ(galimi_reward(743448672675ULL, 17), UINT64_C(128) * COIN);
  ASSERT_EQ(galimi_reward(difficulty_type(1) << 39, 17), UINT64_C(128) * COIN);
  // r = 168 -> 45 GAL (well below the old pivot, still positive)
  ASSERT_EQ(galimi_reward(difficulty_type(1) << 87, 17), UINT64_C(45) * COIN);
  // deep difficulty -> small but nonzero
  ASSERT_EQ(galimi_reward(difficulty_type(1) << 120, 17), UINT64_C(18) * COIN);
}

TEST(galimi_curve_v17, legacy_v16_unchanged)
{
  // Pre-fork blocks keep the raw log2 reward.
  ASSERT_EQ(galimi_reward(difficulty_type(1) << 87, 16), UINT64_C(168) * COIN);
  ASSERT_EQ(galimi_reward(1, 16), UINT64_C(255) * COIN);
}

TEST(galimi_curve_v17, moves_with_difficulty)
{
  // Reward falls when difficulty rises, rises again when difficulty falls.
  const uint64_t low = galimi_reward(1000, 17);
  const uint64_t high = galimi_reward(difficulty_type(1) << 87, 17);
  ASSERT_GT(low, high);
  ASSERT_EQ(galimi_reward(1000, 17), low); // deterministic
}

TEST(galimi_tokenomics, difficulty_one_yields_255_gal)
{
  // target = 2^256 - 1, floor(log2(target)) = 255
  ASSERT_EQ(galimi_reward(1), UINT64_C(255) * COIN);
}

TEST(galimi_tokenomics, reward_is_deterministic)
{
  // Same inputs must give the same reward on every node, every time.
  const difficulty_type d = 123456789012345678ULL;
  ASSERT_EQ(galimi_reward(d), galimi_reward(d));
  ASSERT_EQ(galimi_reward(1), galimi_reward(1));
}

TEST(galimi_tokenomics, reward_never_zero_at_realistic_difficulty)
{
  // Perpetual emission: the reward stays positive for any plausible difficulty.
  // difficulty 2^64 -> target = 2^192 - 1 -> floor(log2) = 191
  const difficulty_type huge = difficulty_type(1) << 64;
  ASSERT_EQ(galimi_reward(huge), UINT64_C(191) * COIN);
  ASSERT_GT(galimi_reward(1000000000000ULL), 0);
}

TEST(galimi_tokenomics, reward_self_regulating)
{
  // More hashrate -> higher difficulty -> lower target -> smaller (or equal) reward.
  const uint64_t r1 = galimi_reward(1);
  const uint64_t r2 = galimi_reward(1000);
  const uint64_t r3 = galimi_reward(1000000);
  const uint64_t r4 = galimi_reward(difficulty_type(1) << 64);
  ASSERT_GE(r1, r2);
  ASSERT_GE(r2, r3);
  ASSERT_GE(r3, r4);
  ASSERT_LT(r4, r1); // strictly smaller at high difficulty
}

TEST(galimi_tokenomics, reward_ignores_coins_emitted)
{
  // Unlike Monero's emission curve, the Galimi reward must not depend on
  // already_generated_coins: perpetual, difficulty-driven only.
  uint64_t r_a = 0, r_b = 0;
  ASSERT_TRUE(get_block_reward(0, 1, 0, r_a, 16, 5000));
  ASSERT_TRUE(get_block_reward(0, 1, UINT64_C(999999999999999999), r_b, 16, 5000));
  ASSERT_EQ(r_a, r_b);
}

TEST(galimi_genesis, empty_coinbase_zero_premine)
{
  // The hardcoded genesis coinbase must carry no outputs: zero premine.
  block bl;
  ASSERT_TRUE(generate_genesis_block(bl, config::GENESIS_TX, config::GENESIS_NONCE));
  ASSERT_TRUE(bl.miner_tx.vout.empty());
  ASSERT_EQ(bl.miner_tx.vin.size(), 1);
  ASSERT_TRUE(bl.miner_tx.vin[0].type() == typeid(txin_gen));
  ASSERT_EQ(boost::get<txin_gen>(bl.miner_tx.vin[0]).height, 0);
}

TEST(galimi_genesis, deterministic_block)
{
  // Every node must derive the exact same genesis block (PoW search starts at
  // the fixed GENESIS_NONCE and difficulty 1, so the result is deterministic).
  block a, b;
  ASSERT_TRUE(generate_genesis_block(a, config::GENESIS_TX, config::GENESIS_NONCE));
  ASSERT_TRUE(generate_genesis_block(b, config::GENESIS_TX, config::GENESIS_NONCE));
  ASSERT_EQ(get_block_hash(a), get_block_hash(b));
  ASSERT_EQ(get_transaction_hash(a.miner_tx), get_transaction_hash(b.miner_tx));
}

} // namespace
