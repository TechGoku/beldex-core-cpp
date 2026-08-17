//
//  beldex_fee_utils.cpp
//  Copyright © 2018 MyMonero. All rights reserved.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are
//  permitted provided that the following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of
//	conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list
//	of conditions and the following disclaimer in the documentation and/or other
//	materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be
//	used to endorse or promote products derived from this software without specific
//	prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
//  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
//  THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
//  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
//  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//
//
//
#include "beldex_fee_utils.hpp"
#include "wallet_errors.h"
#include "epee/string_tools.h"
//
using namespace std;
using namespace boost;
using namespace epee;
using namespace crypto;
using namespace cryptonote;
using namespace tools; // for error::
using namespace beldex_fork_rules;
//
// used to choose when to stop adding outputs to a tx
#define APPROXIMATE_INPUT_BYTES 80
//
uint32_t beldex_fee_utils::default_priority()
{
	return 1; // lowest
}
//
uint64_t beldex_fee_utils::get_base_fee( // added as of v8
	uint64_t fee_per_b
) {
	return fee_per_b;
}
//
uint64_t beldex_fee_utils::estimated_tx_network_fee(
	uint64_t fee_per_byte,
	uint64_t fee_per_output,
	uint32_t priority,
	use_fork_rules_fn_type use_fork_rules_fn
) {
	// uint64_t fee_multiplier = get_fee_multiplier(priority, default_priority(), get_fee_algorithm(use_fork_rules_fn), use_fork_rules_fn);
	uint64_t pct = get_fee_percent(priority,txtype::standard);
	std::vector<uint8_t> extra; // blank extra
	size_t est_tx_size = estimate_rct_tx_size(2, fixed_mixinsize(), 2, extra.size(), true/*bulletproof*/, true/*clsag*/); // typically ~14kb post-rct, pre-bulletproofs
	uint64_t estimated_fee = calculate_fee_from_size_1(fee_per_byte,fee_per_output, est_tx_size, pct);
	//
	return estimated_fee;
}
uint64_t beldex_fee_utils::get_upper_transaction_weight_limit(
	uint64_t upper_transaction_weight_limit__or_0_for_default,
	use_fork_rules_fn_type use_fork_rules_fn
) {
	if (upper_transaction_weight_limit__or_0_for_default > 0)
		return upper_transaction_weight_limit__or_0_for_default;
	return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
}
uint64_t beldex_fee_utils::get_fee_percent(uint32_t priority, txtype type)
{
  static constexpr std::array<uint64_t, 4> percents{{150, 500, 2500, 12500}};

  if (priority == 0) // 0 means no explicit priority was given, so use the wallet default
  {
    priority =1; // The flash default is unusable for this tx, so fall back to unimportant
  }
  if (priority == 5)
	{
		uint64_t burn_pct = 0;
		burn_pct = FLASH_BURN_TX_FEE_PERCENT_OLD;
		return FLASH_MINER_TX_FEE_PERCENT + burn_pct ;
	}
	
  if (priority > percents.size())
    THROW_WALLET_EXCEPTION_IF(false,error::invalid_priority);

  return percents[priority-1];
}	
uint64_t beldex_fee_utils::get_fee_multiplier(
	uint32_t priority,
	uint32_t default_priority,
	int fee_algorithm,
	use_fork_rules_fn_type use_fork_rules_fn
) {
	static const struct
	{
		size_t count;
		uint64_t multipliers[4];
	}
	multipliers[] =
	{
		{ 3, {1, 2, 3} },
		{ 3, {1, 20, 166} },
		{ 4, {1, 4, 20, 166} },
		{ 4, {1, 5, 25, 1000} },
	};
	
	if (fee_algorithm == -1)
		fee_algorithm = get_fee_algorithm(use_fork_rules_fn);
	
	// 0 -> default (here, x1 till fee algorithm 2, x4 from it)
	if (priority == 0)
		priority = default_priority;
	if (priority == 0)
	{
		if (fee_algorithm >= 2)
			priority = 2;
		else
			priority = 1;
	}
	
	THROW_WALLET_EXCEPTION_IF(fee_algorithm < 0 || fee_algorithm > 3, error::invalid_priority);
	
	// 1 to 3/4 are allowed as priorities
	const uint32_t max_priority = multipliers[fee_algorithm].count;
	if (priority >= 1 && priority <= max_priority)
	{
		return multipliers[fee_algorithm].multipliers[priority-1];
	}
	
	THROW_WALLET_EXCEPTION_IF (false, error::invalid_priority);
	return 1;
}
int beldex_fee_utils::get_fee_algorithm(use_fork_rules_fn_type use_fork_rules_fn)
{
	// changes at v3, v5, v8
	if (use_fork_rules_fn(HF_VERSION_PER_BYTE_FEE, 0))
		return 3;
	if (use_fork_rules_fn(5, 0))
		return 2;
	if (use_fork_rules_fn(3, -720 * 14))
		return 1;
	return 0;
}
// HF21: bytes added by the private-token parts of a transaction, none of which
// the classic RingCT model above accounts for.
size_t beldex_fee_utils::estimate_zc_extra_size(int n_zc_outputs, int n_zc_inputs, int mixin)
{
	if (n_zc_outputs <= 0 && n_zc_inputs <= 0) {
		return 0;
	}
	size_t size = 0;
	const int ring_size = mixin + 1;
	//
	// tx_out_zarcanum is larger than txout_to_key: stealth_address +
	// amount_commitment + blinded_token_id (3*32) + varint encrypted_amount
	// (<=9) + mix_attr + version, against the 32 the base model already
	// charged for the output key.
	size += (size_t)n_zc_outputs * ((3 * 32 + 9 + 1 + 1) - 32);
	//
	// One BGE surjection proof per token output. Size is O(log4(ring)) group
	// elements: A, B, y, z (4*32) plus m Pk points and m*(n-1) f scalars, with
	// n = 4 and m = ceil(log4(ring)).
	size_t m = 1;
	while ((size_t)(1 << (2 * m)) < (size_t)ring_size) {
		++m;
	}
	size += (size_t)n_zc_outputs * (4 * 32 + m * 32 + m * 3 * 32);
	//
	if (n_zc_outputs > 0) {
		// Outputs range proof: a Bulletproof+ over the auxiliary commitments,
		// plus the vector-HG aggregation proof that binds them to the real ones
		// (one aux commitment and two response scalars per output, one shared
		// challenge).
		size_t log_padded = 0;
		while ((1 << log_padded) < n_zc_outputs) {
			++log_padded;
		}
		size += (2 * (6 + log_padded) + 4 + 5) * 32 + 3;
		size += (size_t)n_zc_outputs * 3 * 32 + 32;
		// Balance proof: P + a double Schnorr (3 scalars).
		size += 4 * 32;
	}
	//
	// ZC_sig per token input: CLSAG-GGX carries s_g and s_x (one scalar each
	// per ring member) plus c1, D, E, and the two pseudo-out points.
	size += (size_t)n_zc_inputs * (2 * 32 * ring_size + 5 * 32);
	//
	return size;
}
size_t beldex_fee_utils::estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag, int n_zc_outputs, int n_zc_inputs)
{
	size_t size = 0;
	
	// tx prefix
	
	// first few bytes
	size += 1 + 6;
	
	// vin
	size += n_inputs * (1+6+(mixin+1)*2+32);
	
	// vout
	size += n_outputs * (6+32);
	
	// extra
	size += extra_size;
	
	// rct signatures
	
	// type
	size += 1;
	
	// rangeSigs
	if (bulletproof)
	{
		size_t log_padded_outputs = 0;
		while ((1<<log_padded_outputs) < n_outputs)
			++log_padded_outputs;
		size += (2 * (6 + log_padded_outputs) + 4 + 5) * 32 + 3;
	}
	else
		size += (2*64*32+32+64*32) * n_outputs;
	
	// MGs/CLSAGs
	if (clsag)
		size += n_inputs * (32 * (mixin+1) + 64);
	else
		size += n_inputs * (64 * (mixin+1) + 32);
	
	// mixRing - not serialized, can be reconstructed
	/* size += 2 * 32 * (mixin+1) * n_inputs; */
	
	// pseudoOuts
	size += 32 * n_inputs;
	// ecdhInfo
	size += 8 * n_outputs;
	// outPk - only commitment is saved
	size += 32 * n_outputs;
	// txnFee
	size += 4;
	
	// HF21 private-token parts
	size += estimate_zc_extra_size(n_zc_outputs, n_zc_inputs, mixin);
	
	LOG_PRINT_L2("estimated " << (bulletproof ? "bulletproof" : "borromean") << " rct tx size for " << n_inputs << " inputs with ring size " << (mixin+1) << " and " << n_outputs << " outputs: " << size << " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)");
	return size;
}
size_t beldex_fee_utils::estimate_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag, int n_zc_outputs, int n_zc_inputs)
{
	if (use_rct)
		return estimate_rct_tx_size(n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag, n_zc_outputs, n_zc_inputs);
	else
		return n_inputs * (mixin+1) * APPROXIMATE_INPUT_BYTES + extra_size;
}

uint64_t beldex_fee_utils::estimate_tx_weight(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag, int n_zc_outputs, int n_zc_inputs)
{
	size_t size = estimate_tx_size(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag, n_zc_outputs, n_zc_inputs);
	if (use_rct && bulletproof && n_outputs > 2)
	{
		const uint64_t bp_base = 368;
		size_t log_padded_outputs = 2;
		while ((1<<log_padded_outputs) < n_outputs)
			++log_padded_outputs;
		uint64_t nlr = 2 * (6 + log_padded_outputs);
		const uint64_t bp_size = 32 * (9 + nlr);
		const uint64_t bp_clawback = (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
		MDEBUG("clawback on size " << size << ": " << bp_clawback);
		size += bp_clawback;
	}
	return size;
}
uint64_t beldex_fee_utils::estimate_fee(bool use_per_byte_fee, bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag, uint64_t fee_per_b,uint64_t fee_per_o, uint64_t fee_multiplier, uint64_t fee_quantization_mask, int n_zc_outputs, int n_zc_inputs)
{
	if (use_per_byte_fee)
	{
		const size_t estimated_tx_weight = estimate_tx_weight(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag, n_zc_outputs, n_zc_inputs);
		return calculate_fee_from_weight(fee_per_b,fee_per_o, estimated_tx_weight,n_outputs, fee_multiplier, fee_quantization_mask);
	}
	else
	{
		const size_t estimated_tx_size = estimate_tx_size(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag, n_zc_outputs, n_zc_inputs);
		return calculate_fee_from_size_1(fee_per_b, fee_per_o, estimated_tx_size, fee_multiplier);
	}
}
//
uint64_t beldex_fee_utils::calculate_fee_from_weight(uint64_t fee_per_b,uint64_t fee_per_o, uint64_t weight, int outputs, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
{
	uint64_t fee = (weight * fee_per_b + outputs * fee_per_o) * fee_multiplier / 95;
	fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
	return fee;
}
uint64_t beldex_fee_utils::calculate_fee(bool use_per_byte_fee, const cryptonote::transaction &tx, size_t blob_size, uint64_t fee_per_b,uint64_t fee_per_o, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
{
	if (use_per_byte_fee) {
		return calculate_fee_from_weight(fee_per_b,fee_per_o, cryptonote::get_transaction_weight(tx, blob_size),2, fee_multiplier, fee_quantization_mask);
	} else {
		return calculate_fee_from_size_1(fee_per_b,fee_per_o, blob_size, fee_multiplier);
	}
}
//
//uint64_t beldex_fee_utils::calculate_fee_from_size(uint64_t fee_per_b, const cryptonote::blobdata &blob, uint64_t fee_multiplier)
//{
//	return calculate_fee_from_size(fee_per_b, blob.size(), fee_multiplier);
//}
uint64_t beldex_fee_utils::calculate_fee_from_size(uint64_t fee_per_b, size_t bytes, uint64_t fee_multiplier)
{
	return bytes * fee_per_b * fee_multiplier;
}
uint64_t beldex_fee_utils::calculate_fee_from_size_1(uint64_t fee_per_b,uint64_t fee_per_o, size_t bytes, uint64_t pct)
{
	return (fee_per_b * bytes + fee_per_o * 2/*minouts*/) * pct / 100;
}
