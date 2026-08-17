//
//  beldex_transfer_utils.cpp
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
#include <boost/optional.hpp>
#include "beldex_transfer_utils.hpp"
#include "wallet_errors.h"
#include "epee/string_tools.h"
#include "beldex_paymentID_utils.hpp"
#include "beldex_key_image_utils.hpp"
//
using namespace std;
using namespace crypto;
using namespace std;
using namespace boost;
using namespace epee;
using namespace cryptonote;
using namespace tools; // for error::
using namespace beldex_transfer_utils;
using namespace beldex_fork_rules;
using namespace beldex_fee_utils;
using namespace beldex_key_image_utils; // for API response parsing

namespace {
CreateTransactionErrorCode _add_pid_to_tx_extra(
	const boost::optional<string>& payment_id_string,
	vector<uint8_t> &extra
) { // Detect hash8 or hash32 char hex string as pid and configure 'extra' accordingly
	bool r = false;
	if (payment_id_string != none && payment_id_string->size() > 0) {
		crypto::hash payment_id;
		r = beldex_paymentID_utils::parse_long_payment_id(*payment_id_string, payment_id);
		if (r) {
			std::string extra_nonce;
			cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
			r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
			if (!r) {
				return couldntAddPIDNonceToTXExtra;
			}
		} else {
			crypto::hash8 payment_id8;
			r = beldex_paymentID_utils::parse_short_payment_id(*payment_id_string, payment_id8);
			if (!r) { // a PID has been specified by the user but the last resort in validating it fails; error
				return invalidPID;
			}
			std::string extra_nonce;
			cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
			r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
			if (!r) {
				return couldntAddPIDNonceToTXExtra;
			}
		}
	}
	return noError;
}
// HF21: locate a decoy in the per-input decoy set by its global index.
// src.outputs is the ring after the real output has been inserted in sorted
// position, so ring index != decoy index; matching on global_index is the only
// stable correspondence. Returns nullptr when the ring member is not among the
// supplied decoys (which happens for the real output).
static const beldex_transfer_utils::RandomAmountOutput *_find_decoy_by_global_index(
	const std::vector<beldex_transfer_utils::RandomAmountOutputs> &mix_outs,
	size_t input_index,
	uint64_t global_index
) {
	if (input_index >= mix_outs.size()) {
		return nullptr;
	}
	for (const auto &candidate : mix_outs[input_index].outputs) {
		if (candidate.global_index == global_index) {
			return &candidate;
		}
	}
	return nullptr;
}
bool _rct_hex_to_rct_commit(
	const std::string &rct_string,
	rct::key &rct_commit
) {
	// rct string is empty if output is non RCT
	if (rct_string.empty()) {
		return false;
	}
	// rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
	std::string rct_commit_str = rct_string.substr(0,64);
	THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, rct_commit_str), error::wallet_internal_error, "Invalid rct commit hash: " + rct_commit_str);
	string_tools::hex_to_pod(rct_commit_str, rct_commit);
	return true;
}
bool _rct_hex_to_decrypted_mask(
	const std::string &rct_string,
	const crypto::secret_key &view_secret_key,
	const crypto::public_key& tx_pub_key,
	uint64_t internal_output_index,
	rct::key &decrypted_mask
) {
	// rct string is empty if output is non RCT
	if (rct_string.empty()) {
		return false;
	}
	// rct_string is a magic value if output is RCT and coinbase
	if (rct_string == "coinbase") {
		decrypted_mask = rct::identity();
		return true;
	}
	auto make_key_derivation = [&]() {
		crypto::key_derivation derivation;
		bool r = generate_key_derivation(tx_pub_key, view_secret_key, derivation);
		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
		crypto::secret_key scalar;
		crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
		return rct::sk2rct(scalar);
	};
	rct::key encrypted_mask;
	// rct_string is a string with length 64+16 (<rct commit> + <amount>) if RCT version 2
	if (rct_string.size() < 64 * 2) {
		decrypted_mask = rct::genCommitmentMask(make_key_derivation());
		return true;
	}
	// rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
	std::string encrypted_mask_str = rct_string.substr(64,64);
	THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, encrypted_mask_str), error::wallet_internal_error, "Invalid rct mask: " + encrypted_mask_str);
	string_tools::hex_to_pod(encrypted_mask_str, encrypted_mask);
	//
	if (encrypted_mask == rct::identity()) {
		// backward compatibility; should no longer be needed after v11 mainnet fork
		decrypted_mask = encrypted_mask;
		return true;
	}
	//
	// Decrypt the mask
	sc_sub(decrypted_mask.bytes,
		encrypted_mask.bytes,
		rct::hash_to_scalar(make_key_derivation()).bytes);
	
	return true;
}
bool _verify_sec_key(const crypto::secret_key &secret_key, const crypto::public_key &public_key)
{ // borrowed from device_default.cpp
	crypto::public_key calculated_pub;
	bool r = crypto::secret_key_to_public_key(secret_key, calculated_pub);
	return r && public_key == calculated_pub;
}
} // unnamed namespace
//
namespace
{
	template<typename T>
	T pop_index(std::vector<T>& vec, size_t idx)
	{
		CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
		CHECK_AND_ASSERT_MES(idx < vec.size(), T(), "idx out of bounds");

		T res = std::move(vec[idx]);
		if (idx + 1 != vec.size()) {
			vec[idx] = std::move(vec.back());
		}
		vec.resize(vec.size() - 1);
		
		return res;
	}
	//
	template<typename T>
	T pop_random_value(std::vector<T>& vec)
	{
		CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
		
		size_t idx = crypto::rand<size_t>() % vec.size();
		return pop_index (vec, idx);
	}
}
//
//
//
// Decomposed Send procedure
void beldex_transfer_utils::send_step1__prepare_params_for_get_decoys(
	Send_Step1_RetVals &retVals,
	//
	const boost::optional<string>& payment_id_string,
	const vector<uint64_t>& sending_amounts,
	bool is_sweeping,
	uint32_t simple_priority,
	use_fork_rules_fn_type use_fork_rules_fn,
	//
	const vector<SpendableOutput> &unspent_outs,
	uint64_t fee_per_b, // per v8
	uint64_t fee_per_o,
	uint64_t fee_quantization_mask,
	//
	boost::optional<uint64_t> prior_attempt_size_calcd_fee,
	boost::optional<SpendableOutputToRandomAmountOutputs> prior_attempt_unspent_outs_to_mix_outs,
	boost::optional<string> requested_token_id,
	uint8_t hf_version,
	const boost::optional<token_operation_data> &token_op
) {
	retVals = {};
	const bool tokens_active = hf_version >= HF_VERSION_PRIVATE_TOKENS;
	const bool sending_token = requested_token_id != none && !requested_token_id->empty();
	// A token operation (deploy a new asset) also sets requested_token_id -- to
	// the id of the token it is creating -- so that the destinations get tagged
	// as private-token outputs. It is not a transfer of that token though: the
	// token has no outputs to select from yet, so it takes its own path below
	// and the transfer path must not claim it.
	const bool deploying_token = token_op != none;
	if ((sending_token || deploying_token) && !tokens_active) {
		retVals.errCode = notYetImplemented;
		return;
	}
	//
	if (!is_sweeping && !deploying_token) {
		for (uint64_t sending_amount : sending_amounts) {
 			if (sending_amount == 0) {
 				retVals.errCode = enteredAmountTooLow;
 				return;
 			}
 		}
	}
	//
	uint32_t fake_outs_count = beldex_fork_rules::fixed_mixinsize();
	retVals.mixin = fake_outs_count;
	//
	bool use_rct = true;
	bool bulletproof = true;
	bool clsag = true;
	//
	std::vector<uint8_t> extra;
	CreateTransactionErrorCode tx_extra__code = _add_pid_to_tx_extra(payment_id_string, extra);
	if (tx_extra__code != noError) {
		retVals.errCode = tx_extra__code;
		return;
	}
	const uint64_t base_fee = get_base_fee(fee_per_b); // in other words, fee_per_b
	// const uint64_t fee_multiplier = get_fee_multiplier(simple_priority, default_priority(), get_fee_algorithm(use_fork_rules_fn), use_fork_rules_fn);
	const uint64_t fee_multiplier = get_fee_percent(simple_priority,txtype::standard);
	//
	uint64_t attempt_at_min_fee;
	if (prior_attempt_size_calcd_fee == none) {
		attempt_at_min_fee = estimate_fee(true/*use_per_byte_fee*/, true/*use_rct*/, 1/*est num inputs*/, fake_outs_count, 2, extra.size(), bulletproof, clsag, fee_per_b,fee_per_o, fee_multiplier, fee_quantization_mask);
		// use a minimum viable estimate_fee() with 1 input. It would be better to under-shoot this estimate, and then need to use a higher fee  from calculate_fee() because the estimate is too low,
		// versus the worse alternative of over-estimating here and getting stuck using too high of a fee that leads to fingerprinting
	} else {
		attempt_at_min_fee = *prior_attempt_size_calcd_fee;
	}
	// fee may get changed as follows…
	uint64_t sum_sending_amounts;
	uint64_t potential_total; // aka balance_required

	if (is_sweeping) {
		potential_total = sum_sending_amounts = UINT64_MAX; // balance required: all
	} else {
		sum_sending_amounts = 0;
 		for (uint64_t amount : sending_amounts) {
 			sum_sending_amounts += amount;
 		}
 		potential_total = sum_sending_amounts + attempt_at_min_fee;
	}
	//
	// ── HF21: private token send ──────────────────────────────────────────
	// A token transfer spends two disjoint pools at once: token outputs of the
	// requested token to cover the transferred amount, and native BDX outputs
	// to cover the fee (fees are always BDX). They are selected and balanced
	// independently, then concatenated into a single using_outs -- the decoy
	// fetch and construction paths treat them uniformly from there.
	//
	// ── HF21: token descriptor operation (deploy a new asset) ─────────────
	// A deploy has no token inputs -- the token does not exist until this very
	// transaction creates it. What it does have is a fixed fan-out of
	// MIN_TOKEN_MINT_OUTPUTS zarcanum outputs carrying the initial supply, the
	// descriptor operation in tx.extra, and a protocol-mandated BDX burn on top
	// of the ordinary network fee. All of that is paid for out of native
	// outputs, so selection is native-only -- just against a much bigger bill.
	if (deploying_token) {
		if (is_sweeping) {
			// Sweeping is "send everything you have"; a deploy sends nothing.
			retVals.errCode = notYetImplemented;
			return;
		}
		// The descriptor operation is a real part of tx.extra and can run to
		// several hundred bytes (meta_info is free-form user text), so it has to
		// be inside the size the fee is estimated from or the tx is underpaid.
		// Two details matter for that size to be the true one:
		//  - construct_tx re-encodes the operation with the token amount
		//    commitment attached before signing, so size against a copy that
		//    already carries the flag (32 bytes the fee would otherwise miss);
		//  - the burn field is written at its real value, because construct_tx
		//    replaces the wallet's dummy with exactly this number.
		const uint64_t burn_amount = token_op->burn_amount(hf_version);
		cryptonote::tx_extra_token_descriptor_operation sizing_tdo = token_op->tdo;
		sizing_tdo.fields = (uint8_t)(sizing_tdo.fields | cryptonote::token_field_amount_commitment);
		if (!cryptonote::add_token_descriptor_operation_to_tx_extra(extra, sizing_tdo)
			|| !cryptonote::add_burned_amount_to_tx_extra(extra, burn_amount)) {
			retVals.errCode = couldntAddTokenOperationToTXExtra;
			return;
		}
		const int n_zc_outs  = (int)MIN_TOKEN_MINT_OUTPUTS;
		const int n_est_outs = n_zc_outs + 1; // + the BDX change output
		auto estimate_with = [&](size_t n_native_inputs) {
			uint64_t f = estimate_fee(
				true/*use_per_byte_fee*/, use_rct,
				(int)std::max<size_t>(n_native_inputs, 1), fake_outs_count, n_est_outs, extra.size(),
				bulletproof, clsag, fee_per_b, fee_per_o, fee_multiplier, fee_quantization_mask,
				n_zc_outs, 0/*n_zc_inputs -- a deploy spends no token inputs*/
			);
			if (prior_attempt_size_calcd_fee != none && f < attempt_at_min_fee) {
				f = attempt_at_min_fee;
			}
			return f;
		};
		vector<SpendableOutput> native_pool;
		for (const auto &out : unspent_outs) {
			if (out.is_zarcanum()) {
				continue; // a token cannot pay a BDX fee or a BDX burn
			}
			if (out.amount < beldex_fork_rules::dust_threshold()
				&& (out.rct == none || out.rct->empty())) {
				continue; // dusty and unmixable
			}
			native_pool.push_back(out);
		}
		// The burn rides along inside using_fee. construct_tx enforces
		// amount_in - amount_out >= burn_fixed and then credits the miner with
		// only the remainder, so the two have to be covered together or the tx
		// fails to construct at the very last step.
		uint64_t native_using = 0;
		size_t n_native_used = 0;
		uint64_t needed_total = estimate_with(1) + burn_amount;
		while (native_using < needed_total && native_pool.size() > 0) {
			auto out = pop_random_value(native_pool);
			native_using += out.amount;
			retVals.using_outs.push_back(std::move(out));
			++n_native_used;
			needed_total = estimate_with(n_native_used) + burn_amount; // each input grows the tx
		}
		retVals.spendable_balance = native_using;
		retVals.required_balance = needed_total;
		if (native_using < needed_total) {
			retVals.errCode = needMoreMoneyThanFound;
			return;
		}
		retVals.using_fee = needed_total; // network fee + protocol burn
		retVals.final_total_wo_fee = 0;   // nothing native is being sent
		retVals.change_amount = native_using - needed_total;
		uint64_t initial_supply = 0;
		for (uint64_t amount : sending_amounts) {
			initial_supply += amount;
		}
		retVals.token_final_total_wo_fee = initial_supply;
		retVals.token_change_amount = 0;  // a deploy mints; there is no change
		return;
	}
	if (sending_token) {
		if (is_sweeping) {
			// A token sweep would have to drain the token pool while still
			// leaving BDX for the fee; not modelled here yet.
			retVals.errCode = notYetImplemented;
			return;
		}
		vector<SpendableOutput> token_pool, native_pool;
		for (const auto &out : unspent_outs) {
			if (out.is_zarcanum()) {
				if (out.token_id != none && *out.token_id == *requested_token_id) {
					token_pool.push_back(out);
				}
				continue; // a token of some OTHER token is not spendable here
			}
			native_pool.push_back(out);
		}
		// Token side.
		uint64_t token_needed = 0;
		for (uint64_t amount : sending_amounts) {
			token_needed += amount;
		}
		uint64_t token_using = 0;
		while (token_using < token_needed && token_pool.size() > 0) {
			auto out = pop_random_value(token_pool);
			token_using += out.amount;
			retVals.using_outs.push_back(std::move(out));
		}
		retVals.token_spendable_balance = token_using;
		retVals.token_required_balance = token_needed;
		if (token_using < token_needed) {
			retVals.errCode = needMoreMoneyThanFound;
			return;
		}
		retVals.token_final_total_wo_fee = token_needed;
		retVals.token_change_amount = token_using - token_needed;
		//
		// Native side: enough BDX to cover the fee alone. Output count for the
		// estimate is the recipient token output, the token change output, and
		// the BDX change output.
		const int n_zc_inputs = (int)retVals.using_outs.size(); // every out chosen so far is a token out
		const int n_zc_outs = 1 + (retVals.token_change_amount != 0 ? 1 : 0);
		const int n_est_outs = n_zc_outs + 1; // + the BDX change output
		// Estimate against at least one native input, since one will be needed.
		auto estimate_with = [&](size_t n_native_inputs) {
			uint64_t f = estimate_fee(
				true/*use_per_byte_fee*/, use_rct,
				(int)(n_zc_inputs + n_native_inputs), fake_outs_count, n_est_outs, extra.size(),
				bulletproof, clsag, fee_per_b, fee_per_o, fee_multiplier, fee_quantization_mask,
				n_zc_outs, n_zc_inputs
			);
			if (prior_attempt_size_calcd_fee != none && f < attempt_at_min_fee) {
				f = attempt_at_min_fee;
			}
			return f;
		};
		uint64_t native_using = 0;
		size_t n_native_used = 0;
		uint64_t needed_fee_tok = estimate_with(1);
		while (native_using < needed_fee_tok && native_pool.size() > 0) {
			auto out = pop_random_value(native_pool);
			if (out.amount < beldex_fork_rules::dust_threshold()
				&& (out.rct == none || out.rct->empty())) {
				continue; // dusty and unmixable
			}
			native_using += out.amount;
			retVals.using_outs.push_back(std::move(out));
			++n_native_used;
			// Each added input grows the tx, so the fee must be re-estimated.
			needed_fee_tok = estimate_with(n_native_used);
		}
		retVals.spendable_balance = native_using;
		retVals.required_balance = needed_fee_tok;
		if (native_using < needed_fee_tok) {
			retVals.errCode = needMoreMoneyThanFound; // not enough BDX to pay the fee
			return;
		}
		retVals.using_fee = needed_fee_tok;
		retVals.final_total_wo_fee = 0;   // nothing native is being sent
		retVals.change_amount = native_using - needed_fee_tok;
		return;
	}
	//
	// Gather outputs and amount to use for getting decoy outputs…
	uint64_t using_outs_amount = 0;
	vector<SpendableOutput>  remaining_unusedOuts = unspent_outs; // take copy so not to modify original

	// start by using all the passed in outs that were selected in a prior tx construction attempt
	if (prior_attempt_unspent_outs_to_mix_outs != none) {
		for (size_t i = 0; i < remaining_unusedOuts.size(); ++i) {
			SpendableOutput &out = remaining_unusedOuts[i];

			// search for out by public key to see if it should be re-used in an attempt
			if (prior_attempt_unspent_outs_to_mix_outs->find(out.public_key) != prior_attempt_unspent_outs_to_mix_outs->end()) {
				using_outs_amount += out.amount;
				retVals.using_outs.push_back(std::move(pop_index(remaining_unusedOuts, i)));
			}
		}
	}

	// TODO: factor this out to get spendable balance for display in the MM wallet:
	while (using_outs_amount < potential_total && remaining_unusedOuts.size() > 0) {
		auto out = pop_random_value(remaining_unusedOuts);
		if (!use_rct && (out.rct != none && (*out.rct).empty() == false)) {
			// out.rct is set by the server
			continue; // skip rct outputs if not creating rct tx
		}
		if (out.amount < beldex_fork_rules::dust_threshold()) { // amount is dusty..
			if (out.rct == none || (*out.rct).empty()) {
//				cout << "Found a dusty but unmixable (non-rct) output... skipping it!" << endl;
				continue;
			} else {
//				cout << "Found a dusty but mixable (rct) amount... keeping it!" << endl;
			}
		}
		using_outs_amount += out.amount;
//		cout << "Using output: " << out.amount << " - " << out.public_key << endl;
		retVals.using_outs.push_back(std::move(out));
	}
	retVals.spendable_balance = using_outs_amount; // must store for needMoreMoneyThanFound return
	// Note: using_outs and using_outs_amount may still get modified below (so retVals.spendable_balance gets updated)
	//
//	if (/*using_outs.size() > 1*/ && use_rct) { // FIXME? see original core js
	uint64_t needed_fee = estimate_fee(
		true/*use_per_byte_fee*/, use_rct,
		retVals.using_outs.size(), fake_outs_count, /*tx.dsts.size()*/1+1, extra.size(),
		bulletproof, clsag, fee_per_b,fee_per_o, fee_multiplier, fee_quantization_mask
	);
	// if newNeededFee < neededFee, use neededFee instead (should only happen on the 2nd or later times through (due to estimated fee being too low))
	if (prior_attempt_size_calcd_fee != none && needed_fee < attempt_at_min_fee) {
		needed_fee = attempt_at_min_fee;
	}
	//
	// NOTE: needed_fee may get further modified below when !is_sweeping if using_outs_amount < total_incl_fees and gets finalized (for this function's scope) as using_fee
	//
	retVals.required_balance = is_sweeping ? needed_fee : potential_total; // must store for needMoreMoneyThanFound return .... NOTE: this is set to needed_fee for is_sweeping because that's literally the required balance, which an caller may want to print in case they get needMoreMoneyThanFound - note this gets updated below when !is_sweeping
	//
	uint64_t total_wo_fee = is_sweeping
		? /*now that we know outsAmount>needed_fee*/(using_outs_amount - needed_fee)
		: sum_sending_amounts;
	retVals.final_total_wo_fee = total_wo_fee;
	//
	uint64_t total_incl_fees;
	if (is_sweeping) {
		if (using_outs_amount < needed_fee) { // like checking if the result of the following total_wo_fee is < 0
			retVals.errCode = needMoreMoneyThanFound; // sufficiently up-to-date (for this return case) required_balance and using_outs_amount (spendable balance) will have been stored for return by this point
			return;
		}
		total_incl_fees = using_outs_amount;
	} else {
		total_incl_fees = sum_sending_amounts + needed_fee; // because fee changed because using_outs.size() was updated
		while (using_outs_amount < total_incl_fees && remaining_unusedOuts.size() > 0) { // add outputs 1 at a time till we either have them all or can meet the fee
			{
				auto out = pop_random_value(remaining_unusedOuts);
//				cout << "Using output: " << out.amount << " - " << out.public_key << endl;
				using_outs_amount += out.amount;
				retVals.using_outs.push_back(std::move(out));
			}
			retVals.spendable_balance = using_outs_amount; // must store for needMoreMoneyThanFound return
			//
			// Recalculate fee, total incl fees
			needed_fee = estimate_fee(
				true/*use_per_byte_fee*/, use_rct,
				retVals.using_outs.size(), fake_outs_count, /*tx.dsts.size()*/1+1, extra.size(),
				bulletproof, clsag, fee_per_b,fee_per_o, fee_multiplier, fee_quantization_mask
			);
			total_incl_fees = sum_sending_amounts + needed_fee; // because fee changed
		}
		retVals.required_balance = total_incl_fees; // update required_balance b/c total_incl_fees changed
	}
	retVals.using_fee = needed_fee;
	//
//	cout << "Final attempt at fee: " << needed_fee << " for " << retVals.using_outs.size() << " inputs" << endl;
//	cout << "Balance to be used: " << total_incl_fees << endl;
	if (using_outs_amount < total_incl_fees) {
		retVals.errCode = needMoreMoneyThanFound; // sufficiently up-to-date (for this return case) required_balance and using_outs_amount (spendable balance) will have been stored for return by this point.
		return;
	}
	//
	// Change can now be calculated
	uint64_t change_amount = 0; // to initialize
	if (using_outs_amount > total_incl_fees) {
		THROW_WALLET_EXCEPTION_IF(is_sweeping, error::wallet_internal_error, "Unexpected total_incl_fees > using_outs_amount while sweeping");
		change_amount = using_outs_amount - total_incl_fees;
	}
//	cout << "Calculated change amount:" << change_amount << endl;
	retVals.change_amount = change_amount;
	//
//	uint64_t tx_estimated_weight = estimate_tx_weight(true/*use_rct*/, retVals.using_outs.size(), fake_outs_count, 1+1, extra.size(), true/*bulletproof*/);
//	if (tx_estimated_weight >= TX_WEIGHT_TARGET(get_upper_transaction_weight_limit(0, use_fork_rules_fn))) {
//		// TODO?
//	}
}
//
//
void beldex_transfer_utils::pre_step2_tie_unspent_outs_to_mix_outs_for_all_future_tx_attempts(
	Tie_Outs_to_Mix_Outs_RetVals &retVals,
	//
	const vector<SpendableOutput> &using_outs,
	vector<RandomAmountOutputs> mix_outs_from_server,
	//
	const boost::optional<SpendableOutputToRandomAmountOutputs> &prior_attempt_unspent_outs_to_mix_outs
) {
	retVals.errCode = noError;
	//
	// combine newly requested mix outs returned from the server, with the already known decoys from prior tx construction attempts,
	// so that the same decoys will be re-used with the same outputs in all tx construction attempts. This ensures fee returned
	// by calculate_fee() will be correct in the final tx, and also reduces number of needed trips to the server during tx construction.
	SpendableOutputToRandomAmountOutputs prior_attempt_unspent_outs_to_mix_outs_new;
	if (prior_attempt_unspent_outs_to_mix_outs) {
		prior_attempt_unspent_outs_to_mix_outs_new = *prior_attempt_unspent_outs_to_mix_outs;
	}

	std::vector<RandomAmountOutputs> mix_outs;
	mix_outs.reserve(using_outs.size());

	for (size_t i = 0; i < using_outs.size(); ++i) {
		auto out = using_outs[i];

		// if we don't already know of a particular out's mix outs (from a prior attempt),
		// then tie out to a set of mix outs retrieved from the server
		if (prior_attempt_unspent_outs_to_mix_outs_new.find(out.public_key) == prior_attempt_unspent_outs_to_mix_outs_new.end()) {
			for (size_t j = 0; j < mix_outs_from_server.size(); ++j) {
				if ((out.rct != none && mix_outs_from_server[j].amount != 0) ||
					(out.rct == none && mix_outs_from_server[j].amount != out.amount)) {
					continue;
				}

				RandomAmountOutputs output_mix_outs = pop_index(mix_outs_from_server, j);

				// if we need to retry constructing tx, will remember to use same mix outs for this out on subsequent attempt(s)
				prior_attempt_unspent_outs_to_mix_outs_new[out.public_key] = output_mix_outs.outputs;
				mix_outs.push_back(std::move(output_mix_outs));

				break;
			}
		} else {
			RandomAmountOutputs output_mix_outs;
			output_mix_outs.outputs = prior_attempt_unspent_outs_to_mix_outs_new[out.public_key];
			output_mix_outs.amount = out.amount;
			mix_outs.push_back(std::move(output_mix_outs));
		}
	}

	// we expect to have a set of mix outs for every output in the tx
	if (mix_outs.size() != using_outs.size()) {
		retVals.errCode = notEnoughUsableDecoysFound;
		return;
	}

	// we expect to use up all mix outs returned by the server
	if (!mix_outs_from_server.empty()) {
		retVals.errCode = tooManyDecoysRemaining;
		return;
	}

	retVals.mix_outs = std::move(mix_outs);
	retVals.prior_attempt_unspent_outs_to_mix_outs_new = std::move(prior_attempt_unspent_outs_to_mix_outs_new);
}
//
//
//
void beldex_transfer_utils::send_step2__try_create_transaction(
	Send_Step2_RetVals &retVals,
	//
	const boost::optional<master_node_data> &mn_data,
	const string &from_address_string,
	const string &sec_viewKey_string,
	const string &sec_spendKey_string,
	const vector<string> &to_address_strings,
	const boost::optional<string>& payment_id_string,
	const vector<uint64_t>& sending_amounts,
	uint64_t change_amount,
	uint64_t fee_amount,
	uint32_t simple_priority,
	const vector<SpendableOutput> &using_outs,
	uint64_t fee_per_b, // per v8
	uint64_t fee_per_o,
	uint64_t fee_quantization_mask,
	vector<RandomAmountOutputs> &mix_outs, // cannot be const due to convenience__create_transaction's mutability requirement
	use_fork_rules_fn_type use_fork_rules_fn,
	uint64_t unlock_time, // or 0
	cryptonote::network_type nettype,
	const vector<boost::optional<string>> &destination_token_ids,
	uint64_t token_change_amount,
	uint8_t hf_version,
	const boost::optional<token_operation_data> &token_op
) {
	retVals = {};
	//
	Convenience_TransactionConstruction_RetVals create_tx__retVals;
	beldex_transfer_utils::convenience__create_transaction(
		create_tx__retVals,
		mn_data,
		from_address_string,
		sec_viewKey_string, sec_spendKey_string,
		to_address_strings, payment_id_string,
		sending_amounts, change_amount, fee_amount,
		simple_priority,
		using_outs, mix_outs,
		use_fork_rules_fn,
		unlock_time,
		nettype, // TODO: move to after from_address_string
		destination_token_ids, token_change_amount, hf_version, token_op
	);
	if (create_tx__retVals.errCode != noError) {
		retVals.errCode = create_tx__retVals.errCode;
		return;
	}
	THROW_WALLET_EXCEPTION_IF(create_tx__retVals.signed_serialized_tx_string == boost::none, error::wallet_internal_error, "Not expecting no signed_serialized_tx_string given no error");
	//
	size_t blob_size = *create_tx__retVals.txBlob_byteLength;
	uint64_t fee_actually_needed = calculate_fee(
		true/*use_per_byte_fee*/,
		*create_tx__retVals.tx, blob_size,
		get_base_fee(fee_per_b)/*i.e. fee_per_b*/,
		fee_per_o,
		get_fee_percent(simple_priority,txtype::standard),
		fee_quantization_mask
	);
//	if (fee_actually_needed > fee_amount) {
//		cout << "Need to reconstruct tx with fee of at least " << fee_actually_needed << "." << endl;
//		retVals.tx_must_be_reconstructed = true;
//		retVals.fee_actually_needed = fee_actually_needed;
//		return;
//	}
	retVals.signed_serialized_tx_string = std::move(*(create_tx__retVals.signed_serialized_tx_string));
	retVals.tx_hash_string = std::move(*(create_tx__retVals.tx_hash_string));
	retVals.tx_key_string = std::move(*(create_tx__retVals.tx_key_string));
	retVals.tx_pub_key_string = std::move(*(create_tx__retVals.tx_pub_key_string));
}
//
//
// Underlying implementations to mimic historical JS-land create_transaction / construct_tx impls
//
void beldex_transfer_utils::create_transaction(
	TransactionConstruction_RetVals &retVals,
	const boost::optional<master_node_data> &mn_data,
	const bool isRegister,
	const account_keys& sender_account_keys, // this will reference a particular hw::device
	const uint32_t subaddr_account_idx,
	const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses,
	const vector<address_parse_info> &to_addrs, 
	const vector<uint64_t>& sending_amounts,
	uint64_t change_amount,
	uint64_t fee_amount,
	uint32_t simple_priority,
	const vector<SpendableOutput> &outputs,
	vector<RandomAmountOutputs> &mix_outs, 
	const std::vector<uint8_t> &extra,
	use_fork_rules_fn_type use_fork_rules_fn,
	uint64_t unlock_time, // or 0
	bool rct,
	cryptonote::network_type nettype,
	const vector<boost::optional<string>> &destination_token_ids,
	uint64_t token_change_amount,
	uint8_t hf_version,
	const boost::optional<token_operation_data> &token_op
) {
	retVals.errCode = noError;
	// Historically this function hard-coded hf_version = 18, which meant every
	// gate at or above 18 in construct_tx was permanently off -- including the
	// HF21 private-token branch. 0 reproduces that behaviour for callers that
	// have not been updated to pass the real fork version through.
	const uint8_t effective_hf_version = hf_version != 0 ? hf_version : 18;
	const bool tokens_active = effective_hf_version >= HF_VERSION_PRIVATE_TOKENS;
	// HF21: a token descriptor operation (deploy a new asset). Re-derive the
	// token id from the descriptor that is actually going on chain rather than
	// trusting the one handed down: construct_tx will recompute it the same way
	// from tx.extra, and if the two disagree every output would be tagged with a
	// token id the chain does not recognise -- an unspendable transaction.
	if (token_op != none) {
		if (!tokens_active) {
			retVals.errCode = notYetImplemented;
			return;
		}
		const crypto::token_id derived = cryptonote::get_or_calculate_token_id(token_op->tdo);
		if (derived == crypto::null_tid || derived != token_op->token_id
			|| token_op->tx_type() == txtype::standard) {
			retVals.errCode = invalidTokenOperation;
			return;
		}
	}
	//
	// TODO: do we need to sort destinations by amount, here, according to 'decompose_destinations'?
	//
	uint32_t fake_outputs_count = fixed_mixinsize();
	rct::RangeProofType range_proof_type =rct::RangeProofType::PaddedBulletproof;
	int bp_version = 4;
	const rct::RCTConfig rct_config {
		range_proof_type,
		bp_version,
	};
	//
	if (mix_outs.size() != outputs.size() && fake_outputs_count != 0) {
		retVals.errCode = wrongNumberOfMixOutsProvided;
		return;
	}
	for (size_t i = 0; i < mix_outs.size(); i++) {
		if (mix_outs[i].outputs.size() < fake_outputs_count) {
			retVals.errCode = notEnoughOutputsForMixing;
			return;
		}
	}
	if (!sender_account_keys.get_device().verify_keys(sender_account_keys.m_spend_secret_key, sender_account_keys.m_account_address.m_spend_public_key)
		|| !sender_account_keys.get_device().verify_keys(sender_account_keys.m_view_secret_key, sender_account_keys.m_account_address.m_view_public_key)) {
		retVals.errCode = invalidSecretKeys;
		return;
	}
// XXX: need overflow check?
// 	if (sending_amount > std::numeric_limits<uint64_t>::max() - change_amount
//		|| sending_amount + change_amount > std::numeric_limits<uint64_t>::max() - fee_amount) {
//		retVals.errCode = outputAmountOverflow;
//		return;
//	}
 	// Only NATIVE destinations consume BDX. A token destination's amount is
 	// denominated in that token, so folding it in here would make the
 	// found/needed reconciliation below reject every valid token transfer.
 	uint64_t needed_money = fee_amount + change_amount;
 	for (size_t i = 0; i < sending_amounts.size(); ++i) {
 		const bool dst_is_token = i < destination_token_ids.size()
 			&& destination_token_ids[i] != none && !destination_token_ids[i]->empty();
 		if (!dst_is_token) {
 			needed_money += sending_amounts[i];
 		}
 	}
	//
	uint64_t found_money = 0;
	std::vector<tx_source_entry> sources;
	// TODO: log: "Selected transfers: " << outputs
	for (size_t out_index = 0; out_index < outputs.size(); out_index++) {
		// Token inputs are denominated in their own token and pay no part of
		// the BDX fee, so they stay out of the native balance reconciliation.
		if (!outputs[out_index].is_zarcanum()) {
			found_money += outputs[out_index].amount;
		}
		if (found_money > UINT64_MAX) {
			retVals.errCode = inputAmountOverflow;
		}
		auto src = tx_source_entry{};
		src.amount = outputs[out_index].amount;
		src.rct = outputs[out_index].rct != none && (*(outputs[out_index].rct)).empty() == false;
		//
		typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
		if (mix_outs.size() != 0) {
			// Sort fake outputs by global index
			std::sort(mix_outs[out_index].outputs.begin(), mix_outs[out_index].outputs.end(), [] (
				RandomAmountOutput const& a,
				RandomAmountOutput const& b
			) {
				return a.global_index < b.global_index;
			});
			for (
				size_t j = 0;
				src.outputs.size() < fake_outputs_count && j < mix_outs[out_index].outputs.size();
				j++
			) {
				auto mix_out__output = mix_outs[out_index].outputs[j];
				if (mix_out__output.global_index == outputs[out_index].global_index) {
					LOG_PRINT_L2("got mixin the same as output, skipping");
					continue;
				}
				auto oe = tx_output_entry{};
				oe.first = mix_out__output.global_index;
				//
				crypto::public_key public_key{};
				if(!string_tools::hex_to_pod(mix_out__output.public_key, public_key)) {
					retVals.errCode = givenAnInvalidPubKey;
					return;
				}
				oe.second.dest = rct::pk2rct(public_key);
				//
				if (mix_out__output.rct != boost::none && (*(mix_out__output.rct)).empty() == false) {
					rct::key commit;
					_rct_hex_to_rct_commit(*mix_out__output.rct, commit);
					oe.second.mask = commit;
				} else {
					if (outputs[out_index].rct != boost::none && (*(outputs[out_index].rct)).empty() == false) {
						retVals.errCode = mixRCTOutsMissingCommit;
						return;
					}
					oe.second.mask = rct::zeroCommit(src.amount); //create identity-masked commitment for non-rct mix input
				}
				src.outputs.push_back(oe);
			}
		}
		auto real_oe = tx_output_entry{};
		real_oe.first = outputs[out_index].global_index;
		//
		crypto::public_key public_key{};
		if(!string_tools::validate_hex(64, outputs[out_index].public_key)) {
			retVals.errCode = givenAnInvalidPubKey;
			return;
		}
		if (!string_tools::hex_to_pod(outputs[out_index].public_key, public_key)) {
			retVals.errCode = givenAnInvalidPubKey;
			return;
		}
		real_oe.second.dest = rct::pk2rct(public_key);
		//
		if (outputs[out_index].rct != none
				&& outputs[out_index].rct->empty() == false
				&& *outputs[out_index].rct != "coinbase") {
			rct::key commit;
			_rct_hex_to_rct_commit(*(outputs[out_index].rct), commit);
			real_oe.second.mask = commit; //add commitment for real input
		} else {
			real_oe.second.mask = rct::zeroCommit(src.amount/*aka outputs[out_index].amount*/); //create identity-masked commitment for non-rct input
		}
		//
		// Add real_oe to outputs
		uint64_t real_output_index = src.outputs.size();
		for (size_t j = 0; j < src.outputs.size(); j++) {
			if (real_oe.first < src.outputs[j].first) {
				real_output_index = j;
				break;
			}
		}
		src.outputs.insert(src.outputs.begin() + real_output_index, real_oe);
		//
		crypto::public_key tx_pub_key{};
		if(!string_tools::validate_hex(64, outputs[out_index].tx_pub_key)) {
			retVals.errCode = givenAnInvalidPubKey;
			return;
		}
		string_tools::hex_to_pod(outputs[out_index].tx_pub_key, tx_pub_key);
		src.real_out_tx_key = tx_pub_key;
		//
		src.real_out_additional_tx_keys = get_additional_tx_pub_keys_from_extra(extra);
		//
		src.real_output = real_output_index;
		uint64_t internal_output_index = outputs[out_index].index;
		src.real_output_in_tx_index = internal_output_index;
		//
		src.rct = outputs[out_index].rct != boost::none && (*(outputs[out_index].rct)).empty() == false;
		if (src.rct) {
			rct::key decrypted_mask;
			bool r = _rct_hex_to_decrypted_mask(
				*(outputs[out_index].rct),
				sender_account_keys.m_view_secret_key,
				tx_pub_key,
				internal_output_index,
				decrypted_mask
			);
			if (!r) {
				retVals.errCode = cantGetDecryptedMaskFromRCTHex;
				return;
			}
			src.mask = decrypted_mask;
//			rct::key calculated_commit = rct::commit(outputs[out_index].amount, decrypted_mask);
//			rct::key parsed_commit;
//			_rct_hex_to_rct_commit(*(outputs[out_index].rct), parsed_commit);
//			if (!(real_oe.second.mask == calculated_commit)) { // real_oe.second.mask==parsed_commit(outputs[out_index].rct)
//				retVals.errCode = invalidCommitOrMaskOnOutputRCT;
//				return;
//			}
		} else {
			rct::identity(src.mask); // in the original cn_utils impl this was left as null for generate_key_image_helper_rct to fill in with identity I
		}
		//
		// ── HF21: private token (zarcanum) input ───────────────────────────
		if (outputs[out_index].is_zarcanum()) {
			if (!tokens_active) {
				retVals.errCode = notYetImplemented; // token input offered before HF21
				return;
			}
			// Rebuild the on-chain output so the plaintext token id, amount,
			// Pedersen mask and -- crucially -- the token-blinding scalar r can
			// be recovered locally. r has no other source and is required to
			// reconstruct T_real when building the pseudo-output.
			cryptonote::tx_out_zarcanum zout{};
			zout.stealth_address = public_key; // parsed above from outputs[].public_key
			if (!string_tools::hex_to_pod(*outputs[out_index].amount_commitment, zout.amount_commitment)
				|| !string_tools::hex_to_pod(*outputs[out_index].blinded_token_id, zout.blinded_token_id)) {
				retVals.errCode = givenAnInvalidPubKey;
				return;
			}
			zout.encrypted_amount = *outputs[out_index].encrypted_amount;
			//
			crypto::key_derivation derivation{};
			if (!generate_key_derivation(tx_pub_key, sender_account_keys.m_view_secret_key, derivation)) {
				retVals.errCode = cantGetDecryptedMaskFromRCTHex;
				return;
			}
			uint64_t zc_amount = 0;
			crypto::token_id zc_token_id{};
			rct::key zc_amount_mask{}, zc_token_mask{};
			if (!cryptonote::decode_zarcanum_output(
					sender_account_keys, zout, derivation, internal_output_index,
					zc_amount, zc_token_id, zc_amount_mask, zc_token_mask)) {
				// The commitment did not reopen: the output is not ours, or the
				// server sent inconsistent fields.
				retVals.errCode = invalidCommitOrMaskOnOutputRCT;
				return;
			}
			// The LWS-supplied token id is only a selection hint; the authority
			// is what just came out of the output itself.
			if (outputs[out_index].token_id != none) {
				crypto::token_id claimed{};
				if (!string_tools::hex_to_pod(*outputs[out_index].token_id, claimed) || !(claimed == zc_token_id)) {
					retVals.errCode = invalidCommitOrMaskOnOutputRCT;
					return;
				}
			}
			if (zc_amount != outputs[out_index].amount) {
				retVals.errCode = invalidCommitOrMaskOnOutputRCT;
				return;
			}
			src.token_id   = zc_token_id;
			src.token_mask = zc_token_mask;
			src.mask       = zc_amount_mask;
			// The real ring member's own values, not a zeroCommit.
			src.outputs[real_output_index].second.mask = rct::pk2rct(zout.amount_commitment);
			//
			// Third CLSAG-GGX layer: the blinded token id of every ring member,
			// index-aligned with src.outputs. A native decoy has none on chain;
			// its slot is filled with its own amount commitment, which is a
			// well-formed point of unknown discrete log w.r.t. X -- exactly what
			// a decoy slot needs, and what keeps native outputs usable as decoys
			// for token inputs (see TOKEN_RING_SIZE in cryptonote_config.h).
			src.ring_blinded_token_ids.assign(src.outputs.size(), crypto::null_tid);
			for (size_t j = 0; j < src.outputs.size(); j++) {
				if (j == real_output_index) {
					src.ring_blinded_token_ids[j] = zout.blinded_token_id;
					continue;
				}
				const auto decoy_it = _find_decoy_by_global_index(mix_outs, out_index, src.outputs[j].first);
				if (decoy_it != nullptr && decoy_it->blinded_token_id != none
					&& !decoy_it->blinded_token_id->empty()) {
					crypto::token_id decoy_tid{};
					if (!string_tools::hex_to_pod(*decoy_it->blinded_token_id, decoy_tid)) {
						retVals.errCode = givenAnInvalidPubKey;
						return;
					}
					src.ring_blinded_token_ids[j] = decoy_tid;
				} else {
					src.ring_blinded_token_ids[j] =
						rct::rct2tid(src.outputs[j].second.mask);
				}
			}
		}
		// not doing multisig here yet
		src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
		sources.push_back(src);
	}
	//
	// TODO: if this is a multisig wallet, create a list of multisig signers we can use
	std::vector<cryptonote::tx_destination_entry> splitted_dsts;
	THROW_WALLET_EXCEPTION_IF(to_addrs.size() != sending_amounts.size(),
 							  error::wallet_internal_error,
 							  "Amounts don't match destinations");
 	crypto::token_id sending_token_id = crypto::null_tid; // for the token change output
 	for (size_t i = 0; i < to_addrs.size(); ++i) {
 		tx_destination_entry to_dst{};
 		to_dst.addr = to_addrs[i].address;
 		to_dst.amount = sending_amounts[i];
 		to_dst.is_subaddress = to_addrs[i].is_subaddress;
 		// HF21: mark this destination as a private-token output. Leaving
 		// token_id null keeps it an ordinary BDX txout_to_key.
 		if (i < destination_token_ids.size() && destination_token_ids[i] != none
 			&& !destination_token_ids[i]->empty()) {
 			if (!tokens_active) {
 				retVals.errCode = notYetImplemented;
 				return;
 			}
 			crypto::token_id dst_tid{};
 			if (!string_tools::hex_to_pod(*destination_token_ids[i], dst_tid)) {
 				retVals.errCode = givenAnInvalidPubKey;
 				return;
 			}
 			to_dst.token_id = dst_tid;
 			sending_token_id = dst_tid;
 		}
 		splitted_dsts.push_back(to_dst);
 	}
 	// HF21: token change goes back to the sender as a further zarcanum output.
 	// It is accounted separately from `change_amount`, which stays the BDX
 	// change -- a token tx spends native inputs for its fee as well.
 	if (token_change_amount != 0) {
 		if (!tokens_active || sending_token_id == crypto::null_tid) {
 			retVals.errCode = notYetImplemented;
 			return;
 		}
 		tx_destination_entry token_change_dst{};
 		token_change_dst.addr = sender_account_keys.m_account_address;
 		token_change_dst.amount = token_change_amount;
 		token_change_dst.token_id = sending_token_id;
 		splitted_dsts.push_back(token_change_dst);
 	}
 	// HF21: a deploy/mint must emit at least MIN_TOKEN_MINT_OUTPUTS zarcanum
 	// outputs. The chain enforces this so a brand-new token has a ring to hide
 	// in from its very first spend -- with a single output there would be
 	// nothing to hide among. The padding outputs are zero-amount self-sends:
 	// they cost fee and nothing else, and the wallet receives them as its own
 	// ring-member candidates. wallet2::create_token_deploy_tx does exactly this.
 	if (token_op != none) {
 		size_t zc_count = 0;
 		for (const auto &d : splitted_dsts) {
 			if (d.is_zarcanum()) {
 				++zc_count;
 			}
 		}
 		for (size_t i = zc_count; i < (size_t)MIN_TOKEN_MINT_OUTPUTS; ++i) {
 			tx_destination_entry pad_dst{};
 			pad_dst.addr = sender_account_keys.m_account_address;
 			pad_dst.amount = 0;
 			pad_dst.is_subaddress = false;
 			pad_dst.token_id = token_op->token_id;
 			splitted_dsts.push_back(pad_dst);
 		}
 	}
	//
	cryptonote::tx_destination_entry change_dst{};
	change_dst.amount = change_amount;
	//
	if (change_dst.amount == 0) {
		if (splitted_dsts.size() == 1) {
			// If the change is 0, send it to a random address, to avoid confusing
			// the sender with a 0 amount output. We send a 0 amount in order to avoid
			// letting the destination be able to work out which of the inputs is the
			// real one in our rings
			LOG_PRINT_L2("generating dummy address for 0 change");
			cryptonote::account_base dummy;
			dummy.generate();
			change_dst.addr = dummy.get_keys().m_account_address;
			LOG_PRINT_L2("generated dummy address for 0 change");
			splitted_dsts.push_back(change_dst);
		}
	} else {
		change_dst.addr = sender_account_keys.m_account_address;
		splitted_dsts.push_back(change_dst);
	}
	//
	// TODO: log: "sources: " << sources
	if (found_money > needed_money) {
		if (change_dst.amount != fee_amount) {
			retVals.errCode = resultFeeNotEqualToGiven; // aka "early fee calculation != later"
			return; // early
		}
	} else if (found_money < needed_money) {
		retVals.errCode = needMoreMoneyThanFound; // TODO: return actual found_money and needed_money in generalized err params in return val
		return;
	}
	//
	cryptonote::transaction tx;
	crypto::secret_key tx_key;
	std::vector<crypto::secret_key> additional_tx_keys;
	beldex_construct_tx_params tx_params;
	tx_params.hf_version = effective_hf_version;
	if (token_op != none) {
		// HF21: consensus reads the operation type back out of tx.extra and
		// requires it to match tx.type, and requires the burn that goes with it.
		// step1 already folded that burn into fee_amount, so the inputs cover it.
		tx_params.tx_type    = token_op->tx_type();
		tx_params.burn_fixed = token_op->burn_amount(effective_hf_version);
	}
	else if(isRegister){
		// std::cout << "Place for register create construct params" << std::endl;
		tx_params.tx_type = txtype::stake;
	}
	else
		tx_params.tx_type = txtype::standard;

	// Flash sets its own burn. It must not overwrite a token operation's, which
	// is a protocol requirement rather than a priority surcharge -- so token
	// operations reject flash priority upstream and it is guarded here too.
	if(simple_priority == 5 && token_op == none){
		tx_params.burn_fixed   = FLASH_BURN_FIXED;
    	tx_params.burn_percent = FLASH_BURN_TX_FEE_PERCENT_OLD;
	}
	uint64_t burn_fixed = 0, burn_percent = 0;
	std::swap(burn_fixed, tx_params.burn_fixed);
  	std::swap(burn_percent, tx_params.burn_percent);

	bool burning = burn_fixed || burn_percent;
	std::vector<uint8_t> extra_plus; // Copy and modified from input if modification needed
  	const std::vector<uint8_t> &extra_flash = burning ? extra_plus : extra;
	uint64_t fixed_fee = 0;
	uint64_t fee_percent = get_fee_percent(simple_priority,txtype::standard);
	if (burning)
  	{
		extra_plus = extra;
		add_burned_amount_to_tx_extra(extra_plus, 0);
		fixed_fee += burn_fixed;
		// THROW_WALLET_EXCEPTION_IF(burn_percent > fee_percent, error::wallet_internal_error, "invalid burn fees: cannot burn more than the tx fee");
  	}

	if (burning)
      tx_params.burn_fixed = burn_fixed + (fee_amount - burn_fixed) * burn_percent / fee_percent;


	bool r = cryptonote::construct_tx_and_get_tx_key(
		sender_account_keys, subaddresses,
		sources, splitted_dsts, change_dst, extra_flash,
		tx, unlock_time, tx_key, additional_tx_keys,
		rct_config, nullptr,tx_params);

	LOG_PRINT_L2("constructed tx, r="<<r);
	if (!r) {
		// TODO: return error::tx_not_constructed, sources, dsts, unlock_time, nettype
		retVals.errCode = transactionNotConstructed;
		return;
	}
	if (get_upper_transaction_weight_limit(0, use_fork_rules_fn) <= get_transaction_weight(tx)) {
		// TODO: return error::tx_too_big, tx, upper_transaction_weight_limit
		retVals.errCode = transactionTooBig;
		return;
	}
	bool use_bulletproofs = !tx.rct_signatures.p.bulletproofs_plus.empty();
	THROW_WALLET_EXCEPTION_IF(use_bulletproofs != true, error::wallet_internal_error, "Expected tx use_bulletproofs to equal bulletproof flag");
	//
	retVals.tx = tx;
	retVals.tx_key = tx_key;
	retVals.additional_tx_keys = additional_tx_keys;
}
//
void beldex_transfer_utils::convenience__create_transaction(
	Convenience_TransactionConstruction_RetVals &retVals,
	const boost::optional<master_node_data> &mn_data,
	const string &from_address_string,
	const string &sec_viewKey_string,
	const string &sec_spendKey_string,
	const vector<string> &to_address_strings,
	const boost::optional<string>& payment_id_string,
	const vector<uint64_t>& sending_amounts,
	uint64_t change_amount,
	uint64_t fee_amount,
	uint32_t simple_priority,
	const vector<SpendableOutput> &outputs,
	vector<RandomAmountOutputs> &mix_outs,
	use_fork_rules_fn_type use_fork_rules_fn,
	uint64_t unlock_time,
	network_type nettype,
	const vector<boost::optional<string>> &destination_token_ids,
	uint64_t token_change_amount,
	uint8_t hf_version,
	const boost::optional<token_operation_data> &token_op
) {
	retVals.errCode = noError;
	//
	cryptonote::address_parse_info from_addr_info;
	THROW_WALLET_EXCEPTION_IF(!cryptonote::get_account_address_from_str(from_addr_info, nettype, from_address_string), error::wallet_internal_error, "Couldn't parse from-address");
	cryptonote::account_keys account_keys;
	{
		account_keys.m_account_address = from_addr_info.address;
		//
		crypto::secret_key sec_viewKey;
		THROW_WALLET_EXCEPTION_IF(!string_tools::hex_to_pod(sec_viewKey_string, sec_viewKey), error::wallet_internal_error, "Couldn't parse view key");
		account_keys.m_view_secret_key = sec_viewKey;
		//
		crypto::secret_key sec_spendKey;
		THROW_WALLET_EXCEPTION_IF(!string_tools::hex_to_pod(sec_spendKey_string, sec_spendKey), error::wallet_internal_error, "Couldn't parse spend key");
		account_keys.m_spend_secret_key = sec_spendKey;
	}
	vector<cryptonote::address_parse_info> to_addr_infos(to_address_strings.size());
 	size_t to_addr_idx = 0;
 	for (const auto& addr : to_address_strings) {
 		THROW_WALLET_EXCEPTION_IF(
 			addr.find(".") != std::string::npos, // assumed to be an OA address asXMR addresses do not have periods and OA addrs must
 			error::wallet_internal_error,
 			"Integrators must resolve OA addresses before calling Send"
 		); // This would be an app code fault
 		if (!cryptonote::get_account_address_from_str(to_addr_infos[to_addr_idx++], nettype, addr)) {
 			retVals.errCode = couldntDecodeToAddress;
 			return;
 		}
	}
	//
	std::vector<uint8_t> extra;
	
	bool isRegister =false;
	// mn_data is optional and the send-funds bridge is not the only caller:
	// serial_bridge's step2 passes none, as does any non-registration send.
	// Dereferencing it unconditionally aborts on an assertions-enabled build
	// and reads uninitialised memory on one without.
	if(mn_data != boost::none && mn_data->contributor_args.addresses.size() ){
		const master_node_data &data = *mn_data;
		//extra process
		cryptonote::account_public_address address = data.contributor_args.addresses[0];
		// std::cout << " Data.master_node_key : "<< data.master_node_key << std::endl;
		// std::cout << " Data.signature : "<< data.signature << std::endl;
		// std::cout << " Data.Contributor size : " << data.contributor_args.addresses.size() << std::endl;
		// std::cout << " Data.Contributor porsions size : " << data.contributor_args.portions.size() << std::endl;
		// std::vector<uint8_t> extra_register;
		cryptonote::add_master_node_contributor_to_tx_extra(extra, address);

        cryptonote::add_master_node_pubkey_to_tx_extra(extra, data.master_node_key);

        cryptonote::add_master_node_register_to_tx_extra(extra, data.contributor_args.addresses, data.contributor_args.portions_for_operator, data.contributor_args.portions, data.time_stamp, data.signature);
		// std::cout << "extras: " << extra.size() << std::endl;
		for(auto it : extra)
		{
			// std::cout << it <<" ";
		}
		isRegister= true;
	}

	CreateTransactionErrorCode tx_extra__code = _add_pid_to_tx_extra(payment_id_string, extra);
	if (tx_extra__code != noError) {
		retVals.errCode = tx_extra__code;
		return;
	}
	// HF21: the token descriptor operation (deploy a new asset). This is the
	// only place it enters the transaction -- consensus reads the descriptor,
	// the operation type and the token id back out of tx.extra, so the id the
	// user was shown is only real once these bytes are here. step1 has already
	// added an identical field to its own throwaway `extra` so that the fee was
	// estimated against the true size.
	if (token_op != none) {
		if (!cryptonote::add_token_descriptor_operation_to_tx_extra(extra, token_op->tdo)) {
			retVals.errCode = couldntAddTokenOperationToTXExtra;
			return;
		}
	}
	bool payment_id_seen = payment_id_string != none; // logically this is true since payment_id_string has passed validation (or we'd have errored)
	for (const auto& to_addr_info : to_addr_infos) {
		if (to_addr_info.is_subaddress && payment_id_seen) {
 			retVals.errCode = cantUsePIDWithSubAddress; // Never use a subaddress with a payment ID
 			return;
		}
		if (to_addr_info.has_payment_id) {
 			if (payment_id_seen) {
 				retVals.errCode = nonZeroPIDWithIntAddress; // can't use int addr at same time as supplying manual pid
 				return;
 			}
 			if (to_addr_info.is_subaddress) {
 				THROW_WALLET_EXCEPTION_IF(false, error::wallet_internal_error, "Unexpected is_subaddress && has_payment_id"); // should never happen
 				return;
 			}
 			std::string extra_nonce;
 			cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, to_addr_info.payment_id);
 			bool r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
 			if (!r) {
 				retVals.errCode = couldntAddPIDNonceToTXExtra;
 				return;
 			}
 			payment_id_seen = true;
		}
	}
	//
	uint32_t subaddr_account_idx = 0;
	std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
	subaddresses[account_keys.m_account_address.m_spend_public_key] = {0,0};
	//
	TransactionConstruction_RetVals actualCall_retVals;
	create_transaction(
		actualCall_retVals,
		mn_data,isRegister,
		account_keys, subaddr_account_idx, subaddresses,
		to_addr_infos,
		sending_amounts, change_amount, fee_amount,
		simple_priority,
		outputs, mix_outs,
		extra, // TODO: move to after address
		use_fork_rules_fn,
		unlock_time, true/*rct*/, nettype,
		destination_token_ids, token_change_amount, hf_version, token_op
	);
	if (actualCall_retVals.errCode != noError) {
		retVals.errCode = actualCall_retVals.errCode; // pass-through
		return; // already set the error
	}
	auto txBlob = t_serializable_object_to_blob(*actualCall_retVals.tx);
	size_t txBlob_byteLength = txBlob.size();
	//	cout << "txBlob: " << txBlob << endl;
//	cout << "txBlob_byteLength: " << txBlob_byteLength << endl;
	THROW_WALLET_EXCEPTION_IF(txBlob_byteLength <= 0, error::wallet_internal_error, "Expected tx blob byte length > 0");
	//
	// tx hash
	retVals.tx_hash_string = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(*actualCall_retVals.tx));
	// signed serialized tx
	retVals.signed_serialized_tx_string = epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(*actualCall_retVals.tx));
	// (concatenated) tx key
	{
		ostringstream oss;
		oss << epee::string_tools::pod_to_hex(*actualCall_retVals.tx_key);
		for (size_t i = 0; i < (*actualCall_retVals.additional_tx_keys).size(); ++i) {
			oss << epee::string_tools::pod_to_hex((*actualCall_retVals.additional_tx_keys)[i]);
		}
		retVals.tx_key_string = oss.str();
	}
	{
		ostringstream oss;
		oss << epee::string_tools::pod_to_hex(get_tx_pub_key_from_extra(*actualCall_retVals.tx));
		retVals.tx_pub_key_string = oss.str();
	}
	retVals.tx = *actualCall_retVals.tx; // for calculating block weight; FIXME: std::move?
	//
//	cout << "out 0: " << string_tools::pod_to_hex(boost::get<txout_to_key>((*(actualCall_retVals.tx)).vout[0].target).key) << endl;
//	cout << "out 1: " << string_tools::pod_to_hex(boost::get<txout_to_key>((*(actualCall_retVals.tx)).vout[1].target).key) << endl;
	//	
	retVals.txBlob_byteLength = txBlob_byteLength;
}
