//
//  beldex_transfer_utils.hpp
//  Copyright (c) 2014-2019, MyMonero.com
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
#ifndef beldex_transfer_utils_hpp
#define beldex_transfer_utils_hpp
//
#include <boost/optional.hpp>
//
#include "epee/string_tools.h"
//
#include "crypto.h"
#include "cryptonote_basic.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_tx_utils.h"
#include "ringct/rctSigs.h"
//
#include "beldex_fork_rules.hpp"
#include "beldex_fee_utils.hpp"
#include "register_mn_data.hpp"
#include "token_operation_data.hpp"
//
using namespace tools;
#include "tools__ret_vals.hpp"
//
namespace beldex_transfer_utils
{
	using namespace std;
	using namespace boost;
	using namespace cryptonote;
	using namespace beldex_fork_rules;
	using namespace crypto;
	
	// Types - Arguments
	struct SpendableOutput
	{
		uint64_t amount;
		string public_key;
		boost::optional<string> rct;
		uint64_t global_index;
		uint64_t index;
		string tx_pub_key;
		// ── Private token (HF21+) ──────────────────────────────────────────
		// Present together, and only for a tx_out_zarcanum. `public_key` then
		// carries the output's stealth_address rather than a txout_to_key key.
		// The plaintext token id, amount, Pedersen mask and token-blinding
		// scalar are all recovered locally by decode_zarcanum_output() -- the
		// blinding scalar in particular has no other source, and is required
		// to rebuild T_real when spending.
		// Plaintext token id, supplied by the LWS (which holds the view key and
		// already decodes `amount` the same way). Used only to SELECT inputs in
		// step1, which has no keys. create_transaction re-derives it locally
		// from the output itself and rejects a mismatch, so a lying server
		// cannot get a wrong token spent -- it can only cause a failed build.
		boost::optional<string> token_id;           // (64 hex)
		boost::optional<string> blinded_token_id;   // T   (64 hex)
		boost::optional<string> amount_commitment;  // C   (64 hex)
		boost::optional<uint64_t> encrypted_amount; // amount XOR H("enc_amount"..)
		bool is_zarcanum() const {
			return blinded_token_id != boost::none
				&& amount_commitment != boost::none
				&& encrypted_amount != boost::none;
		}
	};
	struct RandomAmountOutput
	{
		uint64_t global_index; // this is, I believe, presently supplied as a string by the API, probably to avoid overflow
		string public_key;
		boost::optional<string> rct;
		// HF21: the decoy's blinded token id, when it is a tx_out_zarcanum.
		// Needed to fill tx_source_entry::ring_blinded_token_ids, which is the
		// third (X) layer of the CLSAG-GGX ring. A decoy that is a native BDX
		// output has none; see _zc_ring_token_id_for_decoy() for what is used
		// in its place.
		boost::optional<string> blinded_token_id;
	};
	struct RandomAmountOutputs
	{
		uint64_t amount;
		vector<RandomAmountOutput> outputs;
	};
	typedef std::unordered_map<string/*public_key*/, std::vector<RandomAmountOutput>> SpendableOutputToRandomAmountOutputs;
	//
	// Types - Return value
	enum CreateTransactionErrorCode // TODO: switch to enum class to fix namespacing
	{ // These codes have values for serialization
		noError 					 	= 0,
		//
		noDestinations				 	= 1,
		wrongNumberOfMixOutsProvided 	= 2,
		notEnoughOutputsForMixing	 	= 3,
		invalidSecretKeys			 	= 4,
		outputAmountOverflow		 	= 5,
		inputAmountOverflow			 	= 6,
		mixRCTOutsMissingCommit		 	= 7,
		resultFeeNotEqualToGiven 		= 8,
		invalidDestinationAddress		= 9,
		nonZeroPIDWithIntAddress		= 10,
		cantUsePIDWithSubAddress		= 11,
		couldntAddPIDNonceToTXExtra		= 12,
		givenAnInvalidPubKey			= 13,
		invalidCommitOrMaskOnOutputRCT	= 14,
		transactionNotConstructed		= 15,
		transactionTooBig				= 16,
		notYetImplemented				= 17,
		couldntDecodeToAddress			= 18,
		invalidPID						= 19,
		enteredAmountTooLow				= 20,
		cantGetDecryptedMaskFromRCTHex	= 21,
		notEnoughUsableDecoysFound		= 22,
		tooManyDecoysRemaining			= 23,
		// HF21 private tokens. Appended at the end so no existing code's numeric
		// value moves -- these are serialized to JavaScript as bare integers.
		couldntAddTokenOperationToTXExtra = 24,
		invalidTokenOperation			= 25,
		needMoreMoneyThanFound			= 90
	};
	static inline const char *err_msg_from_err_code__create_transaction(CreateTransactionErrorCode code)
	{
		switch (code) {
			case noError:
				return "No error";
			case couldntDecodeToAddress:
				return "Couldn't decode address";
			case noDestinations:
				return "No destinations provided";
			case wrongNumberOfMixOutsProvided:
				return "Wrong number of mix outputs provided";
			case notEnoughOutputsForMixing:
				return "Not enough outputs for mixing";
			case invalidSecretKeys:
				return "Invalid secret keys";
			case outputAmountOverflow:
				return "Output amount overflow";
			case inputAmountOverflow:
				return "Input amount overflow";
			case mixRCTOutsMissingCommit:
				return "Mix RCT outs missing commit";
			case resultFeeNotEqualToGiven:
				return "Result fee not equal to given fee";
			case needMoreMoneyThanFound:
				return "Spendable balance too low";
			case invalidDestinationAddress:
				return "Invalid destination address";
			case nonZeroPIDWithIntAddress:
				return "Payment ID must be blank when using an integrated address";
			case cantUsePIDWithSubAddress:
				return "Payment ID must be blank when using a subaddress";
			case couldntAddPIDNonceToTXExtra:
				return "Couldn't add nonce to tx extra";
			case givenAnInvalidPubKey:
				return "Invalid pub key";
			case invalidCommitOrMaskOnOutputRCT:
				return "Invalid commit or mask on output rct";
			case transactionNotConstructed:
				return "Transaction not constructed";
			case transactionTooBig:
				return "Transaction too big";
			case notYetImplemented:
				return "Not yet implemented";
			case invalidPID:
				return "Invalid payment ID";
			case enteredAmountTooLow:
				return "The amount you've entered is too low";
			case notEnoughUsableDecoysFound:
				return "Not enough usable decoys found";
			case tooManyDecoysRemaining:
				return "Too many unused decoys remaining";
			case cantGetDecryptedMaskFromRCTHex:
				return "Can't get decrypted mask from 'rct' hex";
			case couldntAddTokenOperationToTXExtra:
				return "Couldn't add the token operation to tx extra";
			case invalidTokenOperation:
				return "Invalid token operation";
		}
        return "Unknown error";
	}
	//
	// See beldex_send_routine for actual app-lvl interface used by lightwallets 
	//
	//
	// Send_Step* functions procedure for integrators:
	//	1. call GetUnspentOuts endpoint
	//	2. call step1__prepare_params_for_get_decoys to get params for calling RandomOuts; call GetRandomOuts
	//	3. call pre_step2_tie_unspent_outs_to_mix_outs_for_all_future_tx_attempts to use constant set of mix outs for each unpsent out across tx construction attempts
	//	4. call step2__try_… with retVals from Step1 and pre_Step2 (incl using_outs, RandomOuts)
	//		4a. While tx must be reconstructed, re-call step1 passing step2 fee_actually_needed as prior_attempt_size_calcd_fee AND
	// 			passing pre_step2 unspent_outs_to_mix_outs_new as prior_attempt_unspent_outs_to_mix_outs, then repeat steps 2-4
	//		4b. If good tx constructed, proceed to submit/save the tx
	// Note: This separation of steps fully encodes SendFunds_ProcessStep
	//
	struct Send_Step1_RetVals
	{
		CreateTransactionErrorCode errCode; // if != noError, abort Send process
		// for display / information purposes on errCode=needMoreMoneyThanFound during step1:
		uint64_t spendable_balance; //  (effectively but not the same as spendable_balance)
		uint64_t required_balance; // for display / information purposes on errCode=needMoreMoneyThanFound during step1
		//
		// Success case return values
		uint32_t mixin;
		vector<SpendableOutput> using_outs;
		uint64_t using_fee;
		uint64_t final_total_wo_fee;
		uint64_t change_amount;
		// ── Private token send (HF21+) ────────────────────────────────────
		// Only meaningful when requested_token_id was given. The native
		// fields above then account for the BDX side (fee + BDX change) and
		// these for the token side. A token tx spends BOTH: token inputs to
		// cover the transferred amount, and native inputs to pay the fee,
		// which is always denominated in BDX.
		uint64_t token_final_total_wo_fee; // token amount actually being sent
		uint64_t token_change_amount;      // token change back to self
		uint64_t token_spendable_balance;  // for needMoreMoneyThanFound display
		uint64_t token_required_balance;
	};
	void send_step1__prepare_params_for_get_decoys(
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
		boost::optional<uint64_t> prior_attempt_size_calcd_fee, // use this for passing step2 "must-reconstruct" return values back in, i.e. re-entry; when nil, defaults to attempt at network min
		boost::optional<SpendableOutputToRandomAmountOutputs> prior_attempt_unspent_outs_to_mix_outs = none, // use this to make sure upon re-attempting, the calculated fee will be the result of calculate_fee()
		//! HF21+: when set, `sending_amounts` are amounts of THIS token and
		//! inputs are selected from both the token pool (to cover the send)
		//! and the native pool (to cover the fee). When unset, behaviour is
		//! exactly as before.
		boost::optional<string> requested_token_id = none,
		uint8_t hf_version = 0, // 0 = unknown; treated as pre-HF21
		//! HF21+: when set, this is a token descriptor operation (deploy a new
		//! asset) rather than a transfer. It has no token inputs -- the token
		//! does not exist yet -- so selection here is native-only, but the tx is
		//! much larger (MIN_TOKEN_MINT_OUTPUTS zarcanum outputs + the descriptor
		//! in tx.extra) and carries a protocol burn on top of the network fee.
		const boost::optional<token_operation_data> &token_op = none
	);
	struct Tie_Outs_to_Mix_Outs_RetVals
	{
		CreateTransactionErrorCode errCode; // if != noError, abort Send process
		//
		// Success parameters
		vector<RandomAmountOutputs> mix_outs;
		SpendableOutputToRandomAmountOutputs prior_attempt_unspent_outs_to_mix_outs_new;
	};
	void pre_step2_tie_unspent_outs_to_mix_outs_for_all_future_tx_attempts(
		Tie_Outs_to_Mix_Outs_RetVals &retVals,
		//
		const vector<SpendableOutput> &using_outs,
		vector<RandomAmountOutputs> mix_outs_from_server,
		//
		const boost::optional<SpendableOutputToRandomAmountOutputs> &prior_attempt_unspent_outs_to_mix_outs
	);
	//
	struct Send_Step2_RetVals
	{
		CreateTransactionErrorCode errCode; // if != noError, abort Send process
		//
		// Reconstruct-required parameters:
		bool tx_must_be_reconstructed; // if true, re-request RandomOuts with the following parameters and retry step3
		uint64_t fee_actually_needed; // will be non-zero if tx_must_be_reconstructed
		//
		// Success parameters:
		boost::optional<string> signed_serialized_tx_string;
		boost::optional<string> tx_hash_string;
		boost::optional<string> tx_key_string; // this includes additional_tx_keys
		boost::optional<string> tx_pub_key_string; // from get_tx_pub_key_from_extra()
	};
	void send_step2__try_create_transaction(
		Send_Step2_RetVals &retVals,
		//
		const boost::optional<master_node_data> &mn_data,
		const string &from_address_string,
		const string &sec_viewKey_string,
		const string &sec_spendKey_string,
		const vector<string> &to_address_strings,
		const boost::optional<string>& payment_id_string,
		const vector<uint64_t>& sending_amounts, // this gets passed to create_transaction's 'sending_amount'
		uint64_t change_amount,
		uint64_t fee_amount,
		uint32_t simple_priority,
		const vector<SpendableOutput> &using_outs,
		uint64_t fee_per_b, // per v8
		uint64_t fee_per_o,
		uint64_t fee_quantization_mask,
		vector<RandomAmountOutputs> &mix_outs, // it gets sorted
		use_fork_rules_fn_type use_fork_rules_fn,
		uint64_t unlock_time, // or 0
		cryptonote::network_type nettype,
		//! HF21+: one entry per destination, parallel to `to_address_strings`.
		//! Empty (or an unset entry) means that destination is native BDX.
		const vector<boost::optional<string>> &destination_token_ids = {},
		uint64_t token_change_amount = 0,
		uint8_t hf_version = 0,
		//! HF21+: see send_step1__prepare_params_for_get_decoys.
		const boost::optional<token_operation_data> &token_op = none
	);
	//
	//
	// Lower level functions - generally you won't need to call these (these are what used to live in cn_utils.js)
	//
	struct Convenience_TransactionConstruction_RetVals
	{
		CreateTransactionErrorCode errCode;
		//
		boost::optional<string> signed_serialized_tx_string;
		boost::optional<string> tx_hash_string;
		boost::optional<string> tx_key_string; // this includes additional_tx_keys
		boost::optional<string> tx_pub_key_string; // from get_tx_pub_key_from_extra()
		boost::optional<transaction> tx; // for block weight
		boost::optional<size_t> txBlob_byteLength;
	};
	void convenience__create_transaction(
		Convenience_TransactionConstruction_RetVals &retVals,
		const boost::optional<master_node_data> &mn_data,
		const string &from_address_string,
		const string &sec_viewKey_string,
		const string &sec_spendKey_string,
		const vector<string> &to_address_string,
		const boost::optional<string>& payment_id_string,
		const vector<uint64_t>& sending_amounts,
		uint64_t change_amount,
		uint64_t fee_amount,
		uint32_t simple_priority,
		const vector<SpendableOutput> &outputs,
		vector<RandomAmountOutputs> &mix_outs, // get sorted
		use_fork_rules_fn_type use_fork_rules_fn,
		uint64_t unlock_time							= 0, // or 0
		network_type nettype 							= MAINNET,
		const vector<boost::optional<string>> &destination_token_ids = {},
		uint64_t token_change_amount					= 0,
		uint8_t hf_version								= 0,
		//! HF21+: see send_step1__prepare_params_for_get_decoys. This is where
		//! the descriptor operation is written into `extra`.
		const boost::optional<token_operation_data> &token_op = none
	);
	struct TransactionConstruction_RetVals
	{
		CreateTransactionErrorCode errCode;
		//
		boost::optional<transaction> tx;
		boost::optional<secret_key> tx_key;
		boost::optional<vector<secret_key>> additional_tx_keys;
	};
	void create_transaction(
		TransactionConstruction_RetVals &retVals,
		const boost::optional<master_node_data> &mn_data,
		const bool isRegister,
		const account_keys& sender_account_keys, // this will reference a particular hw::device
		const uint32_t subaddr_account_idx, // pass 0 for no subaddrs
		const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses,
		const vector<address_parse_info> &to_addr, // this _must_ include correct .is_subaddr
		const vector<uint64_t>& sending_amounts,
		uint64_t change_amount,
		uint64_t fee_amount,
		uint32_t simple_priority,
		const vector<SpendableOutput> &outputs,
		vector<RandomAmountOutputs> &mix_outs,
		const std::vector<uint8_t> &extra, // this is not declared const b/c it may have the output tx pub key appended to it
		use_fork_rules_fn_type use_fork_rules_fn,
		uint64_t unlock_time							= 0, // or 0
		bool rct 										= true,
		network_type nettype							= MAINNET,
		//! HF21+: parallel to `to_addr`; an unset entry is a native BDX output.
		const vector<boost::optional<string>> &destination_token_ids = {},
		//! HF21+: token change back to the sender, in the token being sent.
		uint64_t token_change_amount					= 0,
		//! Real network fork version. Previously hard-coded to 18 inside
		//! create_transaction, which silently disabled every gate above it.
		//! 0 keeps the historical behaviour.
		uint8_t hf_version								= 0,
		//! HF21+: selects the txtype and the burn, and pads the destinations up
		//! to MIN_TOKEN_MINT_OUTPUTS. `extra` must already contain the matching
		//! descriptor operation -- convenience__create_transaction puts it there.
		const boost::optional<token_operation_data> &token_op = none
	);
}

#endif /* beldex_transfer_utils_hpp */