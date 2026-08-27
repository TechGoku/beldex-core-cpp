// End-to-end test for the HF21 "deploy a new asset" path through
// beldex-core-cpp: send_step1 selection, then send_step2 construction, then
// inspection of the transaction that actually came out.
//
// Build/run with tests/run_token_deploy_test.sh (needs an activated emsdk).
//
// The point of this test is that the deploy path touches the two things a
// light wallet cannot afford to get wrong and cannot check after the fact:
// whether enough BDX was selected to cover the protocol burn as well as the
// fee, and whether the transaction that came out is the shape consensus
// expects. Both are asserted against the real constructed tx, not a model of it.

#include <iostream>
#include <string>
#include <vector>

#include "epee/string_tools.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/token_descriptor_operation_utils.h"
#include "ringct/rctOps.h"
#include "beldex_transfer_utils.hpp"
#include "beldex_fork_rules.hpp"

using namespace std;
using namespace beldex_transfer_utils;

static int g_failures = 0;
static int g_checks = 0;

static void check(bool cond, const string &what)
{
    ++g_checks;
    if (cond) {
        cout << "  PASS " << what << "\n";
    } else {
        cout << "  FAIL " << what << "\n";
        ++g_failures;
    }
}

template <typename A, typename B>
static void check_eq(const A &got, const B &want, const string &what)
{
    ++g_checks;
    if (got == (A)want) {
        cout << "  PASS " << what << " (" << got << ")\n";
    } else {
        cout << "  FAIL " << what << ": got " << got << ", want " << want << "\n";
        ++g_failures;
    }
}

// ── Synthetic wallet-owned outputs ───────────────────────────────────────────
// Built the way a real transaction would build them, so the key image the
// construction path derives actually matches and the commitment actually opens:
// R = r*G, P = Hs(r*A || i)*G + B, mask = genCommitmentMask(Hs(r*A || i)).
static SpendableOutput make_native_out(const cryptonote::account_keys &keys,
                                       uint64_t amount,
                                       uint64_t global_index)
{
    crypto::secret_key tx_sec;
    crypto::public_key tx_pub;
    crypto::generate_keys(tx_pub, tx_sec);

    const size_t out_index = 0;
    crypto::key_derivation derivation;
    if (!crypto::generate_key_derivation(keys.m_account_address.m_view_public_key, tx_sec, derivation))
        throw std::runtime_error("generate_key_derivation failed");

    crypto::public_key out_key;
    if (!crypto::derive_public_key(derivation, out_index, keys.m_account_address.m_spend_public_key, out_key))
        throw std::runtime_error("derive_public_key failed");

    crypto::secret_key scalar;
    crypto::derivation_to_scalar(derivation, out_index, scalar);
    const rct::key mask = rct::genCommitmentMask(rct::sk2rct(scalar));
    const rct::key commit = rct::commit(amount, mask);

    SpendableOutput out{};
    out.amount = amount;
    out.public_key = epee::string_tools::pod_to_hex(out_key);
    out.global_index = global_index;
    out.index = out_index;
    out.tx_pub_key = epee::string_tools::pod_to_hex(tx_pub);
    // "<commit><8-byte amount>" -- the short form, which tells the parser to
    // recompute the mask from the derivation rather than decrypt one.
    out.rct = epee::string_tools::pod_to_hex(commit) + "0000000000000000";
    return out;
}

static vector<RandomAmountOutputs> make_decoys(size_t n_inputs, uint32_t ring)
{
    vector<RandomAmountOutputs> mix_outs;
    uint64_t gi = 1000000;
    for (size_t i = 0; i < n_inputs; ++i) {
        RandomAmountOutputs set{};
        set.amount = 0; // rct
        for (uint32_t j = 0; j < ring; ++j) {
            crypto::secret_key s;
            crypto::public_key p;
            crypto::generate_keys(p, s);
            RandomAmountOutput o{};
            o.global_index = gi++;
            o.public_key = epee::string_tools::pod_to_hex(p);
            o.rct = epee::string_tools::pod_to_hex(rct::commit(0, rct::skGen())) + "0000000000000000";
            set.outputs.push_back(std::move(o));
        }
        mix_outs.push_back(std::move(set));
    }
    return mix_outs;
}

// The descriptor operation the bridge builds for "deploy a new asset".
static token_operation_data make_deploy_op(const cryptonote::account_keys &keys,
                                           uint64_t current_supply,
                                           uint64_t total_max_supply,
                                           uint8_t decimals,
                                           uint32_t salt)
{
    token_operation_data op{};
    op.tdo.operation_type = cryptonote::token_descriptor_operation_type::register_token;
    op.tdo.fields = (uint8_t)(cryptonote::token_field_descriptor | cryptonote::token_field_token_id_salt);
    op.tdo.token_id_salt = salt;
    op.tdo.descriptor.ticker = "DEMO";
    op.tdo.descriptor.full_name = "Demo Token";
    op.tdo.descriptor.meta_info = "";
    op.tdo.descriptor.decimal_point = decimals;
    op.tdo.descriptor.current_supply = current_supply;
    op.tdo.descriptor.total_max_supply = total_max_supply;
    op.tdo.descriptor.owner = keys.m_account_address.m_spend_public_key;
    op.token_id = cryptonote::get_or_calculate_token_id(op.tdo);
    return op;
}

int main()
{
    const uint8_t HF = HF_VERSION_PRIVATE_TOKENS;
    const uint32_t ring = beldex_fork_rules::fixed_mixinsize();
    const uint64_t fee_per_b = 215;
    const uint64_t fee_per_o = 20000000;
    const uint64_t fee_mask = 10000;
    const uint32_t priority = 1;

    cryptonote::account_base acct;
    acct.generate();
    const auto &keys = acct.get_keys();
    const string from_address = cryptonote::get_account_address_as_str(
        cryptonote::network_type::MAINNET, false, keys.m_account_address);
    const string sec_view = epee::string_tools::pod_to_hex(keys.m_view_secret_key);
    const string sec_spend = epee::string_tools::pod_to_hex(keys.m_spend_secret_key);

    auto fork_rules = beldex_fork_rules::make_use_fork_rules_fn(HF);

    // 8 decimals, 1000 tokens initial supply out of a 1,000,000 cap.
    const uint8_t decimals = 8;
    const uint64_t current_supply = 1000ull * 100000000ull;
    const uint64_t max_supply = 1000000ull * 100000000ull;
    token_operation_data deploy_op = make_deploy_op(keys, current_supply, max_supply, decimals, 42);
    const uint64_t expected_burn = tokens::burn_needed(HF, cryptonote::token_descriptor_operation_type::register_token);

    cout << "=== token id derivation ===\n";
    check(deploy_op.token_id != crypto::null_tid, "token id is non-null");
    check(crypto::check_token_key(deploy_op.token_id), "token id is a valid curve point");
    {
        token_operation_data other = make_deploy_op(keys, current_supply, max_supply, decimals, 43);
        check(other.token_id != deploy_op.token_id, "a different salt yields a different token id");
        token_operation_data same = make_deploy_op(keys, current_supply, max_supply, decimals, 42);
        check(same.token_id == deploy_op.token_id, "the same descriptor + salt is deterministic");
    }
    cout << "  burn required: " << expected_burn << " (" << (expected_burn / COIN) << " BDX)\n";

    // ── step1: selection has to cover fee + burn out of native outputs ───────
    cout << "=== step1: selection ===\n";
    vector<SpendableOutput> unspent;
    for (int i = 0; i < 6; ++i) {
        unspent.push_back(make_native_out(keys, 50ull * COIN, 100 + i)); // 300 BDX total
    }
    Send_Step1_RetVals s1{};
    beldex_transfer_utils::send_step1__prepare_params_for_get_decoys(
        s1, boost::none, vector<uint64_t>{current_supply}, false, priority, fork_rules,
        unspent, fee_per_b, fee_per_o, fee_mask,
        boost::none, boost::none,
        boost::optional<string>(epee::string_tools::pod_to_hex(deploy_op.token_id)), HF, deploy_op);

    check_eq((int)s1.errCode, (int)noError, "step1 succeeded");
    if (s1.errCode != noError) {
        cout << "  (" << err_msg_from_err_code__create_transaction(s1.errCode) << ")\n";
        return 1;
    }
    check(s1.using_fee > expected_burn, "using_fee covers the burn plus a network fee");
    check_eq(s1.final_total_wo_fee, (uint64_t)0, "nothing native is being sent");
    check_eq(s1.token_final_total_wo_fee, current_supply, "the token side is the initial supply");
    check_eq(s1.token_change_amount, (uint64_t)0, "a deploy has no token change");
    {
        uint64_t selected = 0;
        bool any_token_inputs = false;
        for (const auto &o : s1.using_outs) {
            selected += o.amount;
            if (o.is_zarcanum()) any_token_inputs = true;
        }
        check(!any_token_inputs, "no token inputs were selected (the token does not exist yet)");
        check_eq(selected, s1.using_fee + s1.change_amount, "inputs balance fee+burn plus change");
        check(selected >= expected_burn, "selected enough to cover the burn");
    }
    // Not enough BDX to cover the burn must be reported, not silently built.
    {
        vector<SpendableOutput> thin;
        thin.push_back(make_native_out(keys, 10ull * COIN, 900)); // way below the 200 BDX burn
        Send_Step1_RetVals s1_thin{};
        beldex_transfer_utils::send_step1__prepare_params_for_get_decoys(
            s1_thin, boost::none, vector<uint64_t>{current_supply}, false, priority, fork_rules,
            thin, fee_per_b, fee_per_o, fee_mask, boost::none, boost::none,
            boost::optional<string>(epee::string_tools::pod_to_hex(deploy_op.token_id)), HF, deploy_op);
        check_eq((int)s1_thin.errCode, (int)needMoreMoneyThanFound,
                 "too little BDX for the burn is reported as needMoreMoneyThanFound");
        check(s1_thin.required_balance > expected_burn, "required_balance includes the burn");
    }

    // ── step2: construct, then inspect what came out ─────────────────────────
    cout << "=== step2: construction ===\n";
    auto mix_outs = make_decoys(s1.using_outs.size(), ring);
    Send_Step2_RetVals s2{};
    beldex_transfer_utils::send_step2__try_create_transaction(
        s2, boost::none, from_address, sec_view, sec_spend,
        vector<string>{from_address}, boost::none,
        vector<uint64_t>{current_supply},
        s1.change_amount, s1.using_fee, priority,
        s1.using_outs, fee_per_b, fee_per_o, fee_mask, mix_outs,
        fork_rules, 0, cryptonote::network_type::MAINNET,
        vector<boost::optional<string>>{boost::optional<string>(epee::string_tools::pod_to_hex(deploy_op.token_id))},
        0, HF, deploy_op);

    check_eq((int)s2.errCode, (int)noError, "step2 succeeded");
    if (s2.errCode != noError) {
        cout << "  (" << err_msg_from_err_code__create_transaction(s2.errCode) << ")\n";
        return 1;
    }
    check(s2.signed_serialized_tx_string != boost::none, "a signed transaction was produced");

    cout << "=== the constructed transaction ===\n";
    cryptonote::blobdata blob;
    check(epee::string_tools::parse_hexstr_to_binbuff(*s2.signed_serialized_tx_string, blob),
          "the serialized tx is valid hex");
    cryptonote::transaction tx{};
    check(cryptonote::parse_and_validate_tx_from_blob(blob, tx), "the tx deserializes");

    check(tx.type == cryptonote::txtype::deploy_new_token, "tx.type is deploy_new_token");

    size_t n_zc_outs = 0, n_native_outs = 0;
    for (const auto &o : tx.vout) {
        if (std::holds_alternative<cryptonote::tx_out_zarcanum>(o.target)) ++n_zc_outs;
        else ++n_native_outs;
    }
    check(n_zc_outs >= (size_t)MIN_TOKEN_MINT_OUTPUTS,
          "at least MIN_TOKEN_MINT_OUTPUTS zarcanum outputs were emitted");
    cout << "  zarcanum outputs: " << n_zc_outs << ", native outputs: " << n_native_outs << "\n";

    cryptonote::tx_extra_token_descriptor_operation on_chain_tdo{};
    check(cryptonote::get_token_descriptor_operation_from_tx_extra(tx.extra, on_chain_tdo),
          "the descriptor operation is in tx.extra");
    check(cryptonote::get_or_calculate_token_id(on_chain_tdo) == deploy_op.token_id,
          "the on-chain descriptor derives the same token id the caller was given");
    check_eq(on_chain_tdo.descriptor.ticker, deploy_op.tdo.descriptor.ticker, "ticker survived");
    check_eq(on_chain_tdo.descriptor.current_supply, current_supply, "current_supply survived");
    check_eq((int)on_chain_tdo.descriptor.decimal_point, (int)decimals, "decimal_point survived");
    check(on_chain_tdo.descriptor.owner == keys.m_account_address.m_spend_public_key,
          "owner is the sending wallet's spend key");
    check(on_chain_tdo.field_is_set(cryptonote::token_field_amount_commitment),
          "construct_tx attached the token amount commitment");

    uint64_t burn_on_chain = cryptonote::get_burned_amount_from_tx_extra(tx.extra);
    check_eq(burn_on_chain, expected_burn, "the burn recorded in tx.extra is the protocol amount");

    check(!tx.token_proofs.empty(), "token proofs were attached");
    cout << "  token proofs: " << tx.token_proofs.size() << ", zc_sig: " << tx.zc_sig.size() << "\n";

    // ── regression: an ordinary BDX send is untouched by any of this ─────────
    cout << "=== regression: ordinary BDX send ===\n";
    for (uint8_t hf : {(uint8_t)18, (uint8_t)HF_VERSION_PRIVATE_TOKENS}) {
        Send_Step1_RetVals bdx{};
        beldex_transfer_utils::send_step1__prepare_params_for_get_decoys(
            bdx, boost::none, vector<uint64_t>{5ull * COIN}, false, priority,
            beldex_fork_rules::make_use_fork_rules_fn(hf),
            unspent, fee_per_b, fee_per_o, fee_mask, boost::none, boost::none,
            boost::none, hf, boost::none);
        check_eq((int)bdx.errCode, (int)noError, "BDX step1 succeeds at hf " + std::to_string((int)hf));
        check(bdx.using_fee < COIN, "BDX fee carries no token burn at hf " + std::to_string((int)hf));
        check_eq(bdx.final_total_wo_fee, 5ull * COIN, "BDX amount is unchanged at hf " + std::to_string((int)hf));
        check_eq(bdx.token_final_total_wo_fee, (uint64_t)0, "BDX send has no token side at hf " + std::to_string((int)hf));
    }

    cout << "\n" << (g_checks - g_failures) << "/" << g_checks << " checks passed"
         << " (failures: " << g_failures << ")\n";
    return g_failures == 0 ? 0 : 1;
}
