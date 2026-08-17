#pragma once // token_operation_data_hpp

#include "cryptonote_tx_utils.h"
#include "token_descriptor_operation_utils.h"
#include "beldex_economy.h"

// HF21 private tokens: a token descriptor operation the caller is asking to
// perform -- currently deploy_new_token ("deploy a new asset").
//
// This mirrors master_node_data (register_mn_data.hpp), which does the same job
// for master-node registration: the bridge/UI layer parses and validates the
// user's input once, and the transfer layer just carries the bundle down and
// turns it into tx.extra + a txtype + a burn at the last moment. Keeping it in
// one struct is what lets every function below take a single defaulted
// `boost::optional<token_operation_data>` argument instead of five.
struct token_operation_data
{
    // Goes into tx.extra verbatim. For a deploy this carries the descriptor
    // (ticker, supply, decimals, owner) and the token id salt.
    cryptonote::tx_extra_token_descriptor_operation tdo{};

    // Derived from `tdo` by cryptonote::get_or_calculate_token_id(). Held here
    // because the id the user was shown, the id the destinations are tagged
    // with, and the id construct_tx recomputes from tx.extra must all be the
    // same one; create_transaction re-derives it and rejects a mismatch rather
    // than trusting whatever the caller passed down.
    crypto::token_id token_id = crypto::null_tid;

    // The tx type this operation is carried by. Consensus reads the operation
    // type out of tx.extra, so these two must agree or the tx is rejected.
    cryptonote::txtype tx_type() const
    {
        using namespace cryptonote;
        switch (tdo.operation_type)
        {
            case token_descriptor_operation_type::register_token: return txtype::deploy_new_token;
            case token_descriptor_operation_type::mint_token:     return txtype::mint_token;
            case token_descriptor_operation_type::update_token:   return txtype::update_token;
            case token_descriptor_operation_type::burn_token:     return txtype::burn_token;
            default:                                              return txtype::standard;
        }
    }

    // BDX that must be burned on top of the ordinary network fee (200 BDX for a
    // deploy). Computed here rather than passed in from JavaScript so a caller
    // cannot under-declare it and produce a tx the network will reject.
    uint64_t burn_amount(uint8_t hf_version) const
    {
        return tokens::burn_needed(hf_version, tdo.operation_type);
    }

    bool is_deploy() const
    {
        return tdo.operation_type == cryptonote::token_descriptor_operation_type::register_token;
    }
};
