#pragma once // token_operation_data_hpp

#include "cryptonote_tx_utils.h"
#include "token_descriptor_operation_utils.h"
#include "beldex_economy.h"

// HF21 private tokens: a token descriptor operation the caller is asking to
// perform -- currently token registration ("deploy a new asset").
//
// This mirrors master_node_data (register_mn_data.hpp), which does the same job
// for master-node registration: the bridge/UI layer parses and validates the
// user's input once, and the transfer layer just carries the bundle down and
// turns it into tx.extra + a txtype + a burn at the last moment. Keeping it in
// one struct is what lets every function below take a single defaulted
// `boost::optional<token_operation_data>` argument instead of five.
// Blocks of headroom added to the registration collateral's unlock height.
//
// Consensus compares the unlock height against the DAEMON's height at
// validation time, while the client only knows the light wallet server's
// reported tip -- which is second-hand and measurably behind: an observed
// 113-block gap against the same server's own scanned height, and growing at
// roughly two blocks a minute. Targeting the exact minimum, or shaving this
// margin close to the observed lag, produces registrations that are rejected
// minutes later for no visible reason.
//
// 1440 blocks is about twelve hours at the 30-second block target: ample
// against any plausible lag, and negligible beside a lock measured in months
// (518,400 blocks). Erring large costs the user a slightly longer lock; erring
// small costs them a transaction that cannot be diagnosed from the client.
// Observed lag between the light wallet server's reported tip and reality has
// exceeded 1,400 blocks on a live testnet, and it grows whenever the server
// falls behind. 10,000 blocks is a few days at the 30-second target -- still
// under 2% of the 518,400-block lock, and large enough that a server having a
// bad day does not silently produce registrations the network will never mine.
inline constexpr uint64_t TOKEN_REGISTRATION_UNLOCK_MARGIN_BLOCKS = 10000;

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
            case token_descriptor_operation_type::register_token: return txtype::register_private_token;
            case token_descriptor_operation_type::mint_token:     return txtype::mint_token;
            case token_descriptor_operation_type::update_token:   return txtype::update_token;
            case token_descriptor_operation_type::burn_token:     return txtype::burn_token;
            default:                                              return txtype::standard;
        }
    }

    // BDX burned on top of the ordinary network fee. Mint and update still
    // burn; registration does not -- it locks collateral instead, see below.
    // Computed here rather than passed in from JavaScript so a caller cannot
    // under-declare it and produce a tx the network will reject.
    uint64_t burn_amount(uint8_t hf_version) const
    {
        return tokens::burn_needed(hf_version, tdo.operation_type);
    }

    // Registration pays no burn. It must instead create a native output back to
    // the registering wallet for REGISTRATION_COLLATERAL_AMOUNT, locked for
    // REGISTRATION_COLLATERAL_LOCK_BLOCKS; consensus rejects a registration
    // without one. The stake returns to the owner when the lock expires, so
    // unlike a burn it has to be *selected for* but is not spent away.
    uint64_t collateral_amount() const
    {
        return is_registration() ? tokens::REGISTRATION_COLLATERAL_AMOUNT : 0;
    }

    bool is_registration() const
    {
        return tdo.operation_type == cryptonote::token_descriptor_operation_type::register_token;
    }
};
