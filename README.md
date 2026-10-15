# ⚰️ Sealed Coffin — a sealed-bid auction on the Tari Ootle

*Bids go into the coffin sealed. Nobody — not other bidders, not the seller, not a block explorer —
learns a bid until the bidding is over. Losers walk away with fresh stealth coins; the ghosts who
never reveal pay for haunting the auction.*

Sealed Coffin is a Tari Ootle **template** (Rust → WASM) for a private, account-free,
second-price (Vickrey) sealed-bid auction:

| Step | Call | What happens |
|---|---|---|
| 1 | `open(seller_key, lot, reserve, deposit, bid_window, reveal_window)` | Anyone opens an auction for a lot (identified only by a 32-byte hash). `seller_key` is a **one-time** Ristretto key. No owner, no admin. |
| 2 | `bid(bidder_key, commitment, signature, deposit)` | The bidder locks **exactly `deposit`** XTM, spent from a **stealth coin**, and publishes only `commitment = SHA-256(domain ‖ auction ‖ amount ‖ salt ‖ bidder_key)`, signed (Schnorr) by a **fresh one-time key**. |
| 3 | `reveal(bidder_key, amount, salt, signature)` | After bidding closes, the bidder opens the commitment. The template recomputes the hash; any mismatch is rejected. |
| 4 | `finalize()` | After the reveal window, anyone settles: highest revealed bid ≥ reserve wins and pays the **second-highest** revealed bid (or the reserve). **Unrevealed bids forfeit their deposit to the seller.** |
| 5 | `refund(bidder_key, statement, signature)` / `collect(statement, signature)` | Every payout leaves the escrow via `Bucket::stealth_transfer` into **fresh Pedersen-committed stealth outputs**. The payee signs a digest of the exact `StealthTransferStatement`, so nobody can redirect it. |

Views: `phase`, `terms`, `result`, `owed_to`, `seller_owed`, `escrow_balance`, and client helpers
`commitment_for`, `payout_digest`.

## Where Tari's privacy does the work

- **Stealth in, stealth out.** Deposits are paid by spending stealth UTXOs; refunds, the winner's
  change and the seller's proceeds go out as new stealth outputs (`Bucket::stealth_transfer` with a
  `StealthTransferStatement`). No account ever touches the auction.
- **No identity in authorisation.** Nothing checks the transaction signer or an account. Every
  state-changing call carries a Ristretto Schnorr signature (engine intrinsic, custom signature
  domain `sealed-coffin/sig/v1`) by a key that exists only for this one auction. A seller's
  auctions, and a bidder's bids across auctions, cannot be grouped by key.
- **Amounts hidden until reveal.** Every bid locks the *same* deposit, so the escrow balance and the
  deposits reveal only *that* someone bid, never *how much*. The commitment is salted (32 random
  bytes) and bound to the auction and the bidder key, so it can neither be brute-forced from a
  small price range nor copied into another auction.
- **Payouts can't be stolen or redirected.** A payout must spend exactly what is owed, only from
  the escrow, only into stealth outputs (no revealed output, no extra inputs, no covenant claims),
  and the signature covers the whole CBOR-encoded statement.
- **Anti-grief.** A bidder who bids and never reveals (to block, to probe, or to keep the price
  hidden while deciding) loses the deposit to the seller.
- **Second-price rule.** Bidding your true value is the dominant strategy, so there is no reason to
  shade bids — sealed bids plus Vickrey pricing is the textbook combination.

## Threat model

| Adversary / attack | Defence | Test |
|---|---|---|
| Observer reads bid amounts during bidding | Equal deposits + salted, key-bound SHA-256 commitments | `successful_auction_…` (escrow = 3 × deposit) |
| Bidder changes their bid after seeing others | Commitment is binding; reveal recomputed on-chain | `wrong_reveal_is_rejected` |
| Reveal with wrong salt / wrong amount | `reveal does not match the commitment` | `wrong_reveal_is_rejected` |
| Reveal twice | `bid already revealed` | `wrong_reveal_is_rejected` |
| Reveal after the window (to react to others) | `the reveal window is closed`; deposit forfeited | `late_reveal_is_rejected_…` |
| Bid-and-vanish griefing | Unrevealed deposit goes to the seller at `finalize` | `late_reveal_is_rejected_…` |
| Someone who learned your opening reveals for you | Reveal must be signed by the bid's one-time key | `foreign_key_is_rejected_everywhere` |
| Thief claims a loser's refund / the seller's proceeds | Signature by the bid key / seller key over the statement digest | `foreign_key_is_rejected_everywhere` |
| Replay a genuine refund signature with a different statement (redirect) | Signature covers SHA-512 of the full CBOR statement | `foreign_key_is_rejected_everywhere` |
| Over-claim (`revealed_amount` > owed) | Payout must spend exactly the amount owed | `losers_are_refunded_exactly_once` |
| Double refund | `already paid` | `losers_are_refunded_exactly_once` |
| Under/over deposit, re-using a bidder key | Exact deposit; one bid per key; no duplicate commitments | `timing_and_deposit_rules_are_enforced` |
| Early reveal, late bid, early/second finalize | Epoch windows enforced with `Consensus::current_epoch()` | `timing_and_deposit_rules_are_enforced` |
| All bids under reserve | Nothing sells, everyone refunded, seller owed 0 | `nothing_sells_below_reserve` |
| Admin changes the rules mid-auction | `OwnerRule::None`, no admin methods | — (by construction) |

Every successful payout in the tests is **spent again** (redeemed into a bank account in a
transaction signed only by the payout's one-time key) to prove the payee really controls exactly
the amount owed.

## Honest limits

- **Revealed bids become public at reveal time**, and the winner and price are public after
  `finalize`. Sealed Coffin hides bids *during* bidding and hides *who* bid; it is not a
  zero-knowledge auction where losing bids stay secret forever. (A ZK range-proof variant is
  future work.)
- **The deposit caps the bid** and is public: it reveals an upper bound on every bid. Choosing a
  generous deposit hides more but locks more capital.
- **Timing and fees link.** Whoever pays the transaction fee, the timing of bids and reveals, and
  the stealth coins spent into the deposit can still be correlated by a careful observer, as with
  any UTXO system without decoys. Fund deposits from fresh stealth coins and pay fees from them.
- **Lose the one-time key, lose the refund.** The key is the only way to claim what is owed.
- **The lot is off-chain.** The auction settles money only; `lot` is a hash of the description.
  Delivering the item (or escrowing a token for it) is out of scope for this version.
- **The bid count is public** (`terms` exposes it), and `MAX_BIDS = 64` bounds gas per finalize.
- **Seller self-bidding (shill bids) is not preventable** with unlinkable keys; the second-price
  rule and the forfeit rule limit but don't eliminate the incentive.
- Tested on the in-process Ootle engine (`tari_template_test_tooling 0.45`), not yet deployed to
  the Esmeralda testnet.

## Build & test

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown --locked   # → sealed_coffin.wasm (~239 KB)
cargo test --locked                                              # 7 end-to-end tests on the real engine
```

`Cargo.lock` is committed on purpose: `tari_engine 0.45.0` does not compile against
`tari_template_lib_types 0.34.1`, so the lock pins `0.34.0`.

Built against `tari_template_lib 0.34.0` and `tari_template_test_tooling 0.45.0`.

## Disclosure

Developed with an AI coding agent; the idea, direction, review and submission are the author's.

## License

MIT — see [LICENSE](LICENSE).
