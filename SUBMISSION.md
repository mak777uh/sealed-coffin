## ⚰️ Sealed Coffin — a sealed-bid auction where nobody sees your bid, or you

**Code (MIT):** https://github.com/mak777uh/sealed-coffin  ← *placeholder, replace when the repo is public*

**Description**

On a transparent chain a "sealed-bid" auction isn't sealed: everyone sees who bid and how much, so
the last bidder snipes, the seller learns your ceiling, and your wallet history tells the world what
you collect. Sealed Coffin is a Tari Ootle template (Rust → WASM) for a **second-price (Vickrey)
sealed-bid auction** in which bids stay sealed until bidding closes and no bidder ever shows an
account.

- `open(seller_key, lot, reserve, deposit, bid_window, reveal_window)` — anyone opens an auction for a lot (only a 32-byte hash of it is on-chain). The seller key is a one-time key; the component has no owner.
- `bid(bidder_key, commitment, signature, deposit)` — the bidder locks exactly `deposit` XTM spent **from a stealth coin** and posts only `SHA-256(domain ‖ auction ‖ amount ‖ salt ‖ bidder_key)`, signed by a **fresh one-time Ristretto key**.
- `reveal(bidder_key, amount, salt, signature)` — after bidding closes the template recomputes the hash; any mismatch is rejected.
- `finalize()` — anyone settles: highest revealed bid ≥ reserve wins and pays the **second-highest** bid. **Bids that never open forfeit their deposit to the seller** (anti-grief).
- `refund` / `collect` — losers, the winner's change and the seller's proceeds leave the escrow through `Bucket::stealth_transfer` into **fresh stealth outputs**, each signed by the payee's one-time key over the exact `StealthTransferStatement`.

**Where Tari's privacy does the work**

- **Stealth XTM in and out.** Deposits are spent from stealth UTXOs, every payout goes to new Pedersen-committed outputs. No account takes part in an auction.
- **No identity in the authorisation.** No call checks the transaction signer. Every action carries a Schnorr signature (engine intrinsic, custom domain) from a key that exists for one auction only, so a bidder's bids — or a seller's auctions — can't be grouped by key.
- **Amounts hidden while it matters.** Every bid locks the same deposit, so the ledger shows *that* someone bid, never *how much*; the 32-byte salt stops anyone brute-forcing a commitment over a small price range, and binding the auction address and key stops copying a commitment elsewhere.
- **Un-redirectable payouts.** A payout must spend exactly what is owed, only from escrow, only into stealth outputs; the signature covers the whole CBOR-encoded statement.

**Honest limits**

Revealed bids become public at reveal time and the winner/price after `finalize` — this hides bids *during* bidding and hides *who* bids, it is not a ZK auction. The deposit is public and caps every bid. Fees, timing and the stealth coins spent in can still be correlated like any UTXO without decoys. Lose the one-time key, lose the refund. The lot itself is off-chain (the template settles money only). Not yet deployed to Esmeralda — tested on the in-process engine. All spelled out in the README.

**Verification**

- `cargo test --locked` → **7 end-to-end tests, 7 passed, 0 failed** on the real Ootle engine in-process (`tari_template_test_tooling 0.45`): a full 3-bidder second-price auction; wrong reveal (bad salt, bad amount, double reveal); late reveal + forfeited deposit; foreign key at every step (bid, reveal, refund, collect, and replaying a genuine refund signature onto a different statement); losers refunded exactly once (over-claim and double refund rejected); timing and deposit rules; nothing sells below reserve.
- **19 attack/negative assertions** each checking the exact rejection reason; **14 stealth payouts** in the suite are each spent again afterwards to prove the payee controls exactly what it was owed; the escrow ends at 0 in every settled auction.
- Mutation check: disabling the reveal signature check makes `foreign_key_is_rejected_everywhere` fail.
- `cargo build --release --target wasm32-unknown-unknown --locked` → `sealed_coffin.wasm`, 238,978 bytes; `cargo clippy --target wasm32-unknown-unknown -- -D warnings` clean.

Built against `tari_template_lib 0.34.0`. **Developed with an AI coding agent**; the idea, direction, review and submission are my own.

**Tari payment address:** `126KP9L7QgjAfidCktMkBkcGwXPF9eFNRAYTGRc8b6UtcuzDL3G4L9Grp9VXNqDJN3rN66E8LERCBQadbjJwALuRaoS`

**Social announcement:** <LINK TO BLUESKY OR r/tari POST>  ← *placeholder*
