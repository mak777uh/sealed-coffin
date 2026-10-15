// Copyright 2026 Sealed Coffin contributors
// SPDX-License-Identifier: MIT

//! # Sealed Coffin
//!
//! A sealed-bid (Vickrey, second-price) auction for the Tari Ootle in which nobody, not even the
//! seller, learns a bid before the bidding closes, and no bidder ever shows an account.
//!
//! ## Lifecycle
//!
//! 1. `open`: anyone opens an auction for a lot (identified only by a 32-byte hash of its
//!    description) with a one-time **seller key**, a reserve price, a fixed **deposit** and two
//!    windows in epochs: bidding, then revealing.
//! 2. `bid`: a bidder locks exactly `deposit` XTM (spent from a stealth coin) and submits only
//!    `commitment = SHA-256(DOMAIN ‖ auction ‖ amount ‖ salt ‖ bidder_key)`, signed by a fresh
//!    one-time Ristretto **bidder key**. Every bid locks the same deposit, so the ledger shows that
//!    someone bid, never how much.
//! 3. `reveal`: after bidding closes, each bidder opens their commitment (amount + salt), signed by
//!    the same one-time key. The template recomputes the hash and rejects any mismatch.
//! 4. `finalize`: after the reveal window anyone may settle. The highest revealed bid at or above
//!    the reserve wins and pays the second-highest revealed bid (or the reserve). A bid that was
//!    never revealed forfeits its deposit to the seller: this is the anti-griefing rule that makes
//!    "bid and vanish" cost money.
//! 5. `refund` / `collect`: every payout leaves the escrow through `Bucket::stealth_transfer` into
//!    fresh Pedersen-committed stealth outputs. The payee signs a digest of the exact transfer
//!    statement with their one-time key, so nobody can redirect it.
//!
//! **Authorisation never uses the transaction signer or an account.** Every state-changing call
//! carries a Schnorr signature (Ristretto, Blake2b challenge, engine intrinsic) by a key that exists
//! only for this auction. The component has no owner (`OwnerRule::None`), so nobody can change the
//! rules after opening.
//!
//! See README.md for the threat model and the honest list of what still leaks.

use tari_template_lib::prelude::*;

/// Domain of the bid commitment hash. Must match the client (tests/common).
pub const DOMAIN_COMMIT: &[u8] = b"sealed-coffin/commit/v1";
/// Domain of the digest a payee signs over a stealth payout statement.
pub const DOMAIN_STATEMENT: &[u8] = b"sealed-coffin/statement/v1";

pub const MSG_BID: &[u8] = b"bid";
pub const MSG_REVEAL: &[u8] = b"reveal";
pub const MSG_REFUND: &[u8] = b"refund";
pub const MSG_COLLECT: &[u8] = b"collect";

/// Shortest and longest bidding / reveal window, in epochs.
pub const MIN_WINDOW: u64 = 1;
pub const MAX_WINDOW: u64 = 10_000;
/// Upper bound on bids per auction: keeps `finalize` and every lookup bounded.
pub const MAX_BIDS: usize = 64;

custom_signature_domain!(CoffinDomain, b"sealed-coffin/sig/v1");

/// Every signature the auction accepts lives in its own domain, so a signature made for another
/// application can never be replayed here.
pub type CoffinSignature = Signature<CoffinDomain>;

fn len_prefixed(data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

/// `SHA-256(len‖DOMAIN ‖ auction ‖ amount (u128 LE) ‖ salt ‖ bidder_key)`.
pub fn bid_commitment(
    auction: &[u8],
    amount: Amount,
    salt: &Hash32,
    bidder_key: &RistrettoPublicKeyBytes,
) -> Hash32 {
    let domain = len_prefixed(DOMAIN_COMMIT);
    let auction = len_prefixed(auction);
    intrinsics::hash_sha256_parts(&[
        &domain,
        &auction,
        &amount.to_le_bytes(),
        salt.as_ref(),
        bidder_key.as_bytes(),
    ])
}

/// The digest a payee signs: SHA-512 over the canonical CBOR encoding of the whole statement, so
/// no output, proof or encrypted field can be swapped after signing.
pub fn statement_digest(statement: &StealthTransferStatement) -> Hash64 {
    let encoded = tari_bor::encode(statement).expect("a decoded statement re-encodes");
    let domain = len_prefixed(DOMAIN_STATEMENT);
    intrinsics::hash_sha512_parts(&[&domain, &encoded])
}

/// The message a key signs for an action: `action ‖ auction ‖ payload`, length-prefixed.
pub fn action_message(action: &[u8], auction: &[u8], payload: &[&[u8]]) -> Vec<u8> {
    let mut msg = len_prefixed(action);
    msg.extend(len_prefixed(auction));
    for part in payload {
        msg.extend(len_prefixed(part));
    }
    msg
}

fn assert_valid_key(key: &RistrettoPublicKeyBytes, what: &str) {
    assert!(
        intrinsics::ristretto_is_canonical(key),
        "{} is not a canonical Ristretto point",
        what
    );
    assert!(
        !intrinsics::ristretto_is_identity(key),
        "{} must not be the identity point",
        what
    );
}

fn assert_signed(key: &RistrettoPublicKeyBytes, message: &[u8], signature: &CoffinSignature, what: &str) {
    assert!(
        signature.verify(&PublicKey::from(*key), message),
        "not authorized: invalid {} signature",
        what
    );
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode, minicbor::CborLen)]
pub struct SealedBid {
    #[n(0)]
    pub key: RistrettoPublicKeyBytes,
    #[n(1)]
    pub commitment: Hash32,
    /// Set by a valid `reveal`.
    #[n(2)]
    pub revealed: Option<Amount>,
    /// What the escrow owes this bidder after `finalize`.
    #[n(3)]
    pub owed: Amount,
    #[n(4)]
    pub paid: bool,
}

#[template]
mod sealed_coffin {
    use super::*;

    pub struct SealedCoffin {
        seller_key: RistrettoPublicKeyBytes,
        lot: Hash32,
        reserve: Amount,
        deposit: Amount,
        bid_deadline: u64,
        reveal_deadline: u64,
        bids: Vec<SealedBid>,
        escrow: Vault,
        finalized: bool,
        winner: Option<u32>,
        price: Amount,
        seller_owed: Amount,
        seller_paid: bool,
    }

    impl SealedCoffin {
        /// Opens an auction. Bidding is open until `now + bid_window` (inclusive); revealing until
        /// `bid_deadline + reveal_window` (inclusive).
        pub fn open(
            seller_key: RistrettoPublicKeyBytes,
            lot: Hash32,
            reserve: Amount,
            deposit: Amount,
            bid_window: u64,
            reveal_window: u64,
        ) -> Component<Self> {
            assert_valid_key(&seller_key, "seller key");
            assert!(deposit.is_positive(), "deposit must be positive");
            assert!(!reserve.is_negative(), "reserve must not be negative");
            assert!(reserve <= deposit, "reserve must not exceed the deposit");
            for window in [bid_window, reveal_window] {
                assert!(
                    (MIN_WINDOW..=MAX_WINDOW).contains(&window),
                    "windows must be between {} and {} epochs",
                    MIN_WINDOW,
                    MAX_WINDOW
                );
            }
            let now = Consensus::current_epoch();
            let bid_deadline = now + bid_window;
            let reveal_deadline = bid_deadline + reveal_window;
            emit_event(
                "coffin_opened",
                metadata! {
                    "bid_deadline" => bid_deadline.to_string(),
                    "reveal_deadline" => reveal_deadline.to_string()
                },
            );
            Component::new(Self {
                seller_key,
                lot,
                reserve,
                deposit,
                bid_deadline,
                reveal_deadline,
                bids: Vec::new(),
                escrow: Vault::new_empty(TARI_TOKEN),
                finalized: false,
                winner: None,
                price: Amount::zero(),
                seller_owed: Amount::zero(),
                seller_paid: false,
            })
            .with_access_rules(AccessRules::allow_all())
            .with_owner_rule(OwnerRule::None)
            .create()
        }

        /// Places a sealed bid. `deposit` must be exactly the auction's deposit in XTM;
        /// `signature` is by `bidder_key` over `action_message("bid", auction, [commitment])`.
        pub fn bid(
            &mut self,
            bidder_key: RistrettoPublicKeyBytes,
            commitment: Hash32,
            signature: CoffinSignature,
            deposit: Bucket,
        ) {
            assert!(
                Consensus::current_epoch() <= self.bid_deadline,
                "bidding is closed"
            );
            assert!(deposit.resource_address() == TARI_TOKEN, "only XTM is accepted");
            assert!(
                deposit.amount() == self.deposit,
                "deposit must equal the auction deposit"
            );
            assert!(self.bids.len() < MAX_BIDS, "too many bids");
            assert_valid_key(&bidder_key, "bidder key");
            assert!(bidder_key != self.seller_key, "the seller key cannot bid");
            assert!(
                self.bids.iter().all(|b| b.key != bidder_key),
                "bidder key already used in this auction"
            );
            assert!(
                self.bids.iter().all(|b| b.commitment != commitment),
                "duplicate commitment"
            );
            let message = action_message(MSG_BID, &Self::context(), &[commitment.as_ref()]);
            assert_signed(&bidder_key, &message, &signature, "bid");

            self.escrow.deposit(deposit);
            self.bids.push(SealedBid {
                key: bidder_key,
                commitment,
                revealed: None,
                owed: Amount::zero(),
                paid: false,
            });
            emit_event("coffin_bid", metadata! { "bids" => self.bids.len().to_string() });
        }

        /// Opens a sealed bid during the reveal window.
        pub fn reveal(
            &mut self,
            bidder_key: RistrettoPublicKeyBytes,
            amount: Amount,
            salt: Hash32,
            signature: CoffinSignature,
        ) {
            let now = Consensus::current_epoch();
            assert!(now > self.bid_deadline, "bidding is still open");
            assert!(now <= self.reveal_deadline, "the reveal window is closed");
            let context = Self::context();
            let index = self.index_of(&bidder_key);
            let bid = &self.bids[index];
            assert!(bid.revealed.is_none(), "bid already revealed");
            assert!(
                bid_commitment(&context, amount, &salt, &bidder_key) == bid.commitment,
                "reveal does not match the commitment"
            );
            assert!(!amount.is_negative(), "bid must not be negative");
            assert!(amount <= self.deposit, "bid exceeds the deposit");
            let message = action_message(MSG_REVEAL, &context, &[&amount.to_le_bytes(), salt.as_ref()]);
            assert_signed(&bidder_key, &message, &signature, "reveal");
            self.bids[index].revealed = Some(amount);
            emit_event("coffin_reveal", metadata! { "epoch" => now.to_string() });
        }

        /// Settles the auction once the reveal window has passed. Callable by anyone.
        ///
        /// Winner: highest revealed bid at or above the reserve (ties go to the earlier bid). Price:
        /// the second-highest revealed bid at or above the reserve, or the reserve. Unrevealed bids
        /// forfeit their deposit to the seller.
        pub fn finalize(&mut self) {
            assert!(!self.finalized, "already finalized");
            assert!(
                Consensus::current_epoch() > self.reveal_deadline,
                "the reveal window is still open"
            );
            let mut best: Option<(usize, Amount)> = None;
            let mut second = self.reserve;
            for (i, bid) in self.bids.iter().enumerate() {
                if let Some(amount) = bid.revealed {
                    if amount < self.reserve {
                        continue;
                    }
                    match best {
                        Some((_, top)) if amount <= top => {
                            if amount > second {
                                second = amount;
                            }
                        }
                        Some((_, top)) => {
                            second = top;
                            best = Some((i, amount));
                        }
                        None => best = Some((i, amount)),
                    }
                }
            }

            let mut seller = Amount::zero();
            for (i, bid) in self.bids.iter_mut().enumerate() {
                bid.owed = match (bid.revealed, best) {
                    (None, _) => {
                        // Anti-griefing: a sealed bid that never opened is forfeited.
                        seller = seller.checked_add(self.deposit).expect("overflow");
                        Amount::zero()
                    }
                    (Some(_), Some((w, _))) if w == i => {
                        seller = seller.checked_add(second).expect("overflow");
                        self.deposit.checked_sub(second).expect("price within deposit")
                    }
                    (Some(_), _) => self.deposit,
                };
            }
            self.winner = best.map(|(i, _)| i as u32);
            self.price = if best.is_some() { second } else { Amount::zero() };
            self.seller_owed = seller;
            self.finalized = true;
            emit_event(
                "coffin_finalized",
                metadata! {
                    "sold" => best.is_some().to_string(),
                    "price" => self.price.to_string()
                },
            );
        }

        /// Pays a bidder what they are owed (refund, or deposit minus price for the winner) into the
        /// stealth outputs of `statement`, signed by the bidder key over the statement digest.
        pub fn refund(
            &mut self,
            bidder_key: RistrettoPublicKeyBytes,
            statement: StealthTransferStatement,
            signature: CoffinSignature,
        ) {
            assert!(self.finalized, "auction not finalized");
            let index = self.index_of(&bidder_key);
            let bid = self.bids[index].clone();
            assert!(!bid.paid, "already paid");
            assert!(bid.owed.is_positive(), "nothing owed");
            self.pay(bid.owed, &bidder_key, MSG_REFUND, statement, &signature, "refund");
            self.bids[index].paid = true;
        }

        /// Pays the seller the price plus any forfeited deposits into stealth outputs.
        pub fn collect(&mut self, statement: StealthTransferStatement, signature: CoffinSignature) {
            assert!(self.finalized, "auction not finalized");
            assert!(!self.seller_paid, "already paid");
            assert!(self.seller_owed.is_positive(), "nothing owed");
            let key = self.seller_key;
            self.pay(
                self.seller_owed,
                &key,
                MSG_COLLECT,
                statement,
                &signature,
                "collect",
            );
            self.seller_paid = true;
        }

        // ------------------------------ views ------------------------------ //

        /// "bidding", "revealing", "awaiting_finalize" or "finalized".
        pub fn phase(&self) -> String {
            let now = Consensus::current_epoch();
            if self.finalized {
                "finalized"
            } else if now <= self.bid_deadline {
                "bidding"
            } else if now <= self.reveal_deadline {
                "revealing"
            } else {
                "awaiting_finalize"
            }
            .to_string()
        }

        /// (lot, reserve, deposit, bid_deadline, reveal_deadline, number of bids)
        pub fn terms(&self) -> (Hash32, Amount, Amount, u64, u64, u32) {
            (
                self.lot,
                self.reserve,
                self.deposit,
                self.bid_deadline,
                self.reveal_deadline,
                self.bids.len() as u32,
            )
        }

        /// After finalize: (winning bid index, price), or None if nothing sold.
        pub fn result(&self) -> Option<(u32, Amount)> {
            self.winner.map(|w| (w, self.price))
        }

        pub fn owed_to(&self, bidder_key: RistrettoPublicKeyBytes) -> Amount {
            self.bids
                .iter()
                .find(|b| b.key == bidder_key)
                .filter(|b| !b.paid)
                .map(|b| b.owed)
                .unwrap_or_default()
        }

        pub fn seller_owed(&self) -> Amount {
            if self.seller_paid {
                Amount::zero()
            } else {
                self.seller_owed
            }
        }

        pub fn escrow_balance(&self) -> Amount {
            self.escrow.balance()
        }

        /// Client helper: the commitment a bidder should submit to this auction.
        pub fn commitment_for(
            &self,
            amount: Amount,
            salt: Hash32,
            bidder_key: RistrettoPublicKeyBytes,
        ) -> Hash32 {
            bid_commitment(&Self::context(), amount, &salt, &bidder_key)
        }

        /// Client helper: the digest a payee signs for a payout statement.
        pub fn payout_digest(statement: StealthTransferStatement) -> Hash64 {
            statement_digest(&statement)
        }

        // ----------------------------- internals ---------------------------- //

        fn context() -> Vec<u8> {
            CallerContext::current_component_address().as_bytes().to_vec()
        }

        fn index_of(&self, key: &RistrettoPublicKeyBytes) -> usize {
            self.bids
                .iter()
                .position(|b| b.key == *key)
                .expect("no bid for this key")
        }

        /// Moves exactly `amount` out of the escrow into the stealth outputs of `statement`. The
        /// statement may spend nothing but that amount and must put all of it into stealth outputs.
        fn pay(
            &self,
            amount: Amount,
            key: &RistrettoPublicKeyBytes,
            action: &[u8],
            statement: StealthTransferStatement,
            signature: &CoffinSignature,
            what: &str,
        ) {
            assert!(
                statement.inputs_statement.inputs.is_empty(),
                "a payout spends the escrow only, no stealth inputs"
            );
            assert!(
                statement.inputs_statement.revealed_amount == amount,
                "a payout must spend exactly the amount owed"
            );
            assert!(
                statement.outputs_statement.revealed_output.is_none(),
                "a payout goes to stealth outputs only"
            );
            assert!(
                !statement.outputs_statement.outputs.is_empty(),
                "a payout needs stealth outputs"
            );
            assert!(
                statement.covenant_claims.is_empty(),
                "a payout carries no covenant claims"
            );
            let digest = statement_digest(&statement);
            let message = action_message(action, &Self::context(), &[digest.as_ref()]);
            assert_signed(key, &message, signature, what);
            self.escrow
                .withdraw(amount)
                .stealth_transfer(statement)
                .drop_empty();
        }
    }
}
