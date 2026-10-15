// SPDX-License-Identifier: MIT
//! End-to-end tests of the Sealed Coffin template on the real Ootle engine
//! (`tari_template_test_tooling`): the template is compiled to WASM and every call below is a
//! real transaction with real stealth inputs and outputs.

mod common;
use common::*;

/// Three bidders, all reveal; second-price settlement; everyone is paid into fresh stealth outputs
/// and each payout is then spent to prove the payee controls exactly what it was owed.
#[test]
fn successful_auction_pays_second_price_into_stealth_outputs() {
    let mut w = World::new();
    let auction = w.open();
    assert_eq!(w.phase(auction), "bidding");

    let alice = Bidder::new("alice", 300);
    let bob = Bidder::new("bob", 700);
    let carol = Bidder::new("carol", 500);
    for b in [&alice, &bob, &carol] {
        w.bid(auction, b);
    }
    // Every bid locks the same deposit: the escrow says nothing about the amounts.
    assert_eq!(w.escrow(auction), a(3 * DEPOSIT));

    // The client's commitment and the template's agree.
    let from_template: Hash32 = w.test.call_method(
        auction,
        "commitment_for",
        args![a(bob.amount), Hash32::from_array(bob.salt), bob.key.public],
        vec![],
    );
    assert_eq!(
        from_template,
        commitment(auction, a(bob.amount), &bob.salt, &bob.key.public)
    );

    w.epoch(BID_DEADLINE + 1);
    assert_eq!(w.phase(auction), "revealing");
    for b in [&alice, &bob, &carol] {
        w.reveal(auction, b);
    }

    w.epoch(REVEAL_DEADLINE + 1);
    assert_eq!(w.phase(auction), "awaiting_finalize");
    w.ok(auction, "finalize", args![]);
    assert_eq!(w.phase(auction), "finalized");

    // Bob wins and pays Carol's bid (Vickrey), not his own.
    assert_eq!(w.result(auction), Some((1, a(500))));
    assert_eq!(w.owed_to(auction, alice.key.public), a(DEPOSIT));
    assert_eq!(w.owed_to(auction, bob.key.public), a(DEPOSIT - 500));
    assert_eq!(w.owed_to(auction, carol.key.public), a(DEPOSIT));
    assert_eq!(w.seller_owed(auction), a(500));

    for (b, owed) in [(&alice, DEPOSIT), (&bob, DEPOSIT - 500), (&carol, DEPOSIT)] {
        let coin = w.refund(auction, b, owed);
        w.redeem(&coin);
    }
    let proceeds = w.collect(auction, 500);
    w.redeem(&proceeds);

    assert_eq!(
        w.escrow(auction),
        Amount::zero(),
        "everything paid out, nothing stuck"
    );
    assert_eq!(w.seller_owed(auction), Amount::zero());
}

/// A reveal that does not open the commitment (wrong salt, wrong amount) is rejected; the honest
/// opening still works afterwards, exactly once.
#[test]
fn wrong_reveal_is_rejected() {
    let mut w = World::new();
    let auction = w.open();
    let alice = Bidder::new("alice", 400);
    w.bid(auction, &alice);
    w.epoch(BID_DEADLINE + 1);

    let mut wrong_salt = alice.salt;
    wrong_salt[0] ^= 1;
    let args = World::reveal_args(auction, &alice.key, alice.key.public, alice.amount, &wrong_salt);
    w.refused(auction, "reveal", args, "reveal does not match the commitment");

    let args = World::reveal_args(
        auction,
        &alice.key,
        alice.key.public,
        alice.amount + 1,
        &alice.salt,
    );
    w.refused(auction, "reveal", args, "reveal does not match the commitment");

    w.reveal(auction, &alice);
    let args = World::reveal_args(auction, &alice.key, alice.key.public, alice.amount, &alice.salt);
    w.refused(auction, "reveal", args, "bid already revealed");
}

/// Revealing after the window fails, and the unrevealed deposit is forfeited to the seller
/// (anti-griefing): the seller is paid price + forfeit, the late bidder is owed nothing.
#[test]
fn late_reveal_is_rejected_and_unrevealed_deposit_is_forfeited() {
    let mut w = World::new();
    let auction = w.open();
    let alice = Bidder::new("alice", 400);
    let ghost = Bidder::new("ghost", 900);
    w.bid(auction, &alice);
    w.bid(auction, &ghost);

    w.epoch(BID_DEADLINE + 1);
    w.reveal(auction, &alice);

    w.epoch(REVEAL_DEADLINE + 1);
    let args = World::reveal_args(auction, &ghost.key, ghost.key.public, ghost.amount, &ghost.salt);
    w.refused(auction, "reveal", args, "the reveal window is closed");

    w.ok(auction, "finalize", args![]);
    // Alice is the only revealed bid: she wins at the reserve.
    assert_eq!(w.result(auction), Some((0, a(RESERVE))));
    assert_eq!(w.owed_to(auction, alice.key.public), a(DEPOSIT - RESERVE));
    assert_eq!(w.owed_to(auction, ghost.key.public), Amount::zero());
    assert_eq!(w.seller_owed(auction), a(RESERVE + DEPOSIT));

    let data = World::payout(DEPOSIT);
    let args = World::refund_args(auction, &ghost.key, ghost.key.public, &data.statement);
    w.refused(auction, "refund", args, "nothing owed");

    let coin = w.refund(auction, &alice, DEPOSIT - RESERVE);
    w.redeem(&coin);
    let proceeds = w.collect(auction, RESERVE + DEPOSIT);
    w.redeem(&proceeds);
    assert_eq!(w.escrow(auction), Amount::zero());
}

/// Signatures from any key other than the one bound to the bid or the seller are refused at every
/// step: bid, reveal, refund and collect. A valid refund signature cannot be moved onto a
/// different payout statement (no redirection).
#[test]
fn foreign_key_is_rejected_everywhere() {
    let mut w = World::new();
    let auction = w.open();
    let alice = Bidder::new("alice", 600);
    let mallory = Key::new("mallory");

    // Bid registered under Alice's key but signed by Mallory.
    let c = commitment(auction, a(alice.amount), &alice.salt, &alice.key.public);
    let sig = mallory.sign(&action_message(MSG_BID, auction.as_bytes(), &[c.as_ref()]));
    let tx = w.bid_tx(auction, alice.key.public, c, sig, DEPOSIT);
    let rejected = w.test.execute_expect_failure(tx, vec![]);
    assert_reject_reason(rejected, "not authorized: invalid bid signature");

    w.bid(auction, &alice);
    w.epoch(BID_DEADLINE + 1);
    // Mallory knows Alice's opening (say it leaked) but cannot reveal for her.
    let args = World::reveal_args(auction, &mallory, alice.key.public, alice.amount, &alice.salt);
    w.refused(
        auction,
        "reveal",
        args,
        "not authorized: invalid reveal signature",
    );
    w.reveal(auction, &alice);

    w.epoch(REVEAL_DEADLINE + 1);
    w.ok(auction, "finalize", args![]);
    let owed = DEPOSIT - RESERVE;

    // Mallory tries to take Alice's refund into Mallory's own stealth output.
    let mallory_out = World::payout(owed);
    let args = World::refund_args(auction, &mallory, alice.key.public, &mallory_out.statement);
    w.refused(
        auction,
        "refund",
        args,
        "not authorized: invalid refund signature",
    );

    // Mallory replays Alice's genuine signature (made for Alice's statement) with her own statement.
    let alice_out = World::payout(owed);
    let digest = statement_digest(&alice_out.statement);
    let alice_sig = alice
        .key
        .sign(&action_message(MSG_REFUND, auction.as_bytes(), &[&digest]));
    w.refused(
        auction,
        "refund",
        args![alice.key.public, mallory_out.statement.clone(), alice_sig],
        "not authorized: invalid refund signature",
    );

    // Mallory tries to collect the seller's proceeds.
    let proceeds = World::payout(RESERVE);
    let args = World::collect_args(auction, &mallory, &proceeds.statement);
    w.refused(
        auction,
        "collect",
        args,
        "not authorized: invalid collect signature",
    );

    // The rightful owners still get paid.
    let coin = w.refund(auction, &alice, owed);
    w.redeem(&coin);
    let coin = w.collect(auction, RESERVE);
    w.redeem(&coin);
}

/// Losers get their whole deposit back into fresh stealth outputs, exactly once and exactly the
/// owed amount; a bid revealed below the reserve is a loser too.
#[test]
fn losers_are_refunded_exactly_once() {
    let mut w = World::new();
    let auction = w.open();
    let winner = Bidder::new("winner", 800);
    let loser = Bidder::new("loser", 650);
    let lowball = Bidder::new("lowball", RESERVE - 1);
    for b in [&winner, &loser, &lowball] {
        w.bid(auction, b);
    }
    w.epoch(BID_DEADLINE + 1);
    for b in [&winner, &loser, &lowball] {
        w.reveal(auction, b);
    }
    w.epoch(REVEAL_DEADLINE + 1);
    w.ok(auction, "finalize", args![]);
    assert_eq!(w.result(auction), Some((0, a(650))));

    // Over-claiming is refused: a payout must spend exactly the amount owed.
    let greedy = World::payout(DEPOSIT + 1);
    let args = World::refund_args(auction, &loser.key, loser.key.public, &greedy.statement);
    w.refused(
        auction,
        "refund",
        args,
        "a payout must spend exactly the amount owed",
    );

    let coin = w.refund(auction, &loser, DEPOSIT);
    w.redeem(&coin);
    let coin = w.refund(auction, &lowball, DEPOSIT);
    w.redeem(&coin);

    // A second refund is refused.
    let again = World::payout(DEPOSIT);
    let args = World::refund_args(auction, &loser.key, loser.key.public, &again.statement);
    w.refused(auction, "refund", args, "already paid");

    let coin = w.refund(auction, &winner, DEPOSIT - 650);
    w.redeem(&coin);
    let coin = w.collect(auction, 650);
    w.redeem(&coin);
    assert_eq!(w.escrow(auction), Amount::zero());
}

/// Phase rules: no reveal while bidding, no bid after the deadline, no finalize before the reveal
/// window ends; deposits must be exact and a bidder key bids once.
#[test]
fn timing_and_deposit_rules_are_enforced() {
    let mut w = World::new();
    let auction = w.open();
    let alice = Bidder::new("alice", 500);

    // Wrong deposit.
    let c = commitment(auction, a(alice.amount), &alice.salt, &alice.key.public);
    let sig = alice
        .key
        .sign(&action_message(MSG_BID, auction.as_bytes(), &[c.as_ref()]));
    let tx = w.bid_tx(auction, alice.key.public, c, sig, DEPOSIT - 1);
    let rejected = w.test.execute_expect_failure(tx, vec![]);
    assert_reject_reason(rejected, "deposit must equal the auction deposit");

    w.bid(auction, &alice);

    // Same key again (with a different commitment).
    let again = Bidder {
        key: Key::new("alice"),
        amount: 501,
        salt: alice.salt,
    };
    let c = commitment(auction, a(again.amount), &again.salt, &again.key.public);
    let sig = again
        .key
        .sign(&action_message(MSG_BID, auction.as_bytes(), &[c.as_ref()]));
    let tx = w.bid_tx(auction, again.key.public, c, sig, DEPOSIT);
    let rejected = w.test.execute_expect_failure(tx, vec![]);
    assert_reject_reason(rejected, "bidder key already used in this auction");

    // Reveal during bidding.
    let args = World::reveal_args(auction, &alice.key, alice.key.public, alice.amount, &alice.salt);
    w.refused(auction, "reveal", args, "bidding is still open");

    // Bid after the deadline.
    w.epoch(BID_DEADLINE + 1);
    let late = Bidder::new("late", 900);
    let c = commitment(auction, a(late.amount), &late.salt, &late.key.public);
    let sig = late
        .key
        .sign(&action_message(MSG_BID, auction.as_bytes(), &[c.as_ref()]));
    let tx = w.bid_tx(auction, late.key.public, c, sig, DEPOSIT);
    let rejected = w.test.execute_expect_failure(tx, vec![]);
    assert_reject_reason(rejected, "bidding is closed");

    // Finalize too early.
    w.refused(auction, "finalize", args![], "the reveal window is still open");
    w.reveal(auction, &alice);
    w.epoch(REVEAL_DEADLINE + 1);
    w.ok(auction, "finalize", args![]);
    w.refused(auction, "finalize", args![], "already finalized");
}

/// If every revealed bid is below the reserve, nothing sells: all deposits go back and the seller
/// is owed nothing.
#[test]
fn nothing_sells_below_reserve() {
    let mut w = World::new();
    let auction = w.open();
    let b1 = Bidder::new("b1", 10);
    let b2 = Bidder::new("b2", 99);
    w.bid(auction, &b1);
    w.bid(auction, &b2);
    w.epoch(BID_DEADLINE + 1);
    w.reveal(auction, &b1);
    w.reveal(auction, &b2);
    w.epoch(REVEAL_DEADLINE + 1);
    w.ok(auction, "finalize", args![]);
    assert_eq!(w.result(auction), None);
    assert_eq!(w.seller_owed(auction), Amount::zero());
    let proceeds = World::payout(1);
    let args = World::collect_args(auction, &w.seller, &proceeds.statement);
    w.refused(auction, "collect", args, "nothing owed");
    for b in [&b1, &b2] {
        let coin = w.refund(auction, b, DEPOSIT);
        w.redeem(&coin);
    }
    assert_eq!(w.escrow(auction), Amount::zero());
}
