# Announcement drafts (do not post until the repo is public; replace <REPO>)

## Bluesky (≤300 characters)

Spooky Secrets 🎃 My @tariproject.bsky.social Ootle contest entry: Sealed Coffin ⚰️ — a sealed-bid auction where bids stay sealed till close. Stealth XTM deposits, one-time keys, refunds to fresh stealth outputs; ghosts who never reveal lose it. <REPO>

(Without the link ≈ 244 characters; with a ~41-character GitHub link ≈ 285 — under Bluesky's 300. Re-check after inserting the real link.)

## Reddit r/tari

**Title:** I built Sealed Coffin ⚰️ — a private sealed-bid auction on Tari Ootle (Spooky Secrets entry)

**Body:**

On a transparent chain a "sealed-bid" auction isn't sealed: everyone sees who bid and how much.
Sealed Coffin is an Ootle template for a second-price (Vickrey) sealed-bid auction where:

- you bid by locking a fixed deposit **from a stealth coin** and posting only a salted SHA-256 commitment, signed by a **one-time key** — no account, no wallet identity;
- every bid locks the same deposit, so nobody (not even the seller) learns amounts until the reveal phase;
- the highest bid wins and pays the second-highest; losers are refunded via `stealth_transfer` into **fresh stealth outputs**;
- bidders who never reveal forfeit their deposit to the seller (anti-grief).

7 end-to-end tests on the real Ootle engine (successful auction, wrong reveal, late reveal, foreign keys, refunds), WASM build, MIT license. README has the threat model and an honest list of what still leaks (revealed bids become public after the reveal, fees/timing can link).

Code: <REPO>
Developed with an AI coding agent; the idea, direction, review and submission are mine.
Feedback welcome! 🎃
