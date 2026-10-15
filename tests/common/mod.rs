// SPDX-License-Identifier: MIT
//! Test harness: a bank mints stealth coins; bidders fund deposits by spending those coins in
//! transactions signed by each coin's own one-time key; every action inside the auction is
//! authorised by a Schnorr signature from a one-time auction key held by the client (this file),
//! never by the transaction signer or an account.
#![allow(dead_code)]

use sha2::{Digest, Sha256, Sha512};
pub use tari_ootle_common_types::RistrettoSchnorrBlake2bVerifier;
pub use tari_template_lib_types::{
    constants::TARI_TOKEN,
    crypto::{RistrettoPublicKeyBytes, Signature},
    custom_signature_domain,
    stealth::StealthTransferStatement,
    Amount, ComponentAddress, Hash32, NonFungibleAddress,
};
pub use tari_template_test_tooling::{
    byte_type::ToByteType,
    crypto::{PublicKey, RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey, SecretKey},
    engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId},
    support::{
        assert_error::assert_reject_reason,
        stealth::{generate_transfer_data, generate_transfer_data_to, StealthSecretTransferData, NO_INPUTS},
    },
    transaction::{args, builder::named_args::NamedArg, Transaction},
    TemplateTest,
};

// Must match src/lib.rs byte for byte.
pub const DOMAIN_COMMIT: &[u8] = b"sealed-coffin/commit/v1";
pub const DOMAIN_STATEMENT: &[u8] = b"sealed-coffin/statement/v1";
pub const MSG_BID: &[u8] = b"bid";
pub const MSG_REVEAL: &[u8] = b"reveal";
pub const MSG_REFUND: &[u8] = b"refund";
pub const MSG_COLLECT: &[u8] = b"collect";
custom_signature_domain!(CoffinDomain, b"sealed-coffin/sig/v1");
pub type CoffinSignature = Signature<CoffinDomain>;

pub const START_EPOCH: u64 = 10;
pub const BID_WINDOW: u64 = 5;
pub const REVEAL_WINDOW: u64 = 5;
pub const BID_DEADLINE: u64 = START_EPOCH + BID_WINDOW;
pub const REVEAL_DEADLINE: u64 = BID_DEADLINE + REVEAL_WINDOW;
pub const DEPOSIT: u64 = 1_000;
pub const RESERVE: u64 = 100;

pub fn a(v: u64) -> Amount {
    Amount::from_u64(v)
}

fn len_prefixed(data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

pub fn action_message(action: &[u8], auction: &[u8], payload: &[&[u8]]) -> Vec<u8> {
    let mut msg = len_prefixed(action);
    msg.extend(len_prefixed(auction));
    for part in payload {
        msg.extend(len_prefixed(part));
    }
    msg
}

/// Client-side commitment, computed independently of the template with the `sha2` crate.
pub fn commitment(
    auction: ComponentAddress,
    amount: Amount,
    salt: &[u8; 32],
    key: &RistrettoPublicKeyBytes,
) -> Hash32 {
    let mut h = Sha256::new();
    h.update(len_prefixed(DOMAIN_COMMIT));
    h.update(len_prefixed(auction.as_bytes()));
    h.update(amount.to_le_bytes());
    h.update(salt);
    h.update(key.as_bytes());
    Hash32::from_array(h.finalize().into())
}

pub fn statement_digest(statement: &StealthTransferStatement) -> [u8; 64] {
    let encoded = tari_bor::encode(statement).unwrap();
    let mut h = Sha512::new();
    h.update(len_prefixed(DOMAIN_STATEMENT));
    h.update(encoded);
    h.finalize().into()
}

/// A one-time auction key (seller key or bidder key). Derived from a label for reproducible tests;
/// a real client would draw it from a CSPRNG and keep it only for one auction.
pub struct Key {
    seed: Vec<u8>,
    secret: RistrettoSecretKey,
    pub public: RistrettoPublicKeyBytes,
}

impl Key {
    pub fn new(label: &str) -> Self {
        let seed = Sha512::digest(format!("sealed-coffin test key {label}").as_bytes()).to_vec();
        let secret = RistrettoSecretKey::from_uniform_bytes(&seed).unwrap();
        let public = RistrettoPublicKey::from_secret_key(&secret).to_byte_type();
        Self { seed, secret, public }
    }

    pub fn sign(&self, message: &[u8]) -> CoffinSignature {
        let mut h = Sha512::new();
        h.update(&self.seed);
        h.update(b"nonce");
        h.update(message);
        let nonce = RistrettoSecretKey::from_uniform_bytes(&h.finalize()).unwrap();
        let nonce_pub = RistrettoPublicKey::from_secret_key(&nonce).to_byte_type();
        let challenge = RistrettoSchnorrBlake2bVerifier::compute_challenge(
            b"sealed-coffin/sig/v1",
            message,
            &self.public,
            &nonce_pub,
        );
        let sig = RistrettoSchnorr::sign_raw_uniform(&self.secret, nonce, &challenge).unwrap();
        CoffinSignature::new(sig.to_byte_type())
    }
}

/// A sealed bid as the bidder's client remembers it.
pub struct Bidder {
    pub key: Key,
    pub amount: u64,
    pub salt: [u8; 32],
}

impl Bidder {
    pub fn new(label: &str, amount: u64) -> Self {
        let salt: [u8; 32] = Sha256::digest(format!("salt {label}").as_bytes()).into();
        Self {
            key: Key::new(label),
            amount,
            salt,
        }
    }
}

/// A stealth UTXO someone holds.
pub struct Coin {
    pub data: StealthSecretTransferData,
    pub value: u64,
}

impl Coin {
    pub fn key(&self) -> &RistrettoSecretKey {
        &self.data.output_masks[0]
    }

    pub fn public(&self) -> RistrettoPublicKeyBytes {
        RistrettoPublicKey::from_secret_key(self.key()).to_byte_type()
    }

    /// Spends the whole coin into a revealed bucket.
    pub fn spend_to_bucket(&self) -> StealthTransferStatement {
        generate_transfer_data_to(
            [self.data.input_spec_for(0, self.value)],
            Amount::zero(),
            Vec::<u64>::new(),
            Amount::from_u64(self.value),
            self.public(),
        )
        .statement
    }
}

pub struct World {
    pub test: TemplateTest,
    pub bank: (ComponentAddress, NonFungibleAddress, RistrettoSecretKey),
    pub seller: Key,
}

pub fn set_epoch(test: &mut TemplateTest, epoch: u64) {
    test.set_virtual_substate(
        VirtualSubstateId::CurrentEpoch,
        VirtualSubstate::CurrentEpoch(epoch),
    );
}

impl World {
    pub fn new() -> Self {
        let mut test = TemplateTest::new_cwd(["."]);
        set_epoch(&mut test, START_EPOCH);
        let bank = test.create_funded_account();
        Self {
            test,
            bank,
            seller: Key::new("seller"),
        }
    }

    pub fn epoch(&mut self, epoch: u64) {
        set_epoch(&mut self.test, epoch);
    }

    /// Mints a stealth coin worth `value` out of the bank account.
    pub fn coin(&mut self, value: u64) -> Coin {
        let data = generate_transfer_data(NO_INPUTS, Amount::from_u64(value), [value], Amount::zero());
        let (account, proof, key) = (self.bank.0, self.bank.1.clone(), self.bank.2.clone());
        let tx = self
            .test
            .transaction()
            .call_method(account, "withdraw", args![TARI_TOKEN, Amount::from_u64(value)])
            .put_last_instruction_output_on_workspace("funds")
            .stealth_transfer_with_input_bucket(TARI_TOKEN, data.statement.clone(), "funds")
            .build_and_seal(&key);
        self.test.execute_expect_success(tx, vec![proof]);
        Coin { data, value }
    }

    /// Opens an auction signed by nobody in particular (any transaction signer works).
    pub fn open(&mut self) -> ComponentAddress {
        let template = self.test.get_template_address("SealedCoffin");
        let lot = Hash32::from_array(Sha256::digest(b"a haunted pocket watch, lot #13").into());
        let tx = self
            .test
            .transaction()
            .call_function(
                template,
                "open",
                args![
                    self.seller.public,
                    lot,
                    a(RESERVE),
                    a(DEPOSIT),
                    BID_WINDOW,
                    REVEAL_WINDOW
                ],
            )
            .build_and_seal(self.test.secret_key());
        let result = self.test.execute_expect_success(tx, vec![]);
        result
            .finalize
            .execution_results
            .iter()
            .find_map(|r| r.decode::<ComponentAddress>().ok())
            .expect("open returns the component address")
    }

    /// The bid transaction: spend a stealth coin worth `deposit` into a bucket, then bid with it.
    /// Signed by the coin's one-time key; the bid itself is authorised by `signature`.
    pub fn bid_tx(
        &mut self,
        auction: ComponentAddress,
        key: RistrettoPublicKeyBytes,
        commitment: Hash32,
        signature: CoffinSignature,
        deposit: u64,
    ) -> Transaction {
        let coin = self.coin(deposit);
        self.test
            .transaction()
            .stealth_transfer(TARI_TOKEN, coin.spend_to_bucket())
            .put_last_instruction_output_on_workspace("deposit")
            .call_method(
                auction,
                "bid",
                args![key, commitment, signature, Workspace("deposit")],
            )
            .build_and_seal(coin.key())
    }

    pub fn bid(&mut self, auction: ComponentAddress, bidder: &Bidder) {
        let c = commitment(auction, a(bidder.amount), &bidder.salt, &bidder.key.public);
        let sig = bidder
            .key
            .sign(&action_message(MSG_BID, auction.as_bytes(), &[c.as_ref()]));
        let tx = self.bid_tx(auction, bidder.key.public, c, sig, DEPOSIT);
        self.test.execute_expect_success(tx, vec![]);
    }

    pub fn reveal_args(
        auction: ComponentAddress,
        signer: &Key,
        key: RistrettoPublicKeyBytes,
        amount: u64,
        salt: &[u8; 32],
    ) -> Vec<NamedArg> {
        let sig = signer.sign(&action_message(
            MSG_REVEAL,
            auction.as_bytes(),
            &[&a(amount).to_le_bytes(), salt],
        ));
        args![key, a(amount), Hash32::from_array(*salt), sig]
    }

    pub fn call_tx(&self, auction: ComponentAddress, method: &str, args: Vec<NamedArg>) -> Transaction {
        self.test
            .transaction()
            .call_method(auction, method, args)
            .build_and_seal(self.test.secret_key())
    }

    pub fn ok(&mut self, auction: ComponentAddress, method: &str, args: Vec<NamedArg>) {
        let tx = self.call_tx(auction, method, args);
        self.test.execute_expect_success(tx, vec![]);
    }

    pub fn refused(&mut self, auction: ComponentAddress, method: &str, args: Vec<NamedArg>, reason: &str) {
        let tx = self.call_tx(auction, method, args);
        let rejected = self.test.execute_expect_failure(tx, vec![]);
        assert_reject_reason(rejected, reason);
    }

    pub fn reveal(&mut self, auction: ComponentAddress, bidder: &Bidder) {
        let args = Self::reveal_args(
            auction,
            &bidder.key,
            bidder.key.public,
            bidder.amount,
            &bidder.salt,
        );
        self.ok(auction, "reveal", args);
    }

    /// A payout statement: no stealth inputs, `amount` revealed in from the escrow, one fresh
    /// stealth output for the payee.
    pub fn payout(amount: u64) -> StealthSecretTransferData {
        generate_transfer_data(NO_INPUTS, Amount::from_u64(amount), [amount], Amount::zero())
    }

    pub fn refund_args(
        auction: ComponentAddress,
        signer: &Key,
        key: RistrettoPublicKeyBytes,
        statement: &StealthTransferStatement,
    ) -> Vec<NamedArg> {
        let digest = statement_digest(statement);
        let sig = signer.sign(&action_message(MSG_REFUND, auction.as_bytes(), &[&digest]));
        args![key, statement.clone(), sig]
    }

    pub fn collect_args(
        auction: ComponentAddress,
        signer: &Key,
        statement: &StealthTransferStatement,
    ) -> Vec<NamedArg> {
        let digest = statement_digest(statement);
        let sig = signer.sign(&action_message(MSG_COLLECT, auction.as_bytes(), &[&digest]));
        args![statement.clone(), sig]
    }

    /// Refunds `bidder` into a fresh stealth output and returns the coin they now hold.
    pub fn refund(&mut self, auction: ComponentAddress, bidder: &Bidder, amount: u64) -> Coin {
        let data = Self::payout(amount);
        let args = Self::refund_args(auction, &bidder.key, bidder.key.public, &data.statement);
        self.ok(auction, "refund", args);
        Coin { data, value: amount }
    }

    pub fn collect(&mut self, auction: ComponentAddress, amount: u64) -> Coin {
        let data = Self::payout(amount);
        let args = Self::collect_args(auction, &self.seller, &data.statement);
        self.ok(auction, "collect", args);
        Coin { data, value: amount }
    }

    pub fn bank_balance(&mut self) -> Amount {
        let account = self.bank.0;
        self.test
            .call_method(account, "balance", args![TARI_TOKEN], vec![])
    }

    /// Spends a payout coin back into the bank: proves the payee controls exactly `value`.
    pub fn redeem(&mut self, coin: &Coin) {
        let before = self.bank_balance();
        let account = self.bank.0;
        let tx = self
            .test
            .transaction()
            .stealth_transfer(TARI_TOKEN, coin.spend_to_bucket())
            .put_last_instruction_output_on_workspace("redeemed")
            .call_method(account, "deposit", args![Workspace("redeemed")])
            .build_and_seal(coin.key());
        self.test.execute_expect_success(tx, vec![]);
        assert_eq!(
            self.bank_balance(),
            before + coin.value,
            "payee controls exactly what it was owed"
        );
    }

    pub fn phase(&mut self, auction: ComponentAddress) -> String {
        self.test.call_method(auction, "phase", args![], vec![])
    }

    pub fn result(&mut self, auction: ComponentAddress) -> Option<(u32, Amount)> {
        self.test.call_method(auction, "result", args![], vec![])
    }

    pub fn owed_to(&mut self, auction: ComponentAddress, key: RistrettoPublicKeyBytes) -> Amount {
        self.test.call_method(auction, "owed_to", args![key], vec![])
    }

    pub fn seller_owed(&mut self, auction: ComponentAddress) -> Amount {
        self.test.call_method(auction, "seller_owed", args![], vec![])
    }

    pub fn escrow(&mut self, auction: ComponentAddress) -> Amount {
        self.test.call_method(auction, "escrow_balance", args![], vec![])
    }
}
