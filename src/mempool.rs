use evmap::{ReadHandle, WriteHandle, shallow_copy::ShallowCopy, ReadGuard};
use crate::tx::Tx;
use secp256k1::rand::prelude::*;
use secp256k1::rand::thread_rng;
use secp256k1::{generate_keypair, Message};
use secp256k1::hashes::sha256;
use secp256k1::PublicKey;
use secp256k1::ecdsa::Signature;
use serde::{Serialize, Deserialize};
use std::str::FromStr;
use std::thread::JoinHandle;
// The mempool is a map of transactions awaiting confirmation
// It should include an ID -> Transaction Key/Value pair
// Tx's will include confirmations

pub struct Mempool {
    pub r: ReadHandle<usize, String>,
    w: WriteHandle<usize, String>,
    nonce: usize,
}

impl Mempool {
    
    pub fn new() -> Mempool {
        let (r, mut w) = evmap::new();
        Mempool { r, w, nonce: 0 }
    }

    pub fn add(&mut self, tx: &Tx) {
        self.w.insert(self.nonce, serde_json::to_string(tx).unwrap());
        self.nonce += 1;
    }

    pub fn refresh(&mut self) {
        self.w.refresh();
    }

    pub fn update(&mut self, nonce: usize, tx: &Tx) {
        self.w.update(nonce, serde_json::to_string(tx).unwrap());
    }

    pub fn iter_read(&self)  -> Vec<JoinHandle<Option<bool>>> {
        let readers: Vec<_> = (0..self.r.len()).map(|i| {
            let r = self.r.clone();
            std::thread::spawn(move || {
                if let Some(guard) = r.get_one(&i) {
                    let tx: Tx = serde_json::from_str(&guard).unwrap();
                    let payload = tx.get_payload();
                    let message = Message::from_hashed_data::<sha256::Hash>(payload.as_bytes());
                    let valid: bool = tx.sig.verify(&message, &tx.pk).is_ok();   

                    Some(valid)

                } else {

                    None

                }
            })
        }).collect();

        readers
    }
}