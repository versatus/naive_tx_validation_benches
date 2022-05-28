#![allow(dead_code, unused_imports)]
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use validator::mempool::Mempool;
use validator::tx::Tx;
use secp256k1::rand::prelude::*;
use secp256k1::rand::thread_rng;
use secp256k1::{generate_keypair, Message};
use secp256k1::hashes::sha256;
use secp256k1::PublicKey;
use secp256k1::ecdsa::Signature;
use serde::{Serialize, Deserialize};
use std::str::FromStr;
use std::thread::JoinHandle;
use std::ops::Add;
use rand;
use rand::RngCore;
use evmap::ReadGuard;
use std::io::prelude::*;
use crossbeam_channel::unbounded;
use std::io::{BufWriter, Write};

fn create_1_tx() -> String {
    let tx = Tx::random();
    serde_json::to_string(&tx).unwrap()
}

fn create_10000_txs() -> Mempool {
    let mut mempool = Mempool::new();
    (0..10000).for_each(|_| {
        let tx = Tx::random();
        mempool.add(&tx);
    });
    mempool.refresh();
    mempool
}

fn create_100000_txs() -> Mempool {
    let mut mempool = Mempool::new();
    (0..100000).for_each(|_| {
        let tx = Tx::random();
        mempool.add(&tx);
    });
    mempool.refresh();
    mempool
}

fn create_1000000_txs() -> Mempool {
    let mut mempool = Mempool::new();
    (0..1000000).for_each(|_| {
        let tx = Tx::random();
        mempool.add(&tx);
    });
    mempool.refresh();
    mempool
}

fn create_5000000_txs() -> Mempool {
    let mut mempool = Mempool::new();
    (0..5000000).for_each(|_| {
        let tx = Tx::random();
        mempool.add(&tx);
    });
    mempool.refresh();
    mempool
}

fn deserialize_tx(tx: String) -> Tx {
    serde_json::from_str(&tx).unwrap()
}

fn recreate_payload(tx: Tx) -> String {
    tx.get_payload()
}

fn deserialize_tx_benchmark(c: &mut Criterion) {
    let tx = create_1_tx();
    c.bench_function("deserialize_tx", |b| b.iter(|| deserialize_tx(tx.clone())));
}

fn create_payload_benchmark(c: &mut Criterion) {
    let tx = deserialize_tx(create_1_tx());
    c.bench_function("create_payload", |b| b.iter(|| tx.clone().get_payload()));
}

fn signature_validation_benchmark(c: &mut Criterion) {
    let tx = deserialize_tx(create_1_tx());
    let payload = tx.get_payload();
    let message = Message::from_hashed_data::<sha256::Hash>(payload.as_bytes());
    c.bench_function("signature_validation", |b| b.iter(|| {
        tx.sig.verify(&message, &tx.pk)
    }));
}

fn signature_validation_benchmark_1_thread(c: &mut Criterion) {
    let tx = create_1_tx();
    let tx = deserialize_tx(tx);
    let payload = tx.get_payload();
    let message = Message::from_hashed_data::<sha256::Hash>(payload.as_bytes());
    c.bench_function("signature_validation_1_thread", |b| b.iter(|| {
        std::thread::spawn(move || {
            tx.sig.verify(&message, &tx.pk)
        });
    }));
}

fn full_validation_benchmark(c: &mut Criterion) {
    let tx = create_1_tx();
    c.bench_function("full_validation", |b| b.iter(|| {
        let tx = deserialize_tx(tx.clone());
        let payload = tx.get_payload();
        let message = Message::from_hashed_data::<sha256::Hash>(payload.as_bytes());
        tx.sig.verify(&message, &tx.pk)
    }));
}

fn full_validation_single_thread_benchmark(c: &mut Criterion) {
    c.bench_function("full_validation_1_thread", |b| b.iter(|| {
        std::thread::spawn(move || {
            let tx = create_1_tx();
            let tx = deserialize_tx(tx);
            let payload = tx.get_payload();
            let message = Message::from_hashed_data::<sha256::Hash>(payload.as_bytes());
            tx.sig.verify(&message, &tx.pk)
        }).join().unwrap()
    }));
}

fn recreate_tx_message(c: &mut Criterion) {
    let payload = deserialize_tx(create_1_tx()).get_payload();
    let payload = payload.as_bytes();
    c.bench_function("recreate_tx_message", |b| b.iter(|| {
        Message::from_hashed_data::<sha256::Hash>(payload);
    }));
}

fn create_1_tx_benchmark(c: &mut Criterion) {
    c.bench_function("single_tx", |b| b.iter(|| {
        create_1_tx()
    }));
}

fn create_file_bench(c: &mut Criterion) {
    c.bench_function("file_creation", |b| b.iter(|| {
        std::fs::File::create("test.json")
    }));
}

fn create_file_bench_ssd(c: &mut Criterion) {
    c.bench_function("file_creation_ssd", |b| b.iter(|| {
        std::fs::File::create("C:/Bench/test.json")
    }));
}

fn clone_large_read_handle(c: &mut Criterion) {
    let mempool = create_100000_txs();
    c.bench_function("clone_large_mempool_reader", |b| b.iter(|| {
        let _ = mempool.r.clone();
    }));
}

fn sererialize_signature(c: &mut Criterion) {
    let tx = create_1_tx();
    let tx = deserialize_tx(tx);
    c.bench_function("deserialize_signature", |b| b.iter(|| {
        tx.sig.to_string();
    }));
}

fn seriailize_tx(c: &mut Criterion) {
    let tx = create_1_tx();
    let tx = deserialize_tx(tx);
    c.bench_function("serialize_tx", |b| b.iter(|| {
        serde_json::to_string(&tx).unwrap()
    }));
}

criterion_group!(
    benches, 
    deserialize_tx_benchmark, 
    create_payload_benchmark, 
    signature_validation_benchmark,
    full_validation_benchmark,
    create_1_tx_benchmark,
    full_validation_single_thread_benchmark,
    signature_validation_benchmark_1_thread,
    recreate_tx_message,
    clone_large_read_handle,
    sererialize_signature,
    create_file_bench,
    create_file_bench_ssd,
);

criterion_main!(benches);
