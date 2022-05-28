#![allow(dead_code, unused_imports)]
use crate::mempool::Mempool;
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
use std::ops::Add;
use rand;
use rand::RngCore;
use evmap::ReadGuard;
use std::io::prelude::*;
use crossbeam_channel::unbounded;
use std::io::{BufWriter, Write};

fn create_100000_txs() -> Mempool {
    let mut mempool = Mempool::new();
    (0..100000).for_each(|_| {
        let tx = Tx::random();
        mempool.add(&tx);
    });
    mempool.refresh();
    mempool
}

fn deserialize_tx(tx: String) -> Tx {
    serde_json::from_str(&tx).unwrap()
}

// TODO: add sender/receiver to below function to have confirmations sent to separate thread
// to handle writes.
#[allow(unused_must_use)]
fn validate_full_mempool(
    mempool: &mut Mempool, 
    n_readers: usize, 
    batch: bool, 
    batch_size: usize,
    timed: bool,
    sx: crossbeam_channel::Sender<std::collections::HashSet<String>>
) -> std::io::Result<()> {
    let start = std::time::Instant::now();
    let end = start + std::time::Duration::from_millis(1000);
    let handles: Vec<_> = (0..n_readers).map(|i| {
        let r = mempool.r.clone();
        let thread_sender = sx.clone();
        std::thread::spawn(move || {
            let mut confs = std::collections::HashSet::new();
            let mut rng = thread_rng();
            let mut count: u32 = 0;
            while std::time::Instant::now() < end {
                if i == 0 {
                    let id = rng.gen_range(0, 100_000 / n_readers);
                    if let Some(v) = r.get_one(&id) {
                        let mut tx = deserialize_tx(v.to_string());
                        let sig = &tx.sig;
                        let payload = tx.get_payload();
                        let message = Message::from_hashed_data::<sha256::Hash>(payload.as_bytes());
                        let _ = sig.verify(&message, &tx.pk);
                        tx.conf += 1;
                        confs.insert(serde_json::to_string(&tx).unwrap());
                        count += 1;

                        if batch {
                            if confs.len() == batch_size {
                                let _ = thread_sender.send(confs.clone());
                                confs.clear();
                            }

                        } else if !batch && !timed {
                            let _ = thread_sender.send(confs.clone());
                            confs.clear()
                        }
                        
                    };
                } else {
                    let id = rng.gen_range((i * 100_000 / n_readers) + 1, (i + 1) * (100_000 / n_readers));
                    if let Some(v) = r.clone().get_one(&id) {
                        let v = v.clone();
                        let mut tx = deserialize_tx(v.to_string());
                        let payload = tx.get_payload();
                        let message = Message::from_hashed_data::<sha256::Hash>(payload.as_bytes());
                        let _ = tx.sig.verify(&message, &tx.pk);
                        tx.conf += 1;
                        confs.insert(serde_json::to_string(&tx).unwrap());
                        count += 1;

                        if batch {
                            if confs.len() == batch_size {
                                let _ = thread_sender.send(confs.clone());
                                confs.clear();
                            }

                        } else if !batch && !timed {
                            let _ = thread_sender.send(confs.clone());
                            confs.clear()
                        }
                    };
                }
            }

            if timed {

            }

            (confs, count)
            
        })
    }).collect();

    let values: Vec<(std::collections::HashSet<String>, u32)> = handles.into_iter().map(|h| {
        h.join().unwrap()
    }).collect();

    let total = values.clone().into_iter().fold(0, |acc, x| acc + x.1);

    if timed {
        let confs = values.into_iter().map(|x| x.0).collect::<Vec<std::collections::HashSet<String>>>();
        let confs = confs.into_iter().flatten().collect::<std::collections::HashSet<String>>();
        let mut f = BufWriter::new(std::fs::File::create("C:/Bench/confs.json").unwrap());
        let write_start = std::time::Instant::now();
        timed_writes(confs.clone(), &mut f);
        let end = write_start.elapsed();
        println!("Write Conf Length: {} in {:?}", confs.len(), end);
    }

    println!("Total Validations: {}", total);

    Ok(())
}

fn single_write(
    confs: &mut std::collections::HashSet<String>, 
    tx: std::collections::HashSet<String>, 
    file: &mut BufWriter<std::fs::File>
) -> std::io::Result<()> {
    confs.extend(tx);
    file.write(&serde_json::to_vec(confs)?)?;
    Ok(())
}

fn batched_writes(
    confs: &mut std::collections::HashSet<String>, 
    tx_list: std::collections::HashSet<String>,
    file: &mut BufWriter<std::fs::File>
) -> std::io::Result<()> {
    confs.extend(tx_list);
    file.write(&serde_json::to_vec(confs)?)?;
    Ok(())
}

fn timed_writes(
    tx_list: std::collections::HashSet<String>,
    file: &mut BufWriter<std::fs::File>
) -> std::io::Result<()> {
    file.write(&serde_json::to_vec(&tx_list)?)?;
    Ok(())
}

pub mod acct;
pub mod mempool;
pub mod state;
pub mod tx;
pub mod vpu;



#[cfg(test)]
mod tests {
    use crate::*;
    use std::sync::mpsc::channel;
    #[test]
    fn test_full_validate() {
        println!("Warming up, creating BufWriter file disk writing");
        let mut f = BufWriter::new(std::fs::OpenOptions::new().write(true).append(false).create(true).open("C:/Bench/confs.json").unwrap());
        println!("Warming up, creating 100k random txs, and setting in mempool....");
        let mut mempool = create_100000_txs();
        let (sx, rx) = unbounded();
        println!("Spinning up validator unit thread(s)");
        let validator_handle = std::thread::spawn(move || {
            let _ = validate_full_mempool(&mut mempool, 50, true, 300, false, sx.clone());
        });
        println!("Starting disk writing loop up validator unit thread(s)");
        let mut conf_set = std::collections::HashSet::new();
        let write_handle = std::thread::spawn(move || {

            while let Ok(conf) = rx.recv() {
                conf_set.extend(conf);
            }
            
            let start = std::time::Instant::now();
            f.write(&serde_json::to_vec(&conf_set).unwrap()).unwrap();
            let end = start.elapsed(); 
            let reader = std::io::BufReader::new(std::fs::OpenOptions::new().write(false).read(true).open("C:/Bench/confs.json").unwrap());
            let conf_set = reader.bytes().map(|b| b.unwrap()).collect::<Vec<u8>>();
            let conf_set = serde_json::from_slice::<std::collections::HashSet<String>>(&conf_set).unwrap();
            println!("Wrote {:?} unique, validated txs to disk in {:?}", conf_set.len(), end);
        });
        
        validator_handle.join().unwrap();
        write_handle.join().unwrap();
    }
}
