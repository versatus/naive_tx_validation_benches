use std::mem::ManuallyDrop;
use evmap::shallow_copy::ShallowCopy;
use uuid::Builder;
use secp256k1::rand::prelude::*;
use secp256k1::rand::thread_rng;
use secp256k1::{generate_keypair, Message};
use secp256k1::hashes::sha256;
use secp256k1::PublicKey;
use secp256k1::ecdsa::Signature;
use serde::{Serialize, Deserialize};

// Tx is a transaction struct that includes
// 1. Unique ID
// 2. Sender public key
// 3. Receiver address
// 4. Amount
// 5. Nonce
// 6. Fee
// 7. Data
// 8. Sender Signature
// 9. Confirmations (Eventually an LLQM Threshold Signature)

macro_rules! gen_random_bytes {
    () => {

        {
            let mut rng = thread_rng();
            let buff: Vec<u8> = (0..16).map(|_| {
                rng.gen()
            }).collect();
            
            buff
        }
    };
}

#[derive(Clone, Hash, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxMessage {
    pub msg: String,
    pub sig: String,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub id: String,
    pub pk: PublicKey,
    pub to: String,
    pub amt: String,
    pub code: String,
    pub nonce: String,
    pub fee: String,
    pub data: String,
    pub sig: Signature,
    pub conf: u32
}

impl Tx {
    pub fn random() -> Tx {
        let uuid = Builder::from_slice(&gen_random_bytes!()).unwrap()
                        .into_uuid()
                        .simple()
                        .to_string();

        let (secret_key, public_key) = generate_keypair(&mut thread_rng());

        let mut prefix = "0x192".to_string();
        let to = Builder::from_slice(&gen_random_bytes!()).unwrap().into_uuid().simple().to_string();
        prefix.push_str(&to);
        let nonce = thread_rng().gen::<u32>();
        let amt = thread_rng().gen::<u128>();
        let fee = thread_rng().gen::<u8>();
        let code = 0;
        let data: Option<String> = None;
        let payload = format!(
            "{:x?}{:x?}{:x?}{:x?}{:x?}{:x?}{:x?}{:x?}", 
            uuid, public_key.to_string(), prefix.clone(), amt, code, nonce, fee, data
        );
        let message = Message::from_hashed_data::<sha256::Hash>(payload.as_bytes());
        let sig = secret_key.sign_ecdsa(message);

        Tx {
            id: uuid,
            pk: public_key,
            to: prefix,
            amt: format!("{:x?}", amt),
            code: format!("{:x?}", code),
            nonce: format!("{:x?}", nonce),
            fee: format!("{:x?}", fee),
            data: format!("{:x?}", data),
            sig: sig,
            conf: 0,
        }
    }

    pub fn get_payload(&self) -> String {
        format!(
            "{:x?}{:x?}{:x?}{:x?}{:x?}{:x?}{:x?}{:x?}", 
            self.id, self.pk, self.to, self.amt, self.code, self.nonce, self.fee, self.data
        )
    }

}
