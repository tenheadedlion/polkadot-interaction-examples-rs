use std::str::FromStr;

use hex_literal::hex;
use parity_scale_codec::{Compact, Encode};
use sp_core::{blake2_256, H256};
use sp_keyring::AccountKeyring;
use sp_runtime::{generic::Era, MultiAddress, MultiSignature};
use sp_version::RuntimeVersion;
use utils::rpc_to_localhost;

#[tokio::main]
async fn main() {
    let pallet_index: u8 = 0;
    let call_index: u8 = 1;
    let signer = AccountKeyring::Alice;
    let account = signer.to_account_id();
    let signer_nonce = get_nonce(&account).await;

    let call = (pallet_index, call_index, hex!("284772656574696e677321"));
    let extra = (
        Era::Immortal,
        Compact(signer_nonce),
        Compact(500000000000000u128),
    );

    let runtime_version = get_runtime_version().await;
    let genesis_hash = get_genesis_hash().await;

    let additional = (
        runtime_version.spec_version,
        runtime_version.transaction_version,
        genesis_hash,
        genesis_hash,
    );
    let signature = {
        // Combine this data together and SCALE encode it:
        let full_unsigned_payload = (&call, &extra, &additional);
        let full_unsigned_payload_scale_bytes = full_unsigned_payload.encode();

        // If payload is longer than 256 bytes, we hash it and sign the hash instead:
        if full_unsigned_payload_scale_bytes.len() > 256 {
            AccountKeyring::Alice.sign(&blake2_256(&full_unsigned_payload_scale_bytes)[..])
        } else {
            AccountKeyring::Alice.sign(&full_unsigned_payload_scale_bytes)
        }
    };
    let signature_to_encode = Some((
        //signer.to_h256_public(),
        MultiAddress::Id::<_, u32>(account),
        // The actual signature, computed above:
        MultiSignature::Sr25519(signature),
        // Extra information to be included in the transaction:
        extra,
    ));
    let payload_scale_encoded = encode_extrinsic(signature_to_encode, call);
    let payload_hex = format!("0x{}", hex::encode(&payload_scale_encoded));

    // Submit it!
    println!("Submitting this payload: {}", payload_hex);
    let res = rpc_to_localhost("author_submitExtrinsic", [payload_hex])
        .await
        .unwrap();

    // The result from this call is the hex value for the extrinsic hash.
    println!("{:?}", res);
}

async fn get_genesis_hash() -> H256 {
    let genesis_hash_json = rpc_to_localhost("chain_getBlockHash", [0]).await.unwrap();
    let genesis_hash_hex = genesis_hash_json.as_str().unwrap();
    H256::from_str(genesis_hash_hex).unwrap()
}

/// Fetch runtime information from the node.
async fn get_runtime_version() -> RuntimeVersion {
    let runtime_version_json = rpc_to_localhost("state_getRuntimeVersion", ())
        .await
        .unwrap();
    serde_json::from_value(runtime_version_json).unwrap()
}

/// How many transactions has this account already made?
async fn get_nonce(account: &sp_runtime::AccountId32) -> u32 {
    let nonce_json = rpc_to_localhost("system_accountNextIndex", (account,))
        .await
        .unwrap();
    serde_json::from_value(nonce_json).unwrap()
}

/// Encode the extrinsic into the expected format. De-optimised a little
/// for simplicity, and taken from sp_runtime/src/generic/unchecked_extrinsic.rs
fn encode_extrinsic<S: Encode, C: Encode>(signature: Option<S>, call: C) -> Vec<u8> {
    let mut tmp: Vec<u8> = vec![];

    // 1 byte for version ID + "is there a signature".
    // The top bit is 1 if signature present, 0 if not.
    // The remaining 7 bits encode the version number (here, 4).
    const EXTRINSIC_VERSION: u8 = 4;
    match signature.as_ref() {
        Some(s) => {
            tmp.push(EXTRINSIC_VERSION | 0b1000_0000);
            // Encode the signature itself now if it's present:
            s.encode_to(&mut tmp);
        }
        None => {
            tmp.push(EXTRINSIC_VERSION & 0b0111_1111);
        }
    }

    // Encode the call itself after this version+signature stuff.
    call.encode_to(&mut tmp);

    // We'll prefix the encoded data with it's length (compact encoding):
    let compact_len = Compact(tmp.len() as u32);

    // So, the output will consist of the compact encoded length,
    // and then the version+"is there a signature" byte,
    // and then the signature (if any),
    // and then encoded call data.
    let mut output: Vec<u8> = vec![];
    compact_len.encode_to(&mut output);
    output.extend(tmp);

    output
}
