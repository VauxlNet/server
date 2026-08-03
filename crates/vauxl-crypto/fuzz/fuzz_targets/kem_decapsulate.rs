#![no_main]

use libfuzzer_sys::fuzz_target;
use vauxl_crypto::kem::{decapsulate, encapsulate, generate_xwing_keypair};

fuzz_target!(|data: &[u8]| {
    let (public_key, secret_key) = generate_xwing_keypair();
    let Ok((mut ciphertext, _)) = encapsulate(&public_key) else {
        return;
    };

    for (index, byte) in data.iter().enumerate() {
        if index < ciphertext.x25519_ephemeral_pub.len() {
            ciphertext.x25519_ephemeral_pub[index] ^= byte;
        } else {
            let index = (index - ciphertext.x25519_ephemeral_pub.len())
                % ciphertext.mlkem_ciphertext.len();
            ciphertext.mlkem_ciphertext[index] ^= byte;
        }
    }

    let _ = decapsulate(&secret_key, &ciphertext);
});
