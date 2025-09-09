
use filosign_crypto_utils::{generate_register_challenge, derive_encryption_material};

fn main() {
    let address = "0x1234567890abcdef";
    let version = "1";
    
    let challenge_result = generate_register_challenge(address, version);
    println!("Challenge: {:?}", challenge_result);
    
    let signature_b64 = "dGVzdCBzaWduYXR1cmUgZGF0YQ==";
    let pin = "1234";
    let pin_salt_b64 = "cGluX3NhbHRfZXhhbXBsZQ==";
    let auth_salt_b64 = "YXV0aF9zYWx0X2V4YW1wbGU=";
    let wrapper_salt_b64 = "d3JhcHBlcl9zYWx0X2V4YW1wbGU=";
    let cid = "test_cid";
    
    let derivation_result = derive_encryption_material(
        signature_b64, 
        pin, 
        pin_salt_b64, 
        auth_salt_b64, 
        wrapper_salt_b64, 
        cid
    );
    println!("Derivation: {:?}", derivation_result);
}
