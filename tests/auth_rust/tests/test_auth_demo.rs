#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_crypto::secp::{Generator, Privkey, Pubkey};
use ckb_script::TransactionScriptsVerifier;
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    H256,
};
use log::{Level, LevelFilter, Metadata, Record};
use rand::{thread_rng, Rng};
use sha3::{digest::generic_array::typenum::private::IsEqualPrivate, Digest, Keccak256};
use std::sync::Arc;

use hex_literal::hex;

use misc::{
    assert_script_error, auth_builder, build_resolved_tx, debug_printer, gen_args, gen_tx,
    gen_tx_with_grouped_args, sign_tx, AlgorithmType, Auth, AuthErrorCodeType, BitcoinAuth,
    CKbAuth, CkbMultisigAuth, DogecoinAuth, DummyDataLoader, EntryCategoryType, EosAuth,
    EthereumAuth, LitecoinAuth, SchnorrAuth, TestConfig, TronAuth, MAX_CYCLES,
};
mod misc;

fn verify_unit(config: &TestConfig) -> Result<u64, ckb_error::Error> {
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, &config);
    let tx = sign_tx(tx, &config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = TransactionScriptsVerifier::new(Arc::new(resolved_tx), data_loader.clone());
    verifier.set_debug_printer(debug_printer);
    verifier.verify(MAX_CYCLES)
}

fn assert_result_ok(res: Result<u64, ckb_error::Error>, des: &str) {
    assert!(
        res.is_ok(),
        "pass {} verification, des: {}",
        des,
        res.unwrap_err().to_string()
    );
}

fn assert_result_error(res: Result<u64, ckb_error::Error>, des: &str, err_codes: &[i32]) {
    assert!(
        res.is_err(),
        "pass failed {} verification, des: run ok",
        des
    );
    let err_str = res.unwrap_err().to_string();
    let mut is_assert = false;
    for err_code in err_codes {
        if err_str.contains(format!("error code {}", err_code).as_str()) {
            is_assert = true;
            break;
        }
    }

    if !is_assert {
        assert!(false, "pass {} verification, des: {}", des, err_str);
    }
}

fn unit_test_success(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    let config = TestConfig::new(auth, run_type, 1);
    assert_result_ok(verify_unit(&config), "");
}

fn unit_test_multiple_args(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    let config = TestConfig::new(auth, run_type, 5);

    assert_result_ok(verify_unit(&config), "multiple args");
}

fn unit_test_multiple_group(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    let mut data_loader = DummyDataLoader::new();

    let config = TestConfig::new(auth, run_type, 1);

    let mut rng = thread_rng();
    let tx = gen_tx_with_grouped_args(
        &mut data_loader,
        vec![
            (gen_args(&config), 1),
            (gen_args(&config), 1),
            (gen_args(&config), 1),
        ],
        &mut rng,
    );

    let tx = sign_tx(tx, &config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = TransactionScriptsVerifier::new(Arc::new(resolved_tx), data_loader.clone());
    verifier.set_debug_printer(debug_printer);

    assert_result_ok(verify_unit(&config), "multiple group");
}

fn unit_test_faileds(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    // public key
    {
        let mut config = TestConfig::new(auth, run_type, 1);
        config.incorrect_pubkey = true;

        assert_result_error(
            verify_unit(&config),
            "public key",
            &[AuthErrorCodeType::Mismatched as i32],
        );
    }

    // sign data
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign data",
            &[
                AuthErrorCodeType::Mismatched as i32,
                AuthErrorCodeType::InvalidArg as i32,
            ],
        );
    }

    // sign size bigger
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign_size = misc::TestConfigIncorrectSing::Bigger;
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign size(bigger)",
            &[
                AuthErrorCodeType::Mismatched as i32,
                AuthErrorCodeType::InvalidArg as i32,
            ],
        );
    }

    // sign size smaller
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign_size = misc::TestConfigIncorrectSing::Smaller;
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[
                AuthErrorCodeType::Mismatched as i32,
                AuthErrorCodeType::InvalidArg as i32,
            ],
        );
    }
}

fn unit_test_common_with_auth(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    unit_test_success(auth, run_type);
    unit_test_multiple_args(auth, run_type);
    unit_test_multiple_group(auth, run_type);

    unit_test_faileds(auth, run_type);
}

fn unit_test_common_with_runtype(
    algorithm_type: AlgorithmType,
    run_type: EntryCategoryType,
    using_official_client: bool,
) {
    let auth = auth_builder(algorithm_type, using_official_client).unwrap();
    unit_test_common_with_auth(&auth, run_type);
}

fn unit_test_common(algorithm_type: AlgorithmType) {
    for t in [EntryCategoryType::DynamicLinking, EntryCategoryType::Exec] {
        unit_test_common_with_runtype(algorithm_type, t, false);
    }
}

fn unit_test_common_official(algorithm_type: AlgorithmType) {
    for t in [EntryCategoryType::DynamicLinking, EntryCategoryType::Exec] {
        unit_test_common_with_runtype(algorithm_type, t, true);
    }
}

#[test]
fn ckb_verify() {
    unit_test_common(AlgorithmType::Ckb);
}

#[test]
fn ethereum_verify() {
    unit_test_common(AlgorithmType::Ethereum);
}

#[test]
fn eos_verify() {
    unit_test_common(AlgorithmType::Eos);
}

#[test]
fn tron_verify() {
    unit_test_common(AlgorithmType::Tron);
}

#[test]
fn bitcoin_verify() {
    unit_test_common(AlgorithmType::Bitcoin);
}

#[test]
fn bitcoin_uncompress_verify() {
    let mut auth = misc::BitcoinAuth::new();
    auth.compress = false;
    let auth: Box<dyn Auth> = auth;
    unit_test_common_with_auth(&auth, EntryCategoryType::DynamicLinking);
    unit_test_common_with_auth(&auth, EntryCategoryType::Exec);
}

#[test]
fn bitcoin_pubkey_recid_verify() {
    #[derive(Clone)]
    pub struct BitcoinFailedAuth(BitcoinAuth);
    impl Auth for BitcoinFailedAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            BitcoinAuth::get_btc_pub_key_hash(&self.0.privkey, self.0.compress)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Bitcoin as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            BitcoinAuth::btc_convert_message(message)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            let sign = self
                .0
                .privkey
                .sign_recoverable(&msg)
                .expect("sign")
                .serialize();
            assert_eq!(sign.len(), 65);

            let mut rng = rand::thread_rng();
            let mut recid: u8 = rng.gen_range(0, 4);
            while recid == sign[64] && recid < 31 {
                recid = rng.gen_range(0, 4);
            }
            let mut mark: u8 = sign[64];
            if self.0.compress {
                mark = mark | 4;
            }
            let mut ret = BytesMut::with_capacity(65);
            ret.put_u8(mark);
            ret.put(&sign[0..64]);
            Bytes::from(ret)
        }
    }

    let privkey = Generator::random_privkey();
    let auth: Box<dyn Auth> = Box::new(BitcoinFailedAuth {
        0: BitcoinAuth {
            privkey,
            compress: true,
        },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver btc",
        &[
            AuthErrorCodeType::Mismatched as i32,
            AuthErrorCodeType::ErrorWrongState as i32,
        ],
    );
}

#[test]
fn dogecoin_verify() {
    unit_test_common(AlgorithmType::Dogecoin);
}

#[test]
fn litecoin_verify() {
    unit_test_common(AlgorithmType::Litecoin);
}

#[test]
fn litecoin_verify_official() {
    // We need litecoin binaries to test signing.
    if which::which("litecoin-cli").is_err() {
        return;
    }
    unit_test_common_official(AlgorithmType::Litecoin);
}

#[test]
fn monero_old_verify() {
    unit_test_common(AlgorithmType::Monero);
}

#[test]
fn monero_verify() {
    let algorithm_type = AlgorithmType::Monero;
    let auth = auth_builder(algorithm_type, false).unwrap();
    let run_type = EntryCategoryType::Exec;
    unit_test_success(&auth, run_type);
}

// // Set up an address signature message hash
// // Hash data: domain separator, spend public key, view public key, mode identifier, payload data
// static crypto::hash get_message_hash(const std::string &data, const crypto::public_key &spend_key, const crypto::public_key &view_key, const uint8_t mode)
// {
//   KECCAK_CTX ctx;
//   keccak_init(&ctx);
//   keccak_update(&ctx, (const uint8_t*)config::HASH_KEY_MESSAGE_SIGNING, sizeof(config::HASH_KEY_MESSAGE_SIGNING)); // includes NUL
//   keccak_update(&ctx, (const uint8_t*)&spend_key, sizeof(crypto::public_key));
//   keccak_update(&ctx, (const uint8_t*)&view_key, sizeof(crypto::public_key));
//   keccak_update(&ctx, (const uint8_t*)&mode, sizeof(uint8_t));
//   char len_buf[(sizeof(size_t) * 8 + 6) / 7];
//   char *ptr = len_buf;
//   tools::write_varint(ptr, data.size());
//   CHECK_AND_ASSERT_THROW_MES(ptr > len_buf && ptr <= len_buf + sizeof(len_buf), "Length overflow");
//   keccak_update(&ctx, (const uint8_t*)len_buf, ptr - len_buf);
//   keccak_update(&ctx, (const uint8_t*)data.data(), data.size());
//   crypto::hash hash;
//   keccak_finish(&ctx, (uint8_t*)&hash);
//   return hash;
// }
//

fn get_test_key_pair() -> monero::KeyPair {
    let view_key: [u8; 32] =
        hex!("972874ae95f5c167285858141e940847398f9c246c7913c0d396b6d73b484105");
    let view_key = monero::PrivateKey::from_slice(&view_key).unwrap();

    let spend_key: [u8; 32] =
        hex!("8ef26aced8b5f8e1e8ce63b6c75ac6ee41424242424242424242424242424202");
    let spend_key = monero::PrivateKey::from_slice(&spend_key).unwrap();

    monero::KeyPair {
        view: view_key,
        spend: spend_key,
    }
}

fn get_varint(i: usize) -> Vec<u8> {
    let mut res = Vec::new();
    let mut i = i;
    loop {
        if i < 0x80 {
            break;
        }
        res.push(((i & 0x7f) | 0x80) as u8);
        i = i >> 7;
    }
    res.push(i as u8);
    res
}

fn get_message_hash(keypair: &monero::KeyPair, message: &[u8]) -> [u8; 32] {
    use monero::cryptonote::hash::keccak_256;
    //   KECCAK_CTX ctx;
    //   keccak_init(&ctx);
    //   keccak_update(&ctx, (const uint8_t*)config::HASH_KEY_MESSAGE_SIGNING, sizeof(config::HASH_KEY_MESSAGE_SIGNING)); // includes NUL
    //   keccak_update(&ctx, (const uint8_t*)&spend_key, sizeof(crypto::public_key));
    //   keccak_update(&ctx, (const uint8_t*)&view_key, sizeof(crypto::public_key));
    //   keccak_update(&ctx, (const uint8_t*)&mode, sizeof(uint8_t));
    //   char len_buf[(sizeof(size_t) * 8 + 6) / 7];
    //   char *ptr = len_buf;
    //   tools::write_varint(ptr, data.size());
    //   CHECK_AND_ASSERT_THROW_MES(ptr > len_buf && ptr <= len_buf + sizeof(len_buf), "Length overflow");
    //   keccak_update(&ctx, (const uint8_t*)len_buf, ptr - len_buf);
    //   keccak_update(&ctx, (const uint8_t*)data.data(), data.size());
    //   crypto::hash hash;
    //   keccak_finish(&ctx, (uint8_t*)&hash);
    const HASH_KEY_MESSAGE_SIGNING: &[u8; 23] = b"MoneroMessageSignature\x00";
    let spend_pubkey = monero::PublicKey::from_private_key(&keypair.spend);
    let spend_pubkey = spend_pubkey.as_bytes();
    let view_pubkey = monero::PublicKey::from_private_key(&keypair.view);
    let view_pubkey = view_pubkey.as_bytes();
    let mode: [u8; 1] = [0];
    let varint = get_varint(message.len());
    let len = HASH_KEY_MESSAGE_SIGNING.len()
        + spend_pubkey.len()
        + view_pubkey.len()
        + 1
        + varint.len()
        + message.len();
    let mut buf = BytesMut::with_capacity(len);
    buf.put_slice(HASH_KEY_MESSAGE_SIGNING.as_slice());
    buf.put_slice(spend_pubkey);
    buf.put_slice(view_pubkey);
    buf.put_slice(&mode);
    buf.put_slice(&varint);
    buf.put_slice(&message);

    let msg = buf.freeze();
    dbg!(hex::encode(&msg));

    use tiny_keccak::Hasher;
    use tiny_keccak::Keccak;
    let mut keccak = Keccak::v256();

    let mut out = [0u8; 32];
    keccak.update(HASH_KEY_MESSAGE_SIGNING.as_slice());
    keccak.update(spend_pubkey);
    keccak.update(view_pubkey);
    keccak.update(&mode);
    keccak.update(&varint);
    keccak.update(&message);
    keccak.finalize(&mut out);

    dbg!(hex::encode(out));
    keccak_256(&msg)
}

#[test]
fn monero_hash_test() {
    let message = b"helloworld";
    let keypair = get_test_key_pair();
    // [tests/test_auth_demo.rs:388] hex::encode(&msg) = "4d6f6e65726f4d6573736167655369676e617475726500
    // 007caf7a553a894389dd562115b17e78ba84a5c7692677f216c54385dc5c6ff1
    // bbcb8c902571ae1a777f7f07a023ecc5e3d83ba624d4b0ffb7eff79e8b5d10bd
    // 00
    // 0a
    // 68656c6c6f776f726c64"
    // [tests/test_auth_demo.rs:397] hex::encode(&message_hash) = "7c7122c67b25b5fee952ba8b1ee73cfa41e14383f170b04206aeed709a220b60"
    // test monero_hash_test ... ok
    let message_hash = get_message_hash(&keypair, message);
    dbg!(hex::encode(&message_hash));
}

#[test]
fn convert_eth_error() {
    #[derive(Clone)]
    struct EthConverFaileAuth(EthereumAuth);
    impl Auth for EthConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            EthereumAuth::get_eth_pub_key_hash(&self.0.pubkey)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Ethereum as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let eth_prefix: &[u8; 28] = b"\x19Ethereum Signed Xessage:\n32";
            let mut hasher = Keccak256::new();
            hasher.update(eth_prefix);
            hasher.update(message);
            let r = hasher.finalize();
            let ret = H256::from_slice(r.as_slice()).expect("convert_keccak256_hash");
            ret
        }
        fn sign(&self, msg: &H256) -> Bytes {
            EthereumAuth::eth_sign(msg, &self.0.privkey)
        }
    }

    let generator: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let (privkey, pubkey) = generator.generate_keypair(&mut rng);

    let auth: Box<dyn Auth> = Box::new(EthConverFaileAuth {
        0: EthereumAuth { privkey, pubkey },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver eth",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[test]
fn convert_eos_error() {
    #[derive(Clone)]
    struct EthConverFaileAuth(EosAuth);
    impl Auth for EthConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            EthereumAuth::get_eth_pub_key_hash(&self.0.pubkey)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Eos as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            use mbedtls::hash::{Md, Type::Sha256};
            let mut md = Md::new(Sha256).unwrap();
            md.update(message).expect("sha256 update data");
            md.update(&[1, 2, 3]).expect("sha256 update data");

            let mut msg = [0u8; 32];
            md.finish(&mut msg).expect("sha256 finish");
            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            EthereumAuth::eth_sign(msg, &self.0.privkey)
        }
    }

    let generator: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let (privkey, pubkey) = generator.generate_keypair(&mut rng);

    let auth: Box<dyn Auth> = Box::new(EthConverFaileAuth {
        0: EosAuth { privkey, pubkey },
    });
    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver eos",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[test]
fn convert_tron_error() {
    #[derive(Clone)]
    struct TronConverFaileAuth(TronAuth);
    impl Auth for TronConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            EthereumAuth::get_eth_pub_key_hash(&self.0.pubkey)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Tron as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let eth_prefix: &[u8; 24] = b"\x19TRON Signed Xessage:\n32";
            let mut hasher = Keccak256::new();
            hasher.update(eth_prefix);
            hasher.update(message);
            let r = hasher.finalize();
            H256::from_slice(r.as_slice()).expect("convert_keccak256_hash")
        }
        fn sign(&self, msg: &H256) -> Bytes {
            EthereumAuth::eth_sign(msg, &self.0.privkey)
        }
    }

    let generator: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let (privkey, pubkey) = generator.generate_keypair(&mut rng);
    let auth: Box<dyn Auth> = Box::new(TronConverFaileAuth {
        0: TronAuth { privkey, pubkey },
    });
    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver tron",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[test]
fn convert_btc_error() {
    #[derive(Clone)]
    struct BtcConverFaileAuth(BitcoinAuth);
    impl Auth for BtcConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            BitcoinAuth::get_btc_pub_key_hash(&self.0.privkey, self.0.compress)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Bitcoin as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let message_magic = b"\x18Bitcoin Signed Xessage:\n\x40";
            let msg_hex = hex::encode(message);
            assert_eq!(msg_hex.len(), 64);

            let mut temp2: BytesMut = BytesMut::with_capacity(message_magic.len() + msg_hex.len());
            temp2.put(Bytes::from(message_magic.to_vec()));
            temp2.put(Bytes::from(hex::encode(message)));

            let msg = misc::calculate_sha256(&temp2);
            let msg = misc::calculate_sha256(&msg);

            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            BitcoinAuth::btc_sign(msg, &self.0.privkey, self.0.compress)
        }
    }

    let privkey = Generator::random_privkey();
    let auth: Box<dyn Auth> = Box::new(BtcConverFaileAuth {
        0: BitcoinAuth {
            privkey,
            compress: true,
        },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver btc",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[test]
fn convert_doge_error() {
    #[derive(Clone)]
    struct DogeConverFaileAuth(DogecoinAuth);
    impl Auth for DogeConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            BitcoinAuth::get_btc_pub_key_hash(&self.0.privkey, self.0.compress)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Bitcoin as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let message_magic = b"\x18Bitcoin Signed Xessage:\n\x40";
            let msg_hex = hex::encode(message);
            assert_eq!(msg_hex.len(), 64);

            let mut temp2: BytesMut = BytesMut::with_capacity(message_magic.len() + msg_hex.len());
            temp2.put(Bytes::from(message_magic.to_vec()));
            temp2.put(Bytes::from(hex::encode(message)));

            let msg = misc::calculate_sha256(&temp2);
            let msg = misc::calculate_sha256(&msg);

            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            BitcoinAuth::btc_sign(msg, &self.0.privkey, self.0.compress)
        }
    }

    let privkey = Generator::random_privkey();
    let auth: Box<dyn Auth> = Box::new(DogeConverFaileAuth {
        0: DogecoinAuth {
            privkey,
            compress: true,
        },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver doge",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[test]
fn convert_lite_error() {
    #[derive(Clone)]
    struct LiteConverFaileAuth(LitecoinAuth);
    impl Auth for LiteConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            BitcoinAuth::get_btc_pub_key_hash(&self.0.get_privkey(), self.0.compress)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Bitcoin as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let message_magic = b"\x18Bitcoin Signed Xessage:\n\x40";
            let msg_hex = hex::encode(message);
            assert_eq!(msg_hex.len(), 64);

            let mut temp2: BytesMut = BytesMut::with_capacity(message_magic.len() + msg_hex.len());
            temp2.put(Bytes::from(message_magic.to_vec()));
            temp2.put(Bytes::from(hex::encode(message)));

            let msg = misc::calculate_sha256(&temp2);
            let msg = misc::calculate_sha256(&msg);

            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            BitcoinAuth::btc_sign(msg, &self.0.get_privkey(), self.0.compress)
        }
    }

    let sk = Generator::random_secret_key().secret_bytes();
    let auth: Box<dyn Auth> = Box::new(LiteConverFaileAuth {
        0: LitecoinAuth {
            official: false,
            sk,
            compress: true,
            network: bitcoin::Network::Testnet,
        },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver lite",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[derive(Clone)]
pub struct CkbMultisigFailedAuth(CkbMultisigAuth);
impl Auth for CkbMultisigFailedAuth {
    fn get_pub_key_hash(&self) -> Vec<u8> {
        self.0.hash.clone()
    }
    fn get_algorithm_type(&self) -> u8 {
        AlgorithmType::CkbMultisig as u8
    }
    fn sign(&self, msg: &H256) -> Bytes {
        let sign_data = self.0.multickb_sign(msg);
        let mut buf = BytesMut::with_capacity(sign_data.len() + 10);
        buf.put(sign_data);
        buf.put(Bytes::from([0; 10].to_vec()));
        buf.freeze()
    }
    fn get_sign_size(&self) -> usize {
        self.0.get_mulktisig_size()
    }
}

fn unit_test_ckbmultisig(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    unit_test_success(auth, run_type);
    unit_test_multiple_args(auth, run_type);
    unit_test_multiple_group(auth, run_type);

    // public key
    {
        let mut config = TestConfig::new(auth, run_type, 1);
        config.incorrect_pubkey = true;

        assert_result_error(verify_unit(&config), "public key", &[-51]);
    }

    // sign data
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign data",
            &[-41, -42, -43, -44, -22],
        );
    }

    // sign size bigger
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign_size = misc::TestConfigIncorrectSing::Bigger;
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign size(bigger)",
            &[-41, -42, -43, -44, -22],
        );
    }

    // sign size smaller
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign_size = misc::TestConfigIncorrectSing::Smaller;
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[-41, -42, -43, -44, -22],
        );
    }

    // cnt_failed
    {
        let auth: Box<dyn Auth> = CkbMultisigAuth::new(2, 3, 1);
        let config = TestConfig::new(&auth, run_type, 1);
        assert_result_error(verify_unit(&config), "cnt failed", &[-43]);
    }

    // cnt_failed
    {
        let auth: Box<dyn Auth> = CkbMultisigAuth::new(2, 2, 4);
        let config = TestConfig::new(&auth, run_type, 1);
        assert_result_error(verify_unit(&config), "require_first_n failed", &[-44]);

        // #define ERROR_INVALID_REQUIRE_FIRST_N -44
    }

    {
        let auth: Box<dyn Auth> = Box::new(CkbMultisigFailedAuth {
            0: {
                let pubkeys_cnt = 2;
                let threshold = 2;
                let require_first_n = 0;
                let (pubkey_data, privkeys) =
                    CkbMultisigAuth::generator_key(pubkeys_cnt, threshold, require_first_n);
                let hash = ckb_hash::blake2b_256(&pubkey_data);
                CkbMultisigAuth {
                    pubkeys_cnt,
                    threshold,
                    pubkey_data,
                    privkeys,
                    hash: hash[0..20].to_vec(),
                }
            },
        });
        let config = TestConfig::new(&auth, run_type, 1);
        assert_result_error(verify_unit(&config), "require_first_n failed", &[-22]);
        // #define ERROR_WITNESS_SIZE -22
    }
}

#[test]
fn ckbmultisig_verify() {
    let auth: Box<dyn Auth> = CkbMultisigAuth::new(2, 2, 1);
    unit_test_ckbmultisig(&auth, EntryCategoryType::DynamicLinking);
    unit_test_ckbmultisig(&auth, EntryCategoryType::Exec);
}

#[test]
fn ckbmultisig_verify_sing_size_failed() {}

#[test]
fn schnorr_verify() {
    unit_test_common(AlgorithmType::SchnorrOrTaproot);
}

#[test]
fn abnormal_algorithm_type() {
    #[derive(Clone)]
    struct AbnormalAuth {}
    impl misc::Auth for AbnormalAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            [0; 20].to_vec()
        }
        fn get_algorithm_type(&self) -> u8 {
            32
        }
        fn sign(&self, _msg: &H256) -> Bytes {
            Bytes::from([0; 85].to_vec())
        }
    }

    let auth: Box<dyn Auth> = Box::new(AbnormalAuth {});
    {
        let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[AuthErrorCodeType::NotImplemented as i32],
        );
    }
    {
        let config = TestConfig::new(&auth, EntryCategoryType::Exec, 1);
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[AuthErrorCodeType::NotImplemented as i32],
        );
    }
}
