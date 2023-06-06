use clap::{arg, Arg, Command};

use ckb_auth_rs::{
    assert_script_error, auth_builder, build_resolved_tx, debug_printer, gen_args, gen_tx,
    gen_tx_with_grouped_args, get_message_to_sign, set_signature, sign_tx, AlgorithmType, Auth,
    AuthErrorCodeType, BitcoinAuth, CKbAuth, CkbMultisigAuth, DogecoinAuth, DummyDataLoader,
    EntryCategoryType, EosAuth, EthereumAuth, SchnorrAuth, TestConfig, TronAuth, MAX_CYCLES,
};

use ckb_script::TransactionScriptsVerifier;
use ckb_types::bytes::{BufMut, Bytes, BytesMut};
use std::sync::Arc;

fn main() {
    let matches = Command::new("CKB-Auth CLI")
        .version("1.0")
        .author("Your Name")
        .about("A command-line interface for CKB-Auth")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(arg!(-b --blockchain <BLOCKCHAIN> "the blochchain to use"))
        .subcommand(
            Command::new("parse")
                .about("Parse an address and obtain the pubkey hash")
                .arg_required_else_help(true)
                .arg(arg!(-a --address <ADDRESS> "the address to pass")),
        )
        .subcommand(
            Command::new("generate")
                .about("Generate a message to be signed")
                .arg_required_else_help(true)
                .arg(arg!(-p --pubkey <PUBKEY> "the pubkey to include in the message")),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a signature")
                .arg_required_else_help(true)
                .arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to verify against"))
                .arg(arg!(-s --signature <SIGNATURE> "The signature to verify")),
        )
        .get_matches();

    let blockchain = matches.get_one::<String>("blockchain").unwrap();

    match matches.subcommand() {
        Some(("parse", parse_matches)) => {
            let address = parse_matches.get_one::<String>("address").unwrap();
            parse_address(&blockchain, &address);
        }
        Some(("generate", generate_matches)) => {
            let pubkey = generate_matches.get_one::<String>("pubkey").unwrap();
            generate_message(&blockchain, &pubkey);
        }
        Some(("verify", verify_matches)) => {
            let pubkey_hash = verify_matches.get_one::<String>("pubkeyhash").unwrap();
            let signature = verify_matches.get_one::<String>("signature").unwrap();
            verify_signature(&blockchain, &pubkey_hash, &signature);
        }
        _ => {
            // Handle invalid or missing subcommands
        }
    }
}

fn parse_address(blockchain: &str, address: &str) {}
fn generate_message(blockchain: &str, pubkey: &str) {
    let algorithm_type = AlgorithmType::Bitcoin;
    let run_type = EntryCategoryType::Exec;
    let auth = auth_builder(algorithm_type).unwrap();
    let config = TestConfig::new(&auth, run_type, 1);
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, &config);
    let message_to_sign = get_message_to_sign(tx, &config);
    dbg!(hex::encode(message_to_sign.as_bytes()));
}
fn verify_signature(blockchain: &str, pubkey_hash: &str, signature: &str) {
    let algorithm_type = AlgorithmType::Bitcoin;
    let run_type = EntryCategoryType::Exec;
    let auth = auth_builder(algorithm_type).unwrap();
    let config = TestConfig::new(&auth, run_type, 1);
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, &config);
    let signature = Bytes::new();
    let tx = set_signature(tx, &config, &signature);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = TransactionScriptsVerifier::new(Arc::new(resolved_tx), data_loader.clone());
    verifier.set_debug_printer(debug_printer);
    assert!(verifier.verify(MAX_CYCLES).is_ok());
}
