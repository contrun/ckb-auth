use ckb_auth_rs::{
    auth_builder, build_resolved_tx, debug_printer, gen_tx_with_pub_key_hash, get_message_to_sign,
    set_signature, AlgorithmType, DummyDataLoader, EntryCategoryType, TestConfig, MAX_CYCLES,
};

use ckb_script::TransactionScriptsVerifier;

use std::sync::Arc;

use anyhow::{anyhow, Error};
use clap::{arg, Command};

fn main() -> Result<(), Error> {
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
                .arg(arg!(-a --address <ADDRESS> "The address to parse")),
        )
        .subcommand(
            Command::new("generate")
                .about("Generate a message to be signed")
                .arg_required_else_help(true)
                .arg(arg!(-a --address <ADDRESS> "The pubkey address whose hash will be included in the message").required(false))
                .arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to include in the message").required(false))
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a signature")
                .arg_required_else_help(true)
                .arg(arg!(-a --address <ADDRESS> "The pubkey address whose hash verify against"))
                .arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to verify against"))
                .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
                .arg(arg!(-e --encoding <ENCODING> "The encoding of the signature (may be hex or base64)"))
        )
        .get_matches();

    let blockchain = matches.get_one::<String>("blockchain").unwrap();

    match matches.subcommand() {
        Some(("parse", parse_matches)) => {
            let address = parse_matches.get_one::<String>("address").unwrap();
            parse_address(blockchain, address);
            Ok(())
        }
        Some(("generate", generate_matches)) => {
            let address = generate_matches.get_one::<String>("address");
            let pubkeyhash = generate_matches.get_one::<String>("pubkeyhash");
            let pubkeyhash = get_pub_key_hash(
                blockchain,
                address.as_ref().map(|x| x.as_str()),
                pubkeyhash.as_ref().map(|x| x.as_str()),
            )?;
            generate_message(blockchain, pubkeyhash);
            Ok(())
        }
        Some(("verify", verify_matches)) => {
            let address = verify_matches.get_one::<String>("address");
            let pubkeyhash = verify_matches.get_one::<String>("pubkeyhash");
            let pubkeyhash = get_pub_key_hash(
                blockchain,
                address.as_ref().map(|x| x.as_str()),
                pubkeyhash.as_ref().map(|x| x.as_str()),
            )?;
            let signature = verify_matches.get_one::<String>("signature").unwrap();
            let encoding = verify_matches
                .get_one::<String>("encoding")
                .map(String::as_str)
                .unwrap_or("hex");
            let signature = decode_string(signature, encoding)?;
            verify_signature(blockchain, pubkeyhash, signature);
            Ok(())
        }
        _ => {
            Err(anyhow!("Unknown subcommand"))
            // Handle invalid or missing subcommands
        }
    }
}

fn decode_string(s: &str, encoding: &str) -> Result<Vec<u8>, Error> {
    match encoding {
        "hex" => Ok(hex::decode(s)?),
        "base64" => {
            use base64::{engine::general_purpose, Engine as _};
            Ok(general_purpose::STANDARD.decode(s)?)
        }
        _ => Err(anyhow!("Unknown encoding {}", encoding)),
    }
}
fn get_pub_key_hash(
    blockchain: &str,
    address: Option<&str>,
    pubkeyhash: Option<&str>,
) -> Result<Vec<u8>, Error> {
    if pubkeyhash.is_some() {
        return Ok(hex::decode(pubkeyhash.unwrap())?);
    }
    if address.is_none() {
        return Err(anyhow!("Must pass pubkey or pubkeyhash"));
    }
    get_pub_key_hash_from_address(blockchain, address.unwrap())
}

fn get_pub_key_hash_from_address(blockchain: &str, address: &str) -> Result<Vec<u8>, Error> {
    if blockchain == "litecoin" {
        // base58 -d <<< mhknqLHQGWDXuLsPdzab8nA4jD3fMdVYS2 | xxd -s 1 -l 20 -p
        let bytes = bs58::decode(&address).into_vec()?;
        return Ok(bytes[1..21].into());
    }
    Err(anyhow!("Unknown blockchain: {}", blockchain))
}

fn parse_address(blockchain: &str, address: &str) {
    println!(
        "{}",
        hex::encode(get_pub_key_hash_from_address(blockchain, address).expect("get pub key hash"))
    );
}

fn generate_message(_blockchain: &str, pubkeyhash: Vec<u8>) {
    let algorithm_type = AlgorithmType::Bitcoin;
    let run_type = EntryCategoryType::Exec;
    let auth = auth_builder(algorithm_type, false).unwrap();
    let config = TestConfig::new(&auth, run_type, 1);
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx_with_pub_key_hash(&mut data_loader, &config, pubkeyhash);
    let message_to_sign = get_message_to_sign(tx, &config);
    println!("{}", hex::encode(message_to_sign.as_bytes()));
}

fn verify_signature(_blockchain: &str, pubkeyhash: Vec<u8>, signature: Vec<u8>) {
    let algorithm_type = AlgorithmType::Bitcoin;
    let run_type = EntryCategoryType::Exec;
    let auth = auth_builder(algorithm_type, false).unwrap();
    let config = TestConfig::new(&auth, run_type, 1);
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx_with_pub_key_hash(&mut data_loader, &config, pubkeyhash);
    let signature = signature.into();
    let tx = set_signature(tx, &signature);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = TransactionScriptsVerifier::new(Arc::new(resolved_tx), data_loader.clone());
    verifier.set_debug_printer(debug_printer);
    let result = verifier.verify(MAX_CYCLES);
    if result.is_err() {
        dbg!(result.unwrap_err());
        panic!("Verification failed");
    }
}
