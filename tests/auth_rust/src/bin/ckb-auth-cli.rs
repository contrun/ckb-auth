use clap::{arg, Arg, Command};

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
                .arg(arg!(-p --pubkey <PUBKEY_HASH> "The pubkey hash to verify against"))
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
            let pubkey_hash = verify_matches.get_one::<String>("pubkey_hash").unwrap();
            let signature = verify_matches.get_one::<String>("signature").unwrap();
            verify_signature(&blockchain, &pubkey_hash, &signature);
        }
        _ => {
            // Handle invalid or missing subcommands
        }
    }
}

fn parse_address(blockchain: &str, address: &str) {}
fn generate_message(blockchain: &str, pubkey: &str) {}
fn verify_signature(blockchain: &str, pubkey_hash: &str, signature: &str) {}
