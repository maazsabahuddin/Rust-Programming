extern crate clap;

use openssl::rsa::{Rsa, Padding};
use std::error::Error;
use std::fs::{File};
use std::io::{Read, Write};

fn generate_key_pair(pub_key_path: &str, priv_key_path: &str, key_size: u32) -> Result<(), Box<dyn Error>> {
    let rsa = Rsa::generate(key_size)?;

    let pub_key_pem = rsa.public_key_to_pem()?;
    let priv_key_pem = rsa.private_key_to_pem()?;

    let mut pub_key_file = File::create(pub_key_path)?;
    pub_key_file.write_all(&pub_key_pem)?;

    let mut priv_key_file = File::create(priv_key_path)?;
    priv_key_file.write_all(&priv_key_pem)?;

    Ok(())
}

fn encrypt(input_file: &str, output_file: &str, pub_key_file: &str) -> Result<(), Box<dyn Error>> {
    let mut pub_key_file = File::open(pub_key_file)?;
    let mut pub_key_data = Vec::new();
    pub_key_file.read_to_end(&mut pub_key_data)?;

    let pub_key = Rsa::public_key_from_pem(&pub_key_data)?;

    let mut input_file = File::open(input_file)?;

    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext)?;

    let mut ciphertext = vec![0; pub_key.size() as usize];
    pub_key.public_encrypt(&plaintext, &mut ciphertext, Padding::PKCS1)?;

    let mut output_file = File::create(output_file)?;
    output_file.write_all(&ciphertext)?;

    Ok(())
}

fn decrypt(input_file: &str, output_file: &str, priv_key_file: &str) -> Result<(), Box<dyn Error>> {
    let mut priv_key_file = File::open(priv_key_file)?;
    let mut priv_key_data = Vec::new();
    priv_key_file.read_to_end(&mut priv_key_data)?;

    let priv_key = Rsa::private_key_from_pem(&priv_key_data)?;

    let mut input_file = File::open(input_file)?;

    let mut ciphertext = Vec::new();
    input_file.read_to_end(&mut ciphertext)?;

    let mut plaintext = vec![0; priv_key.size() as usize];
    let len = priv_key.private_decrypt(&ciphertext, &mut plaintext, Padding::PKCS1)?;

    let mut output_file = File::create(output_file)?;
    output_file.write_all(&plaintext[..len])?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::App::new("RSA Encryption CLI")
        .subcommand(clap::SubCommand::with_name("generate")
            .arg(clap::Arg::with_name("pub_key_file").required(true).index(1))
            .arg(clap::Arg::with_name("priv_key_file").required(true).index(2))
            .arg(clap::Arg::with_name("key_size").short("s").long("size").default_value("2048"))
            .about("Generate RSA key pair"))
        .subcommand(clap::SubCommand::with_name("encrypt")
            .arg(clap::Arg::with_name("input_file").required(true).index(1))
            .arg(clap::Arg::with_name("output_file").required(true).index(2))
            .arg(clap::Arg::with_name("pub_key_file").required(true).index(3))
            .about("Encrypt file"))
        .subcommand(clap::SubCommand::with_name("decrypt")
            .arg(clap::Arg::with_name("input_file").required(true).index(1))
            .arg(clap::Arg::with_name("output_file").required(true).index(2))
            .arg(clap::Arg::with_name("priv_key_file").required(true).index(3))
            .about("Decrypt file"))
        .get_matches();

    match matches.subcommand() {
        ("generate", Some(generate_matches)) => {
            let pub_key_file = generate_matches.value_of("pub_key_file").unwrap();
            let priv_key_file = generate_matches.value_of("priv_key_file").unwrap();
            let key_size = generate_matches.value_of("key_size").unwrap().parse::<u32>()?;
            generate_key_pair(pub_key_file, priv_key_file, key_size)?;
        }
        ("encrypt", Some(encrypt_matches)) => {
            let input_file = encrypt_matches.value_of("input_file").unwrap();
            let output_file = encrypt_matches.value_of("output_file").unwrap();
            let pub_key_file = encrypt_matches.value_of("pub_key_file").unwrap();
            encrypt(input_file, output_file, pub_key_file)?;
        }
        ("decrypt", Some(decrypt_matches)) => {
            let input_file = decrypt_matches.value_of("input_file").unwrap();
            let output_file = decrypt_matches.value_of("output_file").unwrap();
            let priv_key_file = decrypt_matches.value_of("priv_key_file").unwrap();
            decrypt(input_file, output_file, priv_key_file)?;
        }
        _ => eprintln!("Invalid command."),
    }

    Ok(())
}
