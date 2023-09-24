extern crate clap;

use openssl::rsa::{Rsa, Padding};
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::{Read, Write};

struct Config {
    pub_key_file: String,
    priv_key_file: String,
    key_size: u32,
    input_file: String,
    output_file: String,
}

impl Config {
    fn new() -> Self {
        Self {
            pub_key_file: String::from("public_key.pem"),
            priv_key_file: String::from("private_key.pem"),
            key_size: 2048,
            input_file: String::new(),
            output_file: String::new(),
        }
    }
}

fn generate_key_pair(config: &Config) -> Result<(), Box<dyn Error>> {
    let rsa = Rsa::generate(config.key_size)?;

    let pub_key_pem = rsa.public_key_to_pem()?;
    let priv_key_pem = rsa.private_key_to_pem()?;

    let mut pub_key_file = File::create(&config.pub_key_file)?;
    pub_key_file.write_all(&pub_key_pem)?;

    let mut priv_key_file = File::create(&config.priv_key_file)?;
    priv_key_file.write_all(&priv_key_pem)?;

    println!("Key pair generated successfully.");
    Ok(())
}

fn encrypt(config: &Config) -> Result<(), Box<dyn Error>> {
    let mut pub_key_file = File::open(&config.pub_key_file)?;
    let mut pub_key_data = Vec::new();
    pub_key_file.read_to_end(&mut pub_key_data)?;

    let pub_key = Rsa::public_key_from_pem(&pub_key_data)?;

    let mut input_file = File::open(&config.input_file)?;

    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext)?;

    let mut ciphertext = vec![0; pub_key.size() as usize];
    pub_key.public_encrypt(&plaintext, &mut ciphertext, Padding::PKCS1)?;

    let mut output_file = File::create(&config.output_file)?;
    output_file.write_all(&ciphertext)?;

    println!("Encryption complete.");
    Ok(())
}

fn decrypt(config: &Config) -> Result<(), Box<dyn Error>> {
    let mut priv_key_file = File::open(&config.priv_key_file)?;
    let mut priv_key_data = Vec::new();
    priv_key_file.read_to_end(&mut priv_key_data)?;

    let priv_key = Rsa::private_key_from_pem(&priv_key_data)?;

    let mut input_file = File::open(&config.input_file)?;

    let mut ciphertext = Vec::new();
    input_file.read_to_end(&mut ciphertext)?;

    let mut plaintext = vec![0; priv_key.size() as usize];
    let len = priv_key.private_decrypt(&ciphertext, &mut plaintext, Padding::PKCS1)?;

    let mut output_file = File::create(&config.output_file)?;
    output_file.write_all(&plaintext[..len])?;

    println!("Decryption complete.");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut config = Config::new();

    loop {
        println!("Press 1 to generate public-private key pair");
        println!("Press 2 to encrypt data");
        println!("Press 3 to decrypt data");
        println!("Press 4 to QUIT");

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => {
                generate_key_pair(&config)?;
            }
            "2" => {
                println!("Enter the input file path:");
                let mut input_path = String::new();
                io::stdin().read_line(&mut input_path)?;

                println!("Enter the output file path for encryption:");
                let mut output_path = String::new();
                io::stdin().read_line(&mut output_path)?;

                config.input_file = input_path.trim().to_string();
                config.output_file = output_path.trim().to_string();

                encrypt(&config)?;
            }
            "3" => {
                println!("Enter the input file path for decryption:");
                let mut input_path = String::new();
                io::stdin().read_line(&mut input_path)?;

                println!("Enter the output file path for decrypted data:");
                let mut output_path = String::new();
                io::stdin().read_line(&mut output_path)?;

                config.input_file = input_path.trim().to_string();
                config.output_file = output_path.trim().to_string();

                decrypt(&config)?;
            }
            "4" => {
                println!("Exiting the program.");
                break;
            }
            _ => {
                println!("Invalid option. Please enter a valid option (1, 2, 3, or 4).");
            }
        }
    }

    Ok(())
}
