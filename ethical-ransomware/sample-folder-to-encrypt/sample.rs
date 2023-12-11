// Import external modules 
use openssl::rsa::{Rsa, Padding}; // openssl encryption and decryption crate usability
use std::error::Error; // Handling erros
use std::fs::File; // Used to play with file handling
use std::io; // This library is input output handling
use std::io::{Read, Write}; // This module used for file read and write

// Struct will hold the configuration parameters.
struct Config {
    pub_key_file: String,
    priv_key_file: String,
    key_size: u32,
    input_file: String,
    output_file: String,
}

// Implementation of stuct parameters that will be used through the project.
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

    // This will generate an RSA key value pair
    let rsa = Rsa::generate(config.key_size)?;

    // The below code will convert the keys into pem format so that encryption decryption takes place
    let pub_key_pem = rsa.public_key_to_pem()?;
    let priv_key_pem = rsa.private_key_to_pem()?;

    // Create the file and store the pub pvt key into them..
    let mut pub_key_file = File::create(&config.pub_key_file)?;
    pub_key_file.write_all(&pub_key_pem)?;

    let mut priv_key_file = File::create(&config.priv_key_file)?;
    priv_key_file.write_all(&priv_key_pem)?;

    println!("\n\tKey pair generated successfully.");
    Ok(())
}

fn get_valid_file_path(prompt: &str, check_existence: bool) -> String {
    // This function will check the existence of the file and prompt the user to enter a valid file path.
    // Will only check the existence if the check_existence flag is set to true.
    loop {
        let mut path = String::new();
        println!("\n\t{}", prompt);
        io::stdin().read_line(&mut path).expect("Failed to read input");
        let path = path.trim();
        
        if !path.is_empty() {
            if !check_existence || std::fs::metadata(&path).is_ok() {
                return path.to_string();
            } else {
                println!("\t====== File not found. Please enter a valid file path. =====");
            }
        } else {
            println!("\n\tInvalid path. Please enter a valid path.");
        }
    }
}

fn encrypt(config: &Config) -> Result<(), Box<dyn Error>> {

    // Get input and output file paths from the user.
    let input_file = get_valid_file_path("\n\tPlease input the path of the file that needs to be encrypted:", true);
    let output_file = get_valid_file_path("\n\tEnter the personalized file name for your encrypted data:", false);

    // The below lines will open a file with the specific path provided by the user
    let mut pub_key_file = File::open(&config.pub_key_file)?;
    let mut pub_key_data = Vec::new();
    // Read the file after opening it.
    pub_key_file.read_to_end(&mut pub_key_data)?;

    // Parse the public key
    let pub_key = Rsa::public_key_from_pem(&pub_key_data)?;

    // Read the data inside the file    
    let mut input_file = File::open(&input_file)?;

    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext)?;

    // Preparte the data and encrypt it
    let mut ciphertext = vec![0; pub_key.size() as usize];
    pub_key.public_encrypt(&plaintext, &mut ciphertext, Padding::PKCS1)?;

    // Create or open a file `encrypted.bin` to store the encrypted text and write the encrypted text to it.
    let mut output_file = File::create(&output_file)?;
    output_file.write_all(&ciphertext)?;

    println!("\n\tEncryption complete.");
    Ok(())
}

fn decrypt(config: &Config) -> Result<(), Box<dyn Error>> {

    // Get input and output file paths from the user.
    let input_file = get_valid_file_path("\n\tPlease input the path for encrypted file:", true);
    let output_file = get_valid_file_path("\n\tPlease input the output file path name to see the decrypted data:", false);

    // Read the private key from a file.
    let mut priv_key_file = File::open(&config.priv_key_file)?;
    let mut priv_key_data = Vec::new();
    priv_key_file.read_to_end(&mut priv_key_data)?;

    // Parse the private key.
    let priv_key = Rsa::private_key_from_pem(&priv_key_data)?;

    // Read the encrypted text data from an input file.
    let mut input_file = File::open(&input_file)?;

    let mut ciphertext = Vec::new();
    input_file.read_to_end(&mut ciphertext)?;

    // Prepare a buffer for the encrypted text and decrypt the data.
    let mut plaintext = vec![0; priv_key.size() as usize];
    let len = priv_key.private_decrypt(&ciphertext, &mut plaintext, Padding::PKCS1)?;

    // Create or open a file `decrypted.txt` to store the plaintext and write the plaintext to it.
    let mut output_file = File::create(&output_file)?;
    output_file.write_all(&plaintext[..len])?;

    println!("\n\tDecryption complete.");
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let mut config = Config::new();

    // loop for user choices.
    // The loop will execute until the user press the QUIT option.
    loop {
        println!("\n\n\tChoose an option:");
        println!("\n\t1. Press `G` to generate key pairs");
        println!("\t2. Press `E` to encrypt");
        println!("\t3. Press `D` to decrypt");
        println!("\t4. Press `Q` to quit");

        // Read the user's choice.
        let mut input = String::new();
        println!("\n\tEnter your choice: ");
        io::stdin().read_line(&mut input)?;

        // Switch case in RUST - processing the user's choice.
        match input.trim() {
            "1" | "g" | "G" => {
                generate_key_pair(&config)?;
            }
            "2" | "e" | "E" => {
                config.input_file.clear(); // Clear previous input file path.
                config.output_file.clear(); // Clear previous output file path.
                encrypt(&config)?;
            }
            "3" | "d" | "D" => {
                config.input_file.clear(); // Clear previous input file path.
                config.output_file.clear(); // Clear previous output file path.
                decrypt(&config)?;
            }
            "4" | "q" | "Q" => {
                println!("\n\tExiting the program.");
                break;
            }
            _ => {
                println!("\n\tInvalid option. Please enter a valid option (`G`, `E`, `D`, `Q`).");
            }
        }
    }

    Ok(())
}
