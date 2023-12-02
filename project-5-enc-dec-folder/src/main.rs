// Import necessary crates and modules
extern crate clap; // Command Line Argument Parser
extern crate age; // Encryption and decryption crate
extern crate walkdir; // Directory traversal

use age::{Encryptor, Decryptor}; // Import Encryptor and Decryptor from the 'age' crate
use clap::{App, Arg, SubCommand}; // Import App, Arg, and SubCommand for CLI interaction
use secrecy::Secret; // Import Secret for securely handling sensitive information
use std::fs::File; // Import File for file operations
use walkdir::WalkDir; // Import WalkDir for walking through directory contents
use std::io::{self, Read, Write}; // Import standard I/O traits for reading and writing

// Main function - entry point of the program
fn main() {
    // Setup the command-line interface
    let matches = App::new("Folder Encryption CLI")
        .version("1.3") // Set version
        .author("Maaz Sabah Uddin") // Set author
        .about("Encrypts and Decrypts folders") // Program description
        // Define 'encrypt' subcommand with its arguments
        .subcommand(SubCommand::with_name("encrypt")
            .about("Encrypts a folder")
            .arg(Arg::with_name("FOLDER")
                .help("Sets the input folder to use")
                .required(true)
                .index(1))
            .arg(Arg::with_name("PASSPHRASE")
                .help("Sets the passphrase for encryption")
                .required(true)
                .index(2)))
        // Define 'decrypt' subcommand with its arguments
        .subcommand(SubCommand::with_name("decrypt")
            .about("Decrypts a folder")
            .arg(Arg::with_name("FOLDER")
                .help("Sets the input folder to use")
                .required(true)
                .index(1))
            .arg(Arg::with_name("PASSPHRASE")
                .help("Sets the passphrase for decryption")
                .required(true)
                .index(2)))
        .get_matches();

    // Handle 'encrypt' subcommand
    if let Some(matches) = matches.subcommand_matches("encrypt") {
        if let (Some(folder), Some(passphrase)) = (matches.value_of("FOLDER"), matches.value_of("PASSPHRASE")) {
            match encrypt_folder(folder, passphrase) {
                Ok(_) => println!("Folder encrypted successfully!"),
                Err(e) => eprintln!("Error encrypting folder: {}", e),
            }
        }
    // Handle 'decrypt' subcommand
    } else if let Some(matches) = matches.subcommand_matches("decrypt") {
        if let (Some(folder), Some(passphrase)) = (matches.value_of("FOLDER"), matches.value_of("PASSPHRASE")) {
            match decrypt_folder(folder, passphrase) {
                Ok(_) => println!("Folder decrypted successfully!"),
                Err(e) => eprintln!("Error decrypting folder: {}", e),
            }
        }
    }
}

// Function to encrypt a folder
fn encrypt_folder(path: &str, passphrase: &str) -> io::Result<()> {
    // Iterate over each file in the directory
    for entry in WalkDir::new(path) {
        let entry = entry?;
        let path = entry.path();

        // Skip directories, only encrypt files
        if path.is_dir() {
            continue;
        }

        // Read the file's contents
        let mut file = File::open(path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        // Encrypt the contents using the provided passphrase
        let encryptor = Encryptor::with_user_passphrase(Secret::new(passphrase.to_string()));
        let mut encrypted_writer = vec![];
        {
            let mut writer = match encryptor.wrap_output(&mut encrypted_writer) {
                Ok(w) => w,
                Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
            };
            writer.write_all(&contents)?;
            writer.finish()?;
        }

        // Replace the file with its encrypted version
        let mut file = File::create(path)?;
        file.write_all(&encrypted_writer)?;
    }

    Ok(())
}

// Function to decrypt a folder
fn decrypt_folder(path: &str, passphrase: &str) -> io::Result<()> {
    // Iterate over each file in the directory
    for entry in WalkDir::new(path) {
        let entry = entry?;
        let path = entry.path();

        // Skip directories, only decrypt files
        if path.is_dir() {
            continue;
        }

        // Read the encrypted file's contents
        let mut file = File::open(path)?;
        let mut encrypted_contents = Vec::new();
        file.read_to_end(&mut encrypted_contents)?;

        // Attempt to create a decryptor
        let decryptor_result = Decryptor::new(&encrypted_contents[..]);

        let mut decrypted_contents = Vec::new();

        // Handle the result of decryptor creation
        match decryptor_result {
            Ok(decryptor) => {
                // Handle different types of decryptors, focusing on passphrase decryptors
                match decryptor {
                    Decryptor::Passphrase(d) => {
                        // Attempt to decrypt with the provided passphrase
                        let reader_result = d.decrypt(&Secret::new(passphrase.to_string()), None);
                        match reader_result {
                            Ok(mut reader) => {
                                // Read and store the decrypted contents
                                reader.read_to_end(&mut decrypted_contents)?;
                            },
                            // Handle decryption errors
                            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e))),
                        }
                    },
                    // Handle unsupported decryptor types
                    _ => return Err(io::Error::new(io::ErrorKind::Other, "Unsupported decryptor type")),
                }
            },
            // Handle errors in creating the decryptor
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Failed to create decryptor: {}", e))),
        };

        // Replace the encrypted file with its decrypted version
        let mut file = File::create(path)?;
        file.write_all(&decrypted_contents)?;
    }

    Ok(())
}
