use openssl::rsa::{Rsa};
use openssl::pkey::PKey;
use openssl::symm::{encrypt, decrypt, Cipher};
use openssl::rand::rand_bytes;
use openssl::sha::Sha256;
use std::collections::HashMap;
use std::io;
use std::fs::File;
use std::io::{Read, Write};
use openssl::rsa::Padding;
use std::net::{TcpListener, TcpStream};
use std::thread;

struct User {
    username: String,
    password_hash: Vec<u8>,
    salt: Vec<u8>,
    rsa_key: PKey<openssl::pkey::Private>,
}

struct EncryptedMessage {
    sender: String,
    recipient: String,
    content: Vec<u8>,
}

impl EncryptedMessage {
    fn encrypt_with_aes(message: &str, key: &[u8], iv: &[u8]) -> Vec<u8> {
        let cipher = Cipher::aes_256_gcm(); // You can use other AES modes if needed
        let encrypted_message = encrypt(
            cipher,
            key,        // AES key
            Some(iv),   // IV
            message.as_bytes(),
        )
        .expect("AES encryption failed");
        encrypted_message
    }

    fn decrypt_with_aes(encrypted_message: &[u8], key: &[u8], iv: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let cipher = Cipher::aes_256_gcm(); // You should use the same AES mode used for encryption
        let decrypted_bytes = decrypt(
            cipher,
            key,
            Some(iv),
            encrypted_message,
        )?;
        
        String::from_utf8(decrypted_bytes)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    // Add a function to save an encrypted message to a file
    fn save_to_file(&self, filename: &str) -> std::io::Result<()> {
        let mut file = File::create(filename)?;
        file.write_all(&self.content)?;
        Ok(())
    }

    // Add a function to load an encrypted message from a file
    fn load_from_file(filename: &str) -> std::io::Result<EncryptedMessage> {
        let mut file = File::open(filename)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        Ok(EncryptedMessage {
            sender: String::new(),
            recipient: String::new(),
            content,
        })
    }

}

impl User {
    fn new(username: String, password: String) -> User {
        let salt = User::generate_salt();
        let password_hash = User::hash_password(&password, &salt);

        // Generate RSA key pair for the user
        let rsa = Rsa::generate(2048).expect("RSA key generation failed");
        let rsa_pkey = PKey::from_rsa(rsa).expect("Failed to create RSA PKey");

        User {
            username,
            password_hash,
            salt,
            rsa_key: rsa_pkey,
        }
    }

    fn generate_salt() -> Vec<u8> {
        let mut salt = vec![0; 16];
        rand_bytes(&mut salt).expect("Failed to generate salt");
        salt
    }

    fn hash_password(password: &str, salt: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finish();
        result.to_vec()
    }

    fn verify_password(&self, password: &str) -> bool {
        let hashed_password = User::hash_password(password, &self.salt);
        self.password_hash == hashed_password
    }

}

struct UserManager {
    users: HashMap<String, User>,
}

impl UserManager {
    fn new() -> UserManager {
        UserManager {
            users: HashMap::new(),
        }
    }

    fn register_user(&mut self, username: String, password: String) {
        if self.users.contains_key(&username) {
            println!("Username already exists. Please choose a different username.");
        } else {
            let user = User::new(username.clone(), password);
            self.users.insert(username, user);
            println!("User Registration successful");
        }
    }

    fn login(&self, username: &str, password: &str) -> bool {
        if let Some(user) = self.users.get(username) {
            return user.verify_password(password);
        }
        false
    }

    fn generate_aes_key() -> Vec<u8> {
        let mut aes_key = vec![0u8; 32]; // Create a byte vector of length 32
        rand_bytes(&mut aes_key).expect("Failed to generate AES key");
        aes_key
    }

    fn get_user_by_username(&self, username: &str) -> Option<&User> {
        // Search for a user by username in the `users` HashMap
        self.users.get(username)
    }

    // Function to send an encrypted message
    fn send_message(&self, sender: &User, recipient: &User, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        
        // Generate a random AES key and IV for message encryption
        let aes_key = UserManager::generate_aes_key();
        let mut iv = vec![0; 16]; // Create a byte vector of length 16
        rand_bytes(&mut iv).expect("Failed to generate IV");

       // Encrypt the AES key with the recipient's RSA public key
        let rsa_public_key = recipient.rsa_key.public_key_to_pem()?;
        let recipient_rsa = Rsa::public_key_from_pem(&rsa_public_key)?;

        // Create a mutable byte vector to store the result of public encryption
        let mut encrypted_aes_key = vec![0; recipient_rsa.size() as usize];
        let result = recipient_rsa.public_encrypt(&aes_key, &mut encrypted_aes_key, Padding::PKCS1);
        
        if result.is_err() {
            return Err(Box::new(result.err().unwrap())); // Handle the error appropriately
        }

        // Encrypt the message with AES using the generated key and IV
        let encrypted_message = EncryptedMessage {
            sender: sender.username.clone(),
            recipient: recipient.username.clone(),
            content: EncryptedMessage::encrypt_with_aes(message, &aes_key, &iv),
        };

        // Save the encrypted message to a file
        let message_filename = format!("message_{}_to_{}.bin", sender.username, recipient.username);
        encrypted_message.save_to_file(&message_filename)?;
        
        File::create("encrypted_aes_key.bin")?.write_all(&encrypted_aes_key)?;

        Ok(())

    }

    fn receive_message(&self, recipient_username: &str, sender_username: &str) -> Result<(), Box<dyn std::error::Error>> {
        let filename = format!("message_{}_to_{}.bin", sender_username, recipient_username);
        println!("\n\t\tHi, My name is Maaz Sabah Uddin, and I have done my mid-term assignment. Thanks.");
        if let Ok(message) = EncryptedMessage::load_from_file(&filename) {
            if let Some(recipient) = self.users.get(recipient_username) {
                if let Some(sender) = self.users.get(sender_username) {
                    // Decrypt the AES key with the recipient's RSA private key
                    let rsa_private_key = recipient.rsa_key.private_key_to_pem_pkcs8()?;
                    let recipient_rsa = Rsa::private_key_from_pem(&rsa_private_key)?;
    
                    let mut aes_key_decrypted = vec![0; recipient_rsa.size() as usize];
                    recipient_rsa.private_decrypt(&message.content, &mut aes_key_decrypted, Padding::PKCS1)?;
    
                    // Decrypt the message with AES
                    let decrypted_message = EncryptedMessage::decrypt_with_aes(&message.content, &aes_key_decrypted, &[0; 12])?;
    
                    println!("\n\t\tReceived message from {}: {}", sender_username, decrypted_message);
                    Ok(())
                } else {
                    Err("Sender not found".into())
                }
            } else {
                Err("Recipient not found".into())
            }
        } else {
            Err("Message not found".into())
        }
    }

}

fn main() {
    let mut user_manager = UserManager::new();

    // Create a listener for the sender (server)
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to address");

    // Spawn a thread to listen for incoming connections from the receiver (client)
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buffer = [0; 1024];
                    stream.read(&mut buffer).expect("Failed to read data from client");
                    let message = String::from_utf8_lossy(&buffer).to_string();
                    println!("Received message from client: {}", message);
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }
    });
    
    loop {
        println!("\n\n\tChoose an option:");
        println!("\n\t1. Press `R` to Register");
        println!("\t2. Press `L` to Login");
        println!("\t3. Press `SM` to Send Message");
        println!("\t4. Press `RM` to Receive Message");
        println!("\t5. Press `Q` to Quit");


        println!("\n\tEnter your choice: ");
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("\tFailed to read input");

        match choice.trim() {
            "1" | "R" | "r" => {
                println!("\tEnter a username:");
                let mut username = String::new();
                io::stdin().read_line(&mut username).expect("\tFailed to read input");
                let username = username.trim().to_string();

                println!("\tEnter a password:");
                let mut password = String::new();
                io::stdin().read_line(&mut password).expect("\tFailed to read input");
                let password = password.trim().to_string();

                user_manager.register_user(username, password);
            }
            "2" | "L" | "l" => {
                println!("\tEnter your username:");
                let mut username = String::new();
                io::stdin().read_line(&mut username).expect("\tFailed to read input");
                let username = username.trim();

                println!("\tEnter your password:");
                let mut password = String::new();
                io::stdin().read_line(&mut password).expect("\tFailed to read input");
                let password = password.trim();

                if user_manager.login(username, password) {
                    println!("\tLogin successful!");
                } else {
                    println!("\tLogin failed. Please check your username and password.");
                }
            }
            "3" | "SM" | "sm" => {
                println!("\n\t\tEnter sender's username:");
                let mut sender_username = String::new();
                io::stdin().read_line(&mut sender_username).expect("Failed to read input");
                let sender_username = sender_username.trim();
                
                println!("\n\t\tEnter recipient's username:");
                let mut recipient_username = String::new();
                io::stdin().read_line(&mut recipient_username).expect("Failed to read input");
                let recipient_username = recipient_username.trim();

                println!("\n\t\tEnter the message:");
                let mut message = String::new();
                io::stdin().read_line(&mut message).expect("Failed to read input");
                let message = message.trim();

                // Find the sender and recipient users using the `get_user_by_username` function
                let sender_user = user_manager.get_user_by_username(sender_username).expect("Sender not found");
                let recipient_user = user_manager.get_user_by_username(recipient_username).expect("Recipient not found");

                // Now, call the `send_message` method using the sender user and recipient user
                user_manager.send_message(sender_user, &recipient_user, message).expect("Failed to send message");
                
                // Send the message to the client using a TCP socket
                // let mut client_socket = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to the client");
                // client_socket.write(message.as_bytes()).expect("Failed to send message to client");
                println!("Message sent to client: {}", message);
            }
            "4" | "RM" | "rm" => {
                println!("\n\t\tEnter recipient's username:");
                let mut recipient_username = String::new();
                io::stdin().read_line(&mut recipient_username).expect("Failed to read input");
                let recipient_username = recipient_username.trim();
                
                println!("\n\t\tEnter sender's username:");
                let mut sender_username = String::new();
                io::stdin().read_line(&mut sender_username).expect("Failed to read input");
                let sender_username = sender_username.trim();
                
                user_manager.receive_message(recipient_username, sender_username);
            }
            "5" | "Q" | "q" => {
                println!("\tExiting the program.");
                break;
            }
            _ => {
                println!("\tInvalid option. Please choose a valid option.");
            }
        }
    }
}
