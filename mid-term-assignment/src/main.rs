use openssl::sha::Sha256;
use openssl::rand::rand_bytes;
use std::collections::HashMap;
use std::io;

struct User {
    username: String,
    password_hash: Vec<u8>,
    salt: Vec<u8>,
}

impl User {
    fn new(username: String, password: String) -> User {
        let salt = User::generate_salt();
        let password_hash = User::hash_password(&password, &salt);
        User {
            username,
            password_hash,
            salt,
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
}

fn main() {
    let mut user_manager = UserManager::new();

    loop {
        println!("\n\n\tChoose an option:");
        println!("\n\t1. Press `R` to Register");
        println!("\t2. Press `L` to Login");
        println!("\t3. Press `Q` to Quit");

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
            "3" | "Q" | "q" => {
                println!("\tExiting the program.");
                break;
            }
            _ => {
                println!("\tInvalid option. Please choose a valid option.");
            }
        }
    }
}
