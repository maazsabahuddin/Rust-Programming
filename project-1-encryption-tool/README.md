## Maaz Sabah Uddin - maazsabahuddin@gmail.com

# Generate public and private key pairs
cargo run -- generate mypubkey.pem myprivkey.pem

# Read the plaintext file content and encrypt it using the public key and generate a ciphertext.bin file which is encrypted.
cargo run -- encrypt plaintext.txt ciphertext.bin mypubkey.pem

# Decrypt the ciphertext.bin file using the private key and save the decrypted text to decrypted.txt.
cargo run -- decrypt ciphertext.bin decrypted.txt myprivkey.pem

