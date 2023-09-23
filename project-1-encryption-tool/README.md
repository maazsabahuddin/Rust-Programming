Objective
Develop a command-line interface (CLI) tool using Rust that uses RSA asymmetric encryption to encrypt and decrypt files. The tool should generate a public-private key pair, save them to files, and allow encrypting data with the public key and decrypting it with the private key.

Learning Outcomes
Using object-oriented programming, implement variables, basic types, functions, comments, and control flow.

Apply the fundamentals of object-oriented programming to create a useful cybersecurity tool.

Demonstrate understanding and practical application of asymmetric encryption in the context of secure data storage.

Instructions
Set up your Rust programming environment with the necessary libraries (crates) for working with RSA encryption.

Create a CLI tool with options to generate a key pair, encrypt a file, and decrypt a file.

Implement a function to generate an RSA public-private key pair and save them to separate files.

Implement a function to load the public key from a file and encrypt the contents of a specified file, saving the ciphertext to a new file.

Implement a function to load the private key from a file and decrypt the contents of a specified ciphertext file, saving the plaintext to a new file.

Test your tool with various file types (e.g., text, images, etc.) and verify the encryption and decryption processes.

Submission Requirements
Source code for your CLI tool in Rust.

A brief report (1-2 pages) explaining the functionalities of your tool, any challenges faced during development, and how you addressed them.

Output samples demonstrating successful file encryption and decryption (Screenshot of it working, and screenshot of the code in a PDF format).

Rubric
Functionality (50 points)
Key Pair Generation (10 points): Successfully generates and saves an RSA public-private key pair to separate files.

File Encryption (15 points): Encrypts a file using the public key, saving the ciphertext to a new file.

File Decryption (15 points): Decrypts a ciphertext file using the private key, recovering the original file.

CLI Usability (10 points): Provides a user-friendly command-line interface with clear options and instructions.

Code Quality (25 points)
Object-Oriented Principles (10 points): Effectively implements variables, basic types, functions, comments, and control flow using object-oriented programming.

Code Organization (5 points): Organizes code logically and modularly, making it easy to read and maintain.

Error Handling (10 points): Properly handles potential errors (e.g., invalid key files, incorrect file paths) and provides informative error messages.

Report and Documentation (25 points)
Explanation of Tool (10 points): Clearly explains the tool’s functionalities and how they were implemented.

Challenges and Solutions (10 points): Discusses any challenges faced during development and how they were addressed.

Output Samples (5 points): Provides output samples demonstrating successful file encryption and decryption.

 
A total score of 90-100 points is considered excellent, 80-89 points is considered good, 70-79 points is considered satisfactory, and below 70 points is considered unsatisfactory.