// Importing necessary modules from the `tokio` crate for asynchronous operations
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt};

// Importing modules for environment variable handling and process management
use std::env;
use std::process;

// Function to parse a given port range string into a vector of port numbers
fn parse_port_range(range: &str) -> Result<Vec<u16>, &'static str> {

    // Split the range string into two parts at the hyphen and collect into a vector
    let parts: Vec<&str> = range.split('-').collect();

    // Check if the range string is not in the format "start-end"
    if parts.len() != 2 {
        return Err("Range must be in the format <start>-<end>");
    }

    // Parse the start and end of the range into numbers, returning an error if invalid
    let start = parts[0].parse::<u16>().map_err(|_| "Invalid start port")?;
    let end = parts[1].parse::<u16>().map_err(|_| "Invalid end port")?;

    // Return the range of numbers as a vector
    Ok((start..=end).collect())
}

// Asynchronous main function, the entry point of the program
#[tokio::main]
async fn main() {
    
    // Collect command line arguments into a vector
    let args: Vec<String> = env::args().collect();

    // Check if the correct number of arguments is not provided
    if args.len() != 3 {
        // Print usage instructions and exit if arguments are incorrect
        eprintln!("Usage: port_scanner <IP> <PORT_RANGE>");
        process::exit(1);
    }

    // Extract the IP address and port range from the arguments
    let ip = &args[1];
    let ports: Vec<u16> = parse_port_range(&args[2]).expect("Invalid port range");

    // Print the IP and ports being scanned
    println!("Scanning IP: {}, Ports: {:?}", ip, ports);

    // Loop through each port and scan it
    for port in ports {
        scan_port(ip, port).await;
    }
}

// Asynchronous function to scan a single port
async fn scan_port(ip: &str, port: u16) {
    
    // Format the IP address and port into a string
    let address = format!("{}:{}", ip, port);

    // Attempt to connect to the port and handle the result
    match TcpStream::connect(address).await {

        // If the connection is successful, handle the open port
        Ok(stream) => {
    
            // Print that the port is open
            println!("Port {} is open", port);
            println!("Service on port {}: {}", port, "HTTP (Web Server)");

            // Attempt to identify the service running on the port
            if let Some(service) = identify_service(stream).await {
                println!("Service on port {}: {}", port, service);
            } else {
                println!("Service on port {}: Unknown", port);
            }
        }

        // If the connection fails, handle the closed port
        Err(_) => println!("Port {} is closed", port),
    }
}

// Asynchronous function to identify the service running on an open port
async fn identify_service(mut stream: TcpStream) -> Option<String> {

    // Buffer to read data into
    let mut buffer = [0; 1024];

    // Check if the stream is readable
    if stream.readable().await.is_ok() {

        // Read data from the stream
        match stream.read(&mut buffer).await {

            // Handle the case where no data is received
            Ok(0) => None,

            // Handle the case where data is received
            Ok(_) => {

                // Convert the received data to a string
                let response = String::from_utf8_lossy(&buffer);

                // Match the response against known service banners
                match response.trim() {

                    // Match known SSH banner
                    resp if resp.starts_with("SSH") => Some("SSH".to_string()),

                    // Match known SMTP banner
                    resp if resp.starts_with("220") => Some("SMTP (Email)".to_string()),

                    // Match known HTTP banner
                    resp if resp.contains("HTTP/1.") => Some("HTTP (Web Server)".to_string()),

                    // Match known FTP banner
                    resp if resp.contains("FTP") => Some("FTP (File Transfer)".to_string()),

                    // Default case for unknown services
                    _ => Some("Unknown".to_string()),
                }
            }
            // Handle error in reading from the stream
            Err(_) => None,
        }
    } else {
        // Return None if the stream is not readable
        None
    }
}
