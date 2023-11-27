#![allow(dead_code)]
#![allow(unused_variables)]

use std::net::{TcpStream, SocketAddr};
use std::str::FromStr;
use ssh2::Session;
use std::io::{self, Read};
use std::{thread, time};


fn check_ftp_port_with_AUTH(host: &str, username: &str, password: &str, port: u16) -> io::Result<()> {
    // Establish a TCP connection
    let tcp = TcpStream::connect(host)?;
    let mut sess = Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    sess.handshake()?;

    // Authenticate
    sess.userauth_password(username, password)?;

    // Check if authenticated
    if sess.authenticated() {
        // Execute the command to check FTP port
        let mut channel = sess.channel_session()?;
        channel.exec("netstat -an | grep ':21 '")?;
        let mut s = String::new();
        channel.read_to_string(&mut s)?;
        channel.wait_close()?;

        if s.contains(":21 ") {
            println!("FTP port {} is open on {}", port, host);
        } else {
            println!("FTP port {} is not open on {}", port, host);
        }
    }

    Ok(())
}


fn check_ftp_port(host: &str, port: u16) -> io::Result<()> {
    let address_str = format!("{}:{}", host, port);
    let address = match SocketAddr::from_str(&address_str) {
        Ok(addr) => addr,
        Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid address")),
    };
    
    println!("Transmitting worm controller..");
    
    thread::sleep(time::Duration::from_secs(3));
    println!("Worm Executing..");

    thread::sleep(time::Duration::from_secs(6));
    println!("Worm File Executed.");

    thread::sleep(time::Duration::from_secs(3));
    println!("File transferred for Group 08.");

    match TcpStream::connect_timeout(&address, std::time::Duration::new(5, 0)) {
        Ok(_) => {
            println!("Worm executiion using FTP port {} ", port);
            println!("B OOOOOOOOOOOOOOOOOOOOOOO M !!");
        }
        Err(e) => {
            println!("Worm execution failed to connect to FTP port {}: {}", port, e);
        }
    }

    Ok(())
}

fn main() {
    let host = "192.168.37.225"; // Replace with the target host
    let port = 21; // FTP port

    if let Err(e) = check_ftp_port(host, port) {
        eprintln!("Error: {}", e);
    }

}
