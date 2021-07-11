mod net;
use net::ping;

use std::env::args;
use std::process::exit;
use std::time::Duration;

fn main() {
    let args: Vec<String> = args().collect();
    let mut addr = "";
    let mut verbose = false;
    let mut timeout_sec = 1;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-t" | "-timeout" | "--timeout" => {
                i += 1;
                if i >= args.len() {
                    println!("! You should specify a timeout");
                    exit(1);
                }
                let number = args[i].parse::<u64>().unwrap_or(0);
                if number == 0 {
                    println!("! You should specify a valid timeout");
                    exit(1);
                }
                timeout_sec = number;
            }
            "-v" | "-verbose" | "--verbose" => {
                verbose = true;
            }
            ip => addr = ip,
        }
        i += 1;
    }
    let timeout = Duration::from_secs(timeout_sec);

    match ping(verbose, addr, timeout) {
        Ok(size) => println!("{}", size),
        Err(err) => println!("{}", err),
    }
}
