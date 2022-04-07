mod gg18_key_gen;
mod gg18_sign;
mod li17_key_gen;
mod li17_sign;
mod li17_refresh;
mod requests;
use std::net::TcpListener;
use std::io::{Write, Read, BufReader};
use std::fs::File;
use crate::requests::{process_request, response_bytes_to_b64, Context, Request, Config, ResponseType, ResponseWithBytes};
use std::env;
use std::str;

const BUFFER_SIZE_PER_PARTY: usize = 10_000;

fn main() {
    // Check and parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Error: Expecting a single command line argument");
        return;
    }
    let config_filename = &args[1];

    // Read the configuration file
    let config_file = match File::open(&config_filename) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Error: {}", e.to_string());
            return
        }
    };

    // Parse the configuration file
    let config_reader = BufReader::new(config_file);
    let config: Config = match serde_json::from_reader(config_reader) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e.to_string());
            return
        }
    };

    println!("{:?}", config);
    // Create an empty signer context
    let mut context = Context::Empty;
    let mut response: ResponseWithBytes;

    // Bind to the socket
    let listener = match TcpListener::bind((&config.host[..], config.port)) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Error: {}", e.to_string());
            return
        }
    };

    // Start listening to connections
    loop {
        let (mut socket, _) = match listener.accept() {
            Ok(socket) => socket,
            Err(e) => {
                eprintln!("Error: {}", e.to_string());
                continue;
            }
        };
            'outer: loop {
                // Read an incoming request
                let mut size = 0;
                let mut request_buffer = vec![0; BUFFER_SIZE_PER_PARTY * config.num_parties as usize];

                while serde_json::from_slice::<Request>(&request_buffer[..size]).is_err() {
                    let new_size = match socket.read(&mut request_buffer[size..]) {
                        Ok(size) => size,
                        Err(e) => {
                            eprintln!("Error: {}", e.to_string());
                            break 'outer
                        }
                    };
                    if new_size == 0 {
                        eprintln!("Error: Reached EOF");
                        break 'outer
                    }
                    size += new_size;
                }

                println!("Read size to socket {:?}", size);
                println!("Data: {:?}", str::from_utf8(&request_buffer[..size]).unwrap());

                // Process the request and create a response
                let request = serde_json::from_slice::<Request>(&request_buffer[..size]);
                println!("Got request: {:?}", request);
                (context, response) = match request {
                    Ok(req) => process_request(&context, &config, req),
                    Err(e) => {
                        eprintln!("Error: {}", e.to_string());
                        (
                            Context::Empty,
                            ResponseWithBytes {
                                response_type: ResponseType::Abort,
                                data: Vec::new()
                            }
                        )
                    }
                };
                let response_b64 = response_bytes_to_b64(response);
                println!("Sending response: {:?}", &response_b64);

                // Write back the response
                let json_response = match serde_json::to_vec(&response_b64) {
                    Ok(response) => response,
                    Err(e) => {
                        eprintln!("Error: {}", e.to_string());
                        continue;
                    }
                };
                let write_result = socket.write_all(&json_response);
                if write_result.is_err() {
                    eprintln!("Error: {}", write_result.unwrap_err().to_string());
                    break;
                }
        }
    }
}
