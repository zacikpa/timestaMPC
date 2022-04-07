mod gg18_key_gen;
mod gg18_sign;
mod li17_key_gen;
mod li17_sign;
mod li17_refresh;
mod requests;
use std::net::TcpListener;
use std::io::{Write, Read, BufReader};
use std::fs::File;
use crate::requests::{process_request, response_bytes_to_b64, encrypt_response, Context, Request,
                      Config, ResponseType, ResponseWithBytes, Response};
use std::env;

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
                let request: Request;

                'inner: loop {
                    let request_result = serde_json::from_slice::<Request>(&request_buffer[..size]);
                    if !request_result.is_err() {
                        request = request_result.unwrap();
                        break 'inner;
                    }
                    let new_size_result = socket.read(&mut request_buffer[size..]);
                    let new_size: usize;
                    if !new_size_result.is_err() {
                        new_size = new_size_result.unwrap()
                    } else {
                        new_size = 0;
                    }
                    if new_size == 0 {
                        eprintln!("Error reading from socket.");
                        let response_abort = Response {
                            response_type: ResponseType::Abort,
                            data: Vec::new()
                        };
                        let json_abort = serde_json::to_vec(&response_abort).unwrap();
                        context = Context::Empty;
                        let write_result = socket.write_all(&json_abort);
                        if write_result.is_err() {
                            eprintln!("Error: {}", write_result.unwrap_err().to_string());
                            break 'outer;
                        }
                        continue 'outer;
                    }
                    size += new_size;
                }

                // Process the request and create a response
                println!("Got request: {:?}", request);
                (context, response) = process_request(&context, &config, request);
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
                let write_result = socket.write_all(&encrypt_response(json_response, &config));
                if write_result.is_err() {
                    eprintln!("Error: {}", write_result.unwrap_err().to_string());
                    break;
                }
        }
    }
}
