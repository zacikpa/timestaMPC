mod gg18_key_gen;
mod gg18_sign;
mod li17_key_gen;
mod li17_sign;
mod li17_refresh;
mod requests;
use std::net::{TcpListener, TcpStream};
use std::io::{Write, Read, BufReader};
use std::fs::File;
use std::fs;
use crate::requests::{process_request, response_bytes_to_b64, encrypt_response, decrypt_request,
                      Context, Request, Config, ResponseWithBytes, ResponseType, ABORT};
use std::env;

const BUFFER_SIZE_PER_PARTY: usize = 20_000;
const MAX_SOCKET_READ_SIZE: usize = 32_768;

fn read(socket: &mut TcpStream, buffer: &mut [u8]) -> usize {
    let size_result = socket.read(buffer);
    if size_result.is_err() {
        0 as usize;
    }
    size_result.unwrap()
}

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
                let mut request_buffer = vec![0; BUFFER_SIZE_PER_PARTY * config.num_parties as usize];
                let mut size = read(&mut socket, &mut request_buffer);
                let request: Request;

                'inner: loop {
                    // Try to parse the request as JSON
                    let request_result = serde_json::from_slice::<Request>(&request_buffer[..size]);
                    if !request_result.is_err() {
                        request = request_result.unwrap();
                        break 'inner;
                    }

                    // Probably encrypted, try to load the symmetric key and decrypt
                    let symm = fs::read(&format!("{}/symm{}_manager", config.symm_keys_folder, config.index));
                    println!("{:?}", size);
                    if !symm.is_err() && size % 16 == 0 && size >= 32 {
                        let decrypted = decrypt_request(&symm.unwrap(), &request_buffer[..size]);
                        if !decrypted.is_err() {
                            request = serde_json::from_slice::<Request>(&(decrypted.unwrap())).unwrap();
                            break 'inner;
                        }
                    }

                    // Abort if we finished reading and could not parse
                    if size % MAX_SOCKET_READ_SIZE != 0 {
                        eprintln!("Error reading from socket.");
                        (context, response) = ABORT;
                        let json_response = serde_json::to_vec(&response).unwrap();
                        let write_result = socket.write_all(&json_response);
                        if write_result.is_err() {
                            eprintln!("Error: {}", write_result.unwrap_err().to_string());
                            break 'outer;
                        }
                        continue 'outer;
                    }

                    // Try to read again
                    let new_size = read(&mut socket, &mut request_buffer[size..]);
                    if new_size == 0 {
                        eprintln!("Error reading from socket.");
                        (context, response) = ABORT;
                        let json_response = serde_json::to_vec(&response).unwrap();
                        let write_result = socket.write_all(&json_response);
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
                let response_b64 = response_bytes_to_b64(&response);
                println!("Sending response: {:?}", &response_b64);

                // Write back the response
                let json_response = match serde_json::to_vec(&response_b64) {
                    Ok(response) => response,
                    Err(e) => {
                        eprintln!("Error: {}", e.to_string());
                        continue;
                    }
                };

                let to_send: Vec<u8>;
                let symm = fs::read(&format!("{}/symm{}_manager", config.symm_keys_folder, config.index));
                if symm.is_err() || response.response_type == ResponseType::SymmetricKeySendPlain {
                    to_send = json_response;
                } else {
                    to_send = encrypt_response(&symm.unwrap(), json_response);
                }

                let write_result = socket.write_all(&to_send);
                if write_result.is_err() {
                    eprintln!("Error: {}", write_result.unwrap_err().to_string());
                    break;
                }
        }
    }
}
