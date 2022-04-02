mod key_gen;
mod sign;
mod requests;
use std::net::TcpListener;
use std::io::{Write, Read, BufReader};
use std::fs::File;
use crate::requests::{process_request, response_bytes_to_hex, Context, Request, Config, ResponseType, ResponseWithBytes};
use std::env;

const BUFFER_SIZE: usize = 100000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check and parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Expecting a single command line argument!");
    }
    let config_filename = &args[1];

    // Read the configuration file
    let config_file = File::open(&config_filename).unwrap();
    let config_reader = BufReader::new(config_file);
    let config: Config = serde_json::from_reader(config_reader).unwrap();
    println!("{:?}", config);

    // Create an empty signer context
    let mut context = Context::Empty;
    let mut response: ResponseWithBytes;

    // Bind to the socket
    let listener = TcpListener::bind(&config.address).unwrap();

    // Start listening to connections
    loop {
        let (mut socket, _) = listener.accept().unwrap();
            loop {
                // Read an incoming request
                let mut request_buf = vec![0; BUFFER_SIZE];
                let size = socket.read(&mut request_buf).unwrap();
                let request = serde_json::from_slice::<Request>(&request_buf[..size]);
                println!("{:?}", request);
                (context, response) = match request {
                    Ok(req) => process_request(&context, &config, req),
                    Err(_e) => (Context::Empty,
                                ResponseWithBytes{response_type: ResponseType::Abort, data: Vec::new()})
                };
                println!("{:?}", context);
                println!("{:?}", response);
                // Write back the response
                let e = socket.write_all(&serde_json::to_vec(&response_bytes_to_hex(response)).unwrap());
                if e.is_err() {
                    eprintln!("failed to write to socket; err = {:?}", e);
                    break;
                }
        }
    }
}
