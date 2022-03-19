mod key_gen;
mod sign;
mod requests;
use std::net::TcpListener;
use std::io::{Write, Read};
use crate::requests::{process_request, Context};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

    let mut context = Context::Empty;

    loop {
        let (mut socket, _) = listener.accept().unwrap();

            let mut request_buf = Vec::new();
            loop {
                // Read an incoming request
                let _ = socket.read(&mut request_buf);

                // Process the request and generate a response
                let response = process_request(&context, request_buf.to_vec());
                context = response.0;
                // Write back the response
                let e = socket.write_all(&serde_json::to_vec(&response.1).unwrap());
                if e.is_err() {
                    eprintln!("failed to write to socket; err = {:?}", e);
                    break;
                }

        }
    }
}
