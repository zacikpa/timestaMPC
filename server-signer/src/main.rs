mod key_gen;
mod sign;
use serde::{Deserialize, Serialize};
use std::net::TcpListener;
use std::io::{Write, Read};
use crate::key_gen::{GG18KeyGenContext1, GG18KeyGenContext2, GG18KeyGenContext3, GG18KeyGenContext4,
    GG18KeyGenContext5};
use crate::sign::{GG18SignContext1, GG18SignContext2, GG18SignContext3, GG18SignContext4,
    GG18SignContext5, GG18SignContext6, GG18SignContext7, GG18SignContext8, GG18SignContext9};

#[derive(Clone, Debug, Serialize, Deserialize)]
enum RequestType {
    GenerateKey,
    RegenerateKey,
    InitSign,
    Sign,
    Abort,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    request_type: RequestType,
    data: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum ResponseType {
    GenerateKey,
    RegenerateKey,
    InitSign,
    Sign,
    Abort,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    response_type: ResponseType,
    data: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
enum Context {
    Empty,
    GenContext1(GG18KeyGenContext1),
    GenContext2(GG18KeyGenContext2),
    GenContext3(GG18KeyGenContext3),
    GenContext4(GG18KeyGenContext4),
    GenContext5(GG18KeyGenContext5),
    SignContext1(GG18SignContext1),
    SignContext2(GG18SignContext2),
    SignContext3(GG18SignContext3),
    SignContext4(GG18SignContext4),
    SignContext5(GG18SignContext5),
    SignContext6(GG18SignContext6),
    SignContext7(GG18SignContext7),
    SignContext8(GG18SignContext8),
    SignContext9(GG18SignContext9),
}

fn process_request(context: &Context, request_buf: Vec<u8>) -> (Context, Response) {
    let _request: Request = match serde_json::from_slice(&request_buf) {
        Ok(request) => request,
        Err(_e) => {
            return (Context::Empty, Response{
                            response_type: ResponseType::Abort,
                            data: Vec::new()});
        }
    };
    match context {
    _ => {let response = b"Ok\n";
            return (Context::Empty, Response{
                    response_type: ResponseType::Abort,
                    data: vec![response.to_vec()]});}
    }
}

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
