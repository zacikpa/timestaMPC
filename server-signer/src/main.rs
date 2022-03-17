mod key_gen;
mod sign;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

enum MessageType {
    GenerateKey,
    RegenerateKey,
    InitSign,
    Sign,
    Abort,
}

fn process_request(response_buf: &mut [u8], request_buf: &[u8], request_len: usize) -> usize {
    let _json: Value = match serde_json::from_slice(&request_buf[..request_len]) {
        Ok(json) => json,
        Err(_e) => {
            let response = b"Error\n";
            response_buf[..response.len()].copy_from_slice(response);
            return response.len();
        }
    };
    let response = b"Ok\n";
    response_buf[..response.len()].copy_from_slice(response);
    return response.len();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;

    loop {
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut request_buf = [0; 1024];
            loop {
                // Read an incoming request
                let request_len = match socket.read(&mut request_buf).await {
                    Ok(request_len) if request_len == 0 => return,
                    Ok(request_len) => request_len,
                    Err(e) => {
                        eprintln!("failed to read from socket; err = {:?}", e);
                        return;
                    }
                };

                // Process the request and generate a response
                let mut response_buf = [0; 1024];
                let response_len = process_request(&mut response_buf, &request_buf, request_len);

                // Write back the response
                if let Err(e) = socket.write_all(&response_buf[0..response_len]).await {
                    eprintln!("failed to write to socket; err = {:?}", e);
                    return;
                }
            }
        });
    }
}
