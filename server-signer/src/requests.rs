use crate::key_gen::{
    gg18_key_gen_1, gg18_key_gen_2, gg18_key_gen_3, gg18_key_gen_4, gg18_key_gen_5, gg18_key_gen_6,
    GG18KeyGenContext1, GG18KeyGenContext2, GG18KeyGenContext3, GG18KeyGenContext4,
    GG18KeyGenContext5, GG18SignContext,
};
use crate::sign::{
    gg18_sign1, gg18_sign10, gg18_sign2, gg18_sign3, gg18_sign4, gg18_sign5, gg18_sign6,
    gg18_sign7, gg18_sign8, gg18_sign9, GG18SignContext1, GG18SignContext2, GG18SignContext3,
    GG18SignContext4, GG18SignContext5, GG18SignContext6, GG18SignContext7, GG18SignContext8,
    GG18SignContext9,
};
use chrono::{Duration, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use hex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub index: u16,
    pub context_path: String,
    pub host: String,
    pub port: u16,
    pub num_parties: u16,
    pub threshold: u16,
    pub acceptable_seconds: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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
    data: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ResponseType {
    GenerateKey,
    RegenerateKey,
    InitSign,
    Sign,
    Abort,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub response_type: ResponseType,
    pub data: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseWithBytes {
    pub response_type: ResponseType,
    pub data: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub enum Context {
    Empty,
    GenContext1(GG18KeyGenContext1),
    GenContext2(GG18KeyGenContext2),
    GenContext3(GG18KeyGenContext3),
    GenContext4(GG18KeyGenContext4),
    GenContext5(GG18KeyGenContext5),
    SignContext0(GG18SignContext),
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

/*
fn data_to_gen_info(_data: Vec<Vec<u8>>) -> (u16, u16, u16) {
    (PARTIES, THRESHOLD, INDEX)
}
*/

fn check_time(config: &Config, time_data: Vec<u8>) -> bool {
    let str_timestamp = match std::str::from_utf8(&time_data) {
        Ok(v) => v,
        Err(_e) => return false,
    };
    let unix_timestamp = match str_timestamp.parse::<i64>() {
        Ok(v) => v,
        Err(_e) => return false,
    };
    let time = Utc.timestamp(unix_timestamp, 0);
    let time_error = Duration::seconds(config.acceptable_seconds);
    return time < Utc::now() + time_error && time > Utc::now() - time_error;
}

pub fn response_bytes_to_hex(response_bytes: ResponseWithBytes) -> Response {
    return Response {
        response_type: response_bytes.response_type,
        data: response_bytes.data
            .iter()
            .map(|x| hex::encode(x))
            .collect()
    }
}

pub fn process_request(
    context: &Context,
    config: &Config,
    request: Request,
) -> (Context, ResponseWithBytes) {
    let request_data = request.data
        .iter()
        .map(|x| hex::decode(x).unwrap())
        .collect();

    match (context, request.request_type) {
        (Context::Empty, RequestType::GenerateKey) => {
            //let (parties, threshold, index) = data_to_gen_info(request.data);
            gg18_key_gen_1(config.num_parties, config.threshold, config.index)
        }

        (Context::Empty, RequestType::InitSign) => {
            let data = fs::read_to_string(&config.context_path);
            if data.is_err() {
                eprintln!("Failed to load setup file.");
                return (
                    Context::Empty,
                    ResponseWithBytes {
                        response_type: ResponseType::Abort,
                        data: Vec::new(),
                    },
                );
            }
            let context = serde_json::from_str::<GG18SignContext>(&data.unwrap());
            if context.is_err() {
                eprintln!("Failed to parse setup file.");
                return (
                    Context::Empty,
                    ResponseWithBytes {
                        response_type: ResponseType::Abort,
                        data: Vec::new(),
                    },
                );
            }
            (
                Context::SignContext0(context.unwrap()),
                ResponseWithBytes {
                    response_type: ResponseType::InitSign,
                    data: Vec::new(),
                },
            )
        }

        (Context::GenContext1(context), RequestType::GenerateKey) => {
            gg18_key_gen_2(request_data, context)
        }

        (Context::GenContext2(context), RequestType::GenerateKey) => {
            gg18_key_gen_3(request_data, context)
        }

        (Context::GenContext3(context), RequestType::GenerateKey) => {
            gg18_key_gen_4(request_data, context)
        }

        (Context::GenContext4(context), RequestType::GenerateKey) => {
            gg18_key_gen_5(request_data, context)
        }

        (Context::GenContext5(context), RequestType::GenerateKey) => {
            let c = gg18_key_gen_6(request_data, context).unwrap();
            fs::write(&config.context_path, serde_json::to_string(&c).unwrap())
                .expect("Unable to save setup file.");

            (
                Context::Empty,
                ResponseWithBytes {
                    response_type: ResponseType::GenerateKey,
                    data: vec![serde_json::to_vec(&c.pk).unwrap()],
                },
            )
        }

        (Context::SignContext0(context), RequestType::Sign) => {
            if request.data.len() < 3 || !check_time(config, request_data[2].clone()) {
                return (
                    Context::Empty,
                    ResponseWithBytes {
                        response_type: ResponseType::Abort,
                        data: Vec::new(),
                    },
                );
            }
            let mut hasher = Sha256::new();
            hasher.update(request_data[1].clone());
            hasher.update(request_data[2].clone());
            let hash = hasher.finalize();

            gg18_sign1(
                context,
                request_data[0]
                    .clone()
                    .into_iter()
                    .map(|x| x as u16)
                    .collect(),
                hash.to_vec(),
            )
        }

        (Context::SignContext1(context), RequestType::Sign) => gg18_sign2(request_data, context),

        (Context::SignContext2(context), RequestType::Sign) => gg18_sign3(request_data, context),

        (Context::SignContext3(context), RequestType::Sign) => gg18_sign4(request_data, context),

        (Context::SignContext4(context), RequestType::Sign) => gg18_sign5(request_data, context),

        (Context::SignContext5(context), RequestType::Sign) => gg18_sign6(request_data, context),

        (Context::SignContext6(context), RequestType::Sign) => gg18_sign7(request_data, context),

        (Context::SignContext7(context), RequestType::Sign) => gg18_sign8(request_data, context),

        (Context::SignContext8(context), RequestType::Sign) => gg18_sign9(request_data, context),

        (Context::SignContext9(context), RequestType::Sign) => {
            let s = gg18_sign10(request_data, context);
            if s.is_err() {
                return (
                    Context::Empty,
                    ResponseWithBytes {
                        response_type: ResponseType::Abort,
                        data: Vec::new(),
                    },
                );
            }
            (
                Context::Empty,
                ResponseWithBytes {
                    response_type: ResponseType::Sign,
                    data: vec![s.unwrap()],
                },
            )
        },

        _ => (
            Context::Empty,
            ResponseWithBytes {
                response_type: ResponseType::Abort,
                data: Vec::new(),
            },
        ),
    }
}
