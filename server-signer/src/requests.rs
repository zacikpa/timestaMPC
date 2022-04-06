use crate::gg18_key_gen::{
    gg18_key_gen_1, gg18_key_gen_2, gg18_key_gen_3, gg18_key_gen_4, gg18_key_gen_5, gg18_key_gen_6,
    GG18KeyGenContext1, GG18KeyGenContext2, GG18KeyGenContext3, GG18KeyGenContext4,
    GG18KeyGenContext5, GG18SignContext,
};
use crate::gg18_sign::{
    gg18_sign1, gg18_sign10, gg18_sign2, gg18_sign3, gg18_sign4, gg18_sign5, gg18_sign6,
    gg18_sign7, gg18_sign8, gg18_sign9, GG18SignContext1, GG18SignContext2, GG18SignContext3,
    GG18SignContext4, GG18SignContext5, GG18SignContext6, GG18SignContext7, GG18SignContext8,
    GG18SignContext9,
};
use crate::li17_key_gen::{
    li17_key_gen1, li17_key_gen2, li17_key_gen3, li17_key_gen4,
    Li17KeyGenContext1, Li17KeyGenContext2, Li17KeyGenContext3, Li17SignContext,
};
use crate::li17_sign::{
    li17_sign1, li17_sign2, li17_sign3, li17_sign4,
    Li17SignContext1, Li17SignContext2, Li17SignContext3,
};
use crate::li17_refresh::{
    li17_refresh1, li17_refresh2, li17_refresh3, li17_refresh4,
    Li17RefreshContext1, Li17RefreshContext2, Li17RefreshContext3,
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
    InitSign,
    Sign,
    GenerateKey2p,
    Refresh2p,
    Sign2p,
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
    InitSign,
    Sign,
    GenerateKey2p,
    Refresh2p,
    Sign2p,
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
    Gen2pContext1(Li17KeyGenContext1),
    Gen2pContext2(Li17KeyGenContext2),
    Gen2pContext3(Li17KeyGenContext3),
    Sign2pContext1(Li17SignContext1),
    Sign2pContext2(Li17SignContext2),
    Sign2pContext3(Li17SignContext3),
    Refresh2pContext1(Li17RefreshContext1),
    Refresh2pContext2(Li17RefreshContext2),
    Refresh2pContext3(Li17RefreshContext3),
}

pub const ABORT : (Context, ResponseWithBytes) = (
    Context::Empty,
    ResponseWithBytes {
        response_type: ResponseType::Abort,
        data: Vec::new(),
    },
);

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
    let request_data : Option<Vec<Vec<u8>>>= request.data
        .iter()
        .map(|x| hex::decode(x).ok())
        .collect();

    if request_data.is_none() {
        eprintln!("Failed to decode data.");
        return ABORT
    }
    let request_data = request_data.unwrap();
    match (context, request.request_type) {
        (Context::Empty, RequestType::GenerateKey) => {
            gg18_key_gen_1(config.num_parties, config.threshold, config.index)
        }

        (Context::Empty, RequestType::InitSign) => {
            let data = fs::read_to_string(&config.context_path);
            if data.is_err() {
                eprintln!("Failed to load setup file.");
                return ABORT
            }
            let context = serde_json::from_str::<GG18SignContext>(&data.unwrap());
            if context.is_err() {
                eprintln!("Failed to parse setup file.");
                return ABORT
            }
            (
                Context::SignContext0(context.unwrap()),
                ResponseWithBytes {
                    response_type: ResponseType::InitSign,
                    data: Vec::new(),
                },
            )
        }

        (Context::GenContext1(context), RequestType::GenerateKey) =>
            gg18_key_gen_2(request_data, context),

        (Context::GenContext2(context), RequestType::GenerateKey) =>
            gg18_key_gen_3(request_data, context),

        (Context::GenContext3(context), RequestType::GenerateKey) =>
            gg18_key_gen_4(request_data, context),

        (Context::GenContext4(context), RequestType::GenerateKey) =>
            gg18_key_gen_5(request_data, context),

        (Context::GenContext5(context), RequestType::GenerateKey) => {
            let c = gg18_key_gen_6(request_data, context);
            if c.is_ok() {
                let c = c.unwrap();
                let serde = serde_json::to_string(&c);
                if serde.is_ok() {
                    if fs::write(&config.context_path, serde.unwrap()).is_ok() {
                        return (
                            Context::Empty,
                            ResponseWithBytes {
                                response_type: ResponseType::GenerateKey,
                                data: vec![serde_json::to_vec(&c.pk).unwrap()],
                            },
                        )
                    }
                }
            }
            ABORT
        }

        (Context::SignContext0(context), RequestType::Sign) => {
            if request.data.len() < 3 || !check_time(config, request_data[2].clone()) {
                return ABORT
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
                return ABORT
            }
            (
                Context::Empty,
                ResponseWithBytes {
                    response_type: ResponseType::Sign,
                    data: vec![s.unwrap()],
                },
            )
        },

        (Context::Empty, RequestType::GenerateKey2p) => {
            if config.threshold != 2 || config.num_parties != 2 {
                ABORT
            } else {
                li17_key_gen1(config.index)
            }
        }

        (Context::Gen2pContext1(context), RequestType::GenerateKey2p) =>
            li17_key_gen2(request_data, context),

        (Context::Gen2pContext2(context), RequestType::GenerateKey2p) =>
            li17_key_gen3(request_data, context),

        (Context::Gen2pContext3(context), RequestType::GenerateKey2p) => {
            let c = li17_key_gen4(request_data, context);
            if c.is_ok() {
                let c = c.unwrap();
                let serde = serde_json::to_string(&c);
                if serde.is_ok() {
                    if fs::write(&config.context_path, serde.unwrap()).is_ok() {
                        return (
                            Context::Empty,
                            ResponseWithBytes {
                                response_type: ResponseType::GenerateKey2p,
                                data: vec![serde_json::to_vec(&c.public).unwrap()],
                            },
                        )
                    }
                }
            }
            ABORT
        }

        (Context::Empty, RequestType::Sign2p) => {
            let data = fs::read_to_string(&config.context_path);
            if data.is_err() {
                eprintln!("Failed to load setup file.");
                return ABORT
            }
            let context = serde_json::from_str::<Li17SignContext>(&data.unwrap());
            if context.is_err() {
                eprintln!("Failed to parse setup file.");
                return ABORT
            }
            li17_sign1(context.unwrap(), request_data)
        }

        (Context::Sign2pContext1(context), RequestType::Sign2p) => li17_sign2(request_data, context),

        (Context::Sign2pContext2(context), RequestType::Sign2p) => li17_sign3(request_data, context),

        (Context::Sign2pContext3(context), RequestType::Sign2p) => {
            let s = li17_sign4(request_data, context);
            if s.is_err() {
                return ABORT
            }
            (
                Context::Empty,
                ResponseWithBytes {
                    response_type: ResponseType::Sign,
                    data: vec![s.unwrap()],
                },
            )
        },

        (Context::Empty, RequestType::Refresh2p) => {
            let data = fs::read_to_string(&config.context_path);
            if data.is_err() {
                eprintln!("Failed to load setup file.");
                return ABORT
            }
            let context = serde_json::from_str::<Li17SignContext>(&data.unwrap());
            if context.is_err() {
                eprintln!("Failed to parse setup file.");
                return ABORT
            }
            li17_refresh1(context.unwrap())
        }

        (Context::Refresh2pContext1(context), RequestType::Refresh2p) => li17_refresh2(request_data, context),

        (Context::Refresh2pContext2(context), RequestType::Refresh2p) => li17_refresh3(request_data, context),

        (Context::Refresh2pContext3(context), RequestType::Refresh2p) => {
            let c = li17_refresh4(request_data, context);
            if c.is_err() {
                return ABORT
            }
            let serde = serde_json::to_string(&c);
            if serde.is_err() {
                return ABORT
            }
            fs::write(&config.context_path, serde.unwrap())
                .expect("Unable to save setup file.");

            (
                Context::Empty,
                ResponseWithBytes {
                    response_type: ResponseType::GenerateKey2p,
                    data: Vec::new(),
                },
            )

        }

        _ => ABORT
    }
}
