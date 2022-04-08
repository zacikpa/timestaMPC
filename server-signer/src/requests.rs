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
use base64;
use openssl::rsa::{Rsa, Padding};
use openssl::rand::rand_bytes;
use openssl::symm::{encrypt, Cipher, decrypt};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub index: u16,
    pub context_path: String,
    pub private_rsa: String,
    pub pub_keys_paths: Vec<String>,
    pub symm_path: String,
    pub host: String,
    pub port: u16,
    pub num_parties: u16,
    pub threshold: u16,
    pub acceptable_seconds: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
enum RequestType {
    SymmetricKeySend,
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
    SymmetricKeySend,
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
    WaitingForKeys,
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
    Refresh2pContext4(Li17SignContext),
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

pub fn response_bytes_to_b64(response_bytes: ResponseWithBytes) -> Response {
    return Response {
        response_type: response_bytes.response_type,
        data: response_bytes.data
            .iter()
            .map(|x| base64::encode(x))
            .collect()
    }
}

pub fn encrypt_response( response: Vec<u8>, config: &Config ) -> Vec<u8> {
    // load key
    let symm = fs::read(&format!("{}{}", config.symm_path, "_manager"));
    if symm.is_err(){
        // symmetric key probably not yet established
        return response
    }
    let symm = symm.unwrap();
    println!("Loaded symmetric key length: {}", symm.len());
    //encrypt
    let cipher = Cipher::aes_256_cbc();
    let mut iv : [u8; 16] = [0; 16];
    rand_bytes(&mut iv).unwrap();
    let mut encrypted_response = encrypt(cipher, &symm, Some(&iv), &response).unwrap();

    let mut result_vec = iv.to_vec();
    result_vec.append(&mut encrypted_response);
    result_vec

}

pub fn decrypt_request( enc_request: &[u8], config: &Config ) -> Vec<u8> {
    // load key
    println!("decrypting request");
    let symm = fs::read(&format!("{}{}", config.symm_path, "_manager"));
    if symm.is_err() {
        // this is probably first message with keys not yet established, try to parse original data
        return enc_request.to_vec();
    }

    let cipher = Cipher::aes_256_cbc();
    let request = decrypt(cipher, &symm.unwrap(), Some(&enc_request[0..16]), &enc_request[16..]);
    request.unwrap()
}

pub fn process_request(
    context: &Context,
    config: &Config,
    request: Request,
) -> (Context, ResponseWithBytes) {
    let request_data : Option<Vec<Vec<u8>>>= request.data
        .iter()
        .map(|x| base64::decode(x).ok())
        .collect();

    if request_data.is_none() {
        eprintln!("Failed to decode data.");
        return ABORT
    }
    let request_data = request_data.unwrap();
    match (context, request.request_type) {
        (Context::Empty, RequestType::SymmetricKeySend) => {
            // load private RSA key
            let pem : String = fs::read_to_string(&config.private_rsa).unwrap().parse().unwrap();
            let private_rsa = Rsa::private_key_from_pem(pem.as_bytes()).unwrap();
            let mut symm_key: Vec<u8> = vec![0; private_rsa.size() as usize];
            // decrypt symmetric key shared with manager server
            println!("data size: {}, rsa size: {}", request_data[0].len(), private_rsa.size());
            let r = private_rsa.private_decrypt(&request_data[0], &mut symm_key, Padding::PKCS1);

            if r.is_err() || fs::write(format!("{}{}", config.symm_path, "_manager"), &symm_key[..32]).is_err() {
                println!("decryption error: {}", r.is_err());
                return ABORT
            }
            // generate symmetric keys shared with other signers
            let mut signers_symm_keys: Vec<Vec<u8>> = Vec::new();
            for i in 0..config.num_parties {
                // generate keys for parties with higher index
                if i > config.index {
                    let mut symm_key = [0; 32];
                    // generate random key
                    rand_bytes(&mut symm_key).unwrap();
                    // save it
                    if fs::write(format!("{}{}", config.symm_path, i), symm_key).is_err(){
                        return ABORT
                    }
                    // load RSA public key for corresponding party
                    let pub_rsa = fs::read(&config.pub_keys_paths[i as usize]).unwrap();
                    println!("{}", std::str::from_utf8(&pub_rsa).unwrap());
                    let public_rsa = Rsa::public_key_from_pem_pkcs1(&pub_rsa).unwrap();
                    // encrypt the symm key
                    let mut encrypted: Vec<u8> = vec![0; public_rsa.size() as usize];
                    let _ = public_rsa.public_encrypt(&symm_key, &mut encrypted, Padding::PKCS1).unwrap();
                    // append it
                    signers_symm_keys.push(encrypted.to_vec());
                }
                // parties with lower index will send key to you
                if i < config.index {
                    signers_symm_keys.push(Vec::new());
                }
            }
            (
                Context::WaitingForKeys,
                ResponseWithBytes {
                    response_type: ResponseType::SymmetricKeySend,
                    data: signers_symm_keys,
                },
            )
        }
        (Context::WaitingForKeys, RequestType::SymmetricKeySend) => {
            if request_data.len() < config.index as usize {
                return (
                    Context::WaitingForKeys,
                    ResponseWithBytes {
                        response_type: ResponseType::Abort,
                        data: Vec::new(),
                    },
                )
            }

            for i in 0..config.index {
                if fs::write(format!("{}{}", config.symm_path, i), &request_data[i as usize]).is_err(){
                    return (
                        Context::WaitingForKeys,
                        ResponseWithBytes {
                            response_type: ResponseType::Abort,
                            data: Vec::new(),
                        },
                    )
                }
            }
            return (
                Context::Empty,
                ResponseWithBytes {
                    response_type: ResponseType::SymmetricKeySend,
                    data: Vec::new(),
                },
            )
        }
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
                                data: vec![c.pk.to_bytes(false).as_ref().to_vec()],
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
                                data: vec![c.public.to_bytes(false).as_ref().to_vec()],
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
            if request.data.len() < 2 || !check_time(config, request_data[1].clone()) {
                return ABORT
            }
            let mut hasher = Sha256::new();
            hasher.update(request_data[0].clone());
            hasher.update(request_data[1].clone());
            let hash = hasher.finalize();
            li17_sign1(context.unwrap(), hash.to_vec())
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
            (
                Context::Refresh2pContext4(c.unwrap()),
                ResponseWithBytes {
                    response_type: ResponseType::GenerateKey2p,
                    data: Vec::new(),
                },
            )
        }
        (Context::Refresh2pContext4(context), RequestType::Refresh2p) => {

            let serde = serde_json::to_string(context);
            if serde.is_ok() {
                if fs::write(&config.context_path, serde.unwrap()).is_ok() {
                    return (
                        Context::Empty,
                        ResponseWithBytes {
                            response_type: ResponseType::Refresh2p,
                            data: Vec::new(),
                        },
                    )
                }
            }
            ABORT // oh no, this is sad
        }

        _ => ABORT
    }
}
