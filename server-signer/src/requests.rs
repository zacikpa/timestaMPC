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
use openssl::error::ErrorStack;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub index: u16,
    pub context_path: String,
    pub private_rsa: String,
    pub manager_public_key_path: String,
    pub pub_keys_paths: Vec<String>,
    pub symm_keys_folder: String,
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
    Keys1(Vec<u8>),
    Keys2(Vec<Vec<u8>>),
    Keys3(Vec<Vec<u8>>),
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

pub fn encrypt_response(symm: &[u8], response: Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_256_cbc();
    let mut iv : [u8; 16] = [0; 16];
    rand_bytes(&mut iv).unwrap();
    let mut encrypted_response = encrypt(cipher, &symm, Some(&iv), &response).unwrap();
    let mut result_vec = iv.to_vec();
    result_vec.append(&mut encrypted_response);
    result_vec
}

pub fn decrypt_request(symm: &[u8], enc_request: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_256_cbc();
    return decrypt(cipher, &symm, Some(&enc_request[0..16]), &enc_request[16..]);
}

pub fn encrypt_payload( response: (Context, ResponseWithBytes), config: &Config, parties: Vec<u16>) -> (Context, ResponseWithBytes) {
    let data = response.1.data;
    let mut result : Vec<Vec<u8>> = Vec::new();
    let mut j = 0;
    for i in 0..parties.len() {
        if parties[i] == config.index {
            continue;
        }
        if data[j].is_empty() {
            result.push(Vec::new());
            j += 1;
            continue;
        }
        let key = fs::read(&format!("{}/symm{}_{}", config.symm_keys_folder, config.index, parties[i]));
        if key.is_err() || data[j].len() < 16 {
            return ABORT
        }
        let cipher = Cipher::aes_256_cbc();
        let mut iv : [u8; 16] = [0; 16];
        rand_bytes(&mut iv).unwrap();
        let encrypted_data = encrypt(cipher, &key.unwrap(), Some(&iv), &data[j]);
        if encrypted_data.is_err() {
            return ABORT
        }
        let mut encrypted_data_iv = iv.to_vec();
        encrypted_data_iv.append(&mut encrypted_data.unwrap());

        result.push(encrypted_data_iv);
        j += 1;
    }
    (response.0, ResponseWithBytes{ response_type: response.1.response_type, data: result})
}

pub fn decrypt_payload( data: Vec<Vec<u8>>, config: &Config, parties: Vec<u16>) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut result : Vec<Vec<u8>> = Vec::new();
    let mut j = 0;
    for i in 0..parties.len() {
        if parties[i] == config.index {
            continue;
        }
        if data[j].is_empty() {
            result.push(Vec::new());
            j += 1;
            continue;
        }
        let key = fs::read(&format!("{}/symm{}_{}", config.symm_keys_folder, config.index, parties[i]));
        if key.is_err() || data[j].len() < 16 {
            return Err("invalid encrypted data")
        }
        let cipher = Cipher::aes_256_cbc();
        let request = decrypt(cipher, &key.unwrap(), Some(&data[j][0..16]), &data[j][16..]);
        if request.is_err() {
            return Err("decryption failed")
        }
        result.push(request.unwrap());
        j += 1;
    }
    return Ok(result)
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
            if request_data.is_empty() {
                return ABORT
            }
            // load private RSA key
            let pem : String = fs::read_to_string(&config.private_rsa).unwrap().parse().unwrap();
            let private_rsa = Rsa::private_key_from_pem(pem.as_bytes()).unwrap();
            let mut challenge: Vec<u8> = vec![0; private_rsa.size() as usize];
            // decrypt symmetric key shared with manager server
            let r = private_rsa.private_decrypt(&request_data[0], &mut challenge, Padding::PKCS1);

            let mut symm_key = [0; 32];
            // generate random key
            let r2 = rand_bytes(&mut symm_key);

            if r.is_err() || r2.is_err() {
                return ABORT
            }

            // load manager's RSA public key
            let pub_rsa = fs::read(&config.manager_public_key_path);
            if pub_rsa.is_err() {
                return ABORT
            }
            let public_rsa = Rsa::public_key_from_pem_pkcs1(&pub_rsa.unwrap());
            if public_rsa.is_err() {
                return ABORT
            }
            let public_rsa = public_rsa.unwrap();
            // encrypt the symm key and challenge
            let mut msg = symm_key.to_vec();
            msg.append(&mut challenge[0..r.unwrap()].to_vec());
            let mut encrypted: Vec<u8> = vec![0; public_rsa.size() as usize];
            if public_rsa.public_encrypt(&msg, &mut encrypted, Padding::PKCS1).is_err() {
                return ABORT
            }

            (
                Context::Keys1(symm_key.to_vec()),
                ResponseWithBytes {
                    response_type: ResponseType::SymmetricKeySend,
                    data: vec!(encrypted),
                },
            )
        }
        (Context::Keys1(manager_symm), RequestType::SymmetricKeySend) => {
            let _ = fs::create_dir_all(&config.symm_keys_folder);
            if fs::write(format!("{}/symm{}_manager", config.symm_keys_folder, config.index), &manager_symm).is_err() {
                return ABORT
            }

            let mut messages: Vec<Vec<u8>> = Vec::new();
            let mut challenges: Vec<Vec<u8>> = Vec::new();
            for i in 0..config.num_parties {
                // generate challenges for parties with higher index
                if i > config.index {
                    let mut challenge = [0; 32];
                    // generate challenge
                    if rand_bytes(&mut challenge).is_err(){
                        return ABORT
                    }
                    challenges.push(challenge.to_vec());

                    // load RSA public key for corresponding party
                    let pub_rsa = fs::read(&config.pub_keys_paths[i as usize]).unwrap();
                    let public_rsa = Rsa::public_key_from_pem_pkcs1(&pub_rsa).unwrap();
                    // encrypt the challenge
                    let mut encrypted: Vec<u8> = vec![0; public_rsa.size() as usize];
                    if public_rsa.public_encrypt(&challenge, &mut encrypted, Padding::PKCS1).is_err(){
                        return ABORT
                    }
                    // append it
                    messages.push(encrypted.to_vec());
                }
                // parties with lower index will send challenges to you
                if i < config.index {
                    messages.push(Vec::new());
                    challenges.push(Vec::new());
                }
            }

            (
                Context::Keys2(challenges.clone()),
                ResponseWithBytes {
                    response_type: ResponseType::SymmetricKeySend,
                    data: messages,
                },
            )
        }
        (Context::Keys2(challenges), RequestType::SymmetricKeySend) => {
            if request_data.len() < config.index as usize {
                return ABORT
            }
            // decrypt challenges from signers
            let pem : String = fs::read_to_string(&config.private_rsa).unwrap().parse().unwrap();
            let private_rsa = Rsa::private_key_from_pem(pem.as_bytes()).unwrap();

            let mut response : Vec<Vec<u8>> = Vec::new();

            for i in 0..config.num_parties {
                if i < config.index {
                    let mut challenge: Vec<u8> = vec![0; private_rsa.size() as usize];
                    let r = private_rsa.private_decrypt(&request_data[i as usize], &mut challenge, Padding::PKCS1);

                    if r.is_err() {
                        return ABORT
                    }

                    let mut symm_key = [0; 32];
                    // generate random key
                    if rand_bytes(&mut symm_key).is_err(){
                        return ABORT
                    }
                    // save it
                    if fs::write(format!("{}/symm{}_{}", config.symm_keys_folder, config.index, i), symm_key).is_err(){
                        return ABORT
                    }
                    // load RSA public key for corresponding party
                    let pub_rsa = fs::read(&config.pub_keys_paths[i as usize]).unwrap();
                    let public_rsa = Rsa::public_key_from_pem_pkcs1(&pub_rsa).unwrap();
                    // encrypt the symm key and challenge
                    let mut msg = symm_key.to_vec();
                    msg.append(&mut challenge[0..r.unwrap()].to_vec());
                    let mut encrypted: Vec<u8> = vec![0; public_rsa.size() as usize];
                    if public_rsa.public_encrypt(&msg, &mut encrypted, Padding::PKCS1).is_err(){
                        return ABORT
                    }
                    // append it
                    response.push(encrypted.to_vec());

                }
                if i > config.index {
                    response.push(Vec::new());
                }

            }
            (
                Context::Keys3(challenges.clone()),
                ResponseWithBytes {
                    response_type: ResponseType::SymmetricKeySend,
                    data: response,
                },
            )
        }
        (Context::Keys3(challenges), RequestType::SymmetricKeySend) => {

            if request_data.len() < (config.num_parties as usize - 1) {
                return ABORT
            }

            let pem : String = fs::read_to_string(&config.private_rsa).unwrap().parse().unwrap();
            let private_rsa = Rsa::private_key_from_pem(pem.as_bytes()).unwrap();

            for i in (config.index + 1)..config.num_parties {
                let mut data: Vec<u8> = vec![0; private_rsa.size() as usize];
                let r = private_rsa.private_decrypt(&request_data[(i - 1) as usize], &mut data, Padding::PKCS1);
                if r.is_err() {
                    println!("ABORT decrypt failed");
                    return ABORT
                }
                if challenges[(i - 1) as usize] != data[32..r.unwrap()].to_vec() {
                    println!("ABORT bad challenge");
                    return ABORT
                }
                // save key
                if fs::write(format!("{}/symm{}_{}", config.symm_keys_folder, config.index, i), &data[0..32]).is_err(){
                    println!("ABORT write");
                    return ABORT
                }
            }
            (
                Context::Empty,
                ResponseWithBytes {
                    response_type: ResponseType::SymmetricKeySend,
                    data: vec!(Vec::new())
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
            encrypt_payload(gg18_key_gen_3(request_data, context), config,
                                                                (0..config.num_parties).collect()),

        (Context::GenContext3(context), RequestType::GenerateKey) => {
            let data = decrypt_payload(request_data, config, (0..config.num_parties).collect());
            if data.is_err() {
                return ABORT
            }
            gg18_key_gen_4(data.unwrap(), context)
        }

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

        (Context::SignContext1(context), RequestType::Sign) =>
            encrypt_payload(gg18_sign2(request_data, context), config, context.indices.clone()),

        (Context::SignContext2(context), RequestType::Sign) => {
            let data = decrypt_payload(request_data, config, context.indices.clone());
            if data.is_err() {
                return ABORT
            }
            gg18_sign3(data.unwrap(), context)
        }

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
                encrypt_payload(li17_key_gen1(config.index), config, [0, 1].to_vec())
            }
        }

        (Context::Gen2pContext1(context), RequestType::GenerateKey2p) =>
        {
            let data = decrypt_payload(request_data, config, [0, 1].to_vec());
            if data.is_err() {
                return ABORT
            }
            encrypt_payload(li17_key_gen2(data.unwrap(), context), config, [0, 1].to_vec())
        }

        (Context::Gen2pContext2(context), RequestType::GenerateKey2p) =>
        {
            let data = decrypt_payload(request_data, config, [0, 1].to_vec());
            if data.is_err() {
                return ABORT
            }
            encrypt_payload(li17_key_gen3(data.unwrap(), context), config, [0, 1].to_vec())
        }

        (Context::Gen2pContext3(context), RequestType::GenerateKey2p) => {
            let data = decrypt_payload(request_data, config, [0, 1].to_vec());
            if data.is_err() {
                return ABORT
            }
            let c = li17_key_gen4(data.unwrap(), context);
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
            encrypt_payload(li17_sign1(context.unwrap(), hash.to_vec()), config, [0, 1].to_vec())
        }

        (Context::Sign2pContext1(context), RequestType::Sign2p) => {
            let data = decrypt_payload(request_data, config, [0, 1].to_vec());
            if data.is_err() {
                return ABORT
            }
            encrypt_payload(li17_sign2(data.unwrap(), context), config, [0, 1].to_vec())
        }

        (Context::Sign2pContext2(context), RequestType::Sign2p) => {
            let data = decrypt_payload(request_data, config, [0, 1].to_vec());
            if data.is_err() {
                return ABORT
            }
            encrypt_payload(li17_sign3(data.unwrap(), context), config, [0, 1].to_vec())
        }

        (Context::Sign2pContext3(context), RequestType::Sign2p) => {
            let data = decrypt_payload(request_data, config, [0, 1].to_vec());
            if data.is_err() {
                return ABORT
            }
            let s = li17_sign4(data.unwrap(), context);
            if s.is_err() {
                return ABORT
            }
            (
                Context::Empty,
                ResponseWithBytes {
                    response_type: ResponseType::Sign2p,
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
            encrypt_payload(li17_refresh1(context.unwrap()), config, [0, 1].to_vec())
        }

        (Context::Refresh2pContext1(context), RequestType::Refresh2p) => {
            let data = decrypt_payload(request_data, config, [0, 1].to_vec());
            if data.is_err() {
                return ABORT
            }
            encrypt_payload(li17_refresh2(data.unwrap(), context), config, [0, 1].to_vec())
        }

        (Context::Refresh2pContext2(context), RequestType::Refresh2p) => {
            let data = decrypt_payload(request_data, config, [0, 1].to_vec());
            if data.is_err() {
                return ABORT
            }
            encrypt_payload(li17_refresh3(data.unwrap(), context), config, [0, 1].to_vec())
        }

        (Context::Refresh2pContext3(context), RequestType::Refresh2p) => {
            let data = decrypt_payload(request_data, config, [0, 1].to_vec());
            if data.is_err() {
                return ABORT
            }
            let c = li17_refresh4(data.unwrap(), context);
            if c.is_err() {
                return ABORT
            }
            (
                Context::Refresh2pContext4(c.unwrap()),
                ResponseWithBytes {
                    response_type: ResponseType::Refresh2p,
                    data: vec![Vec::new()],
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
                            data: vec![Vec::new()],
                        },
                    )
                }
            }
            ABORT // oh no, this is sad
        }

        _ => ABORT
    }
}
