use std::fs;
use serde::{Deserialize, Serialize};
use crate::key_gen::{GG18KeyGenContext1, GG18KeyGenContext2, GG18KeyGenContext3, GG18KeyGenContext4,
    GG18KeyGenContext5, GG18SignContext, gg18_key_gen_1, gg18_key_gen_2, gg18_key_gen_3,
    gg18_key_gen_4, gg18_key_gen_5, gg18_key_gen_6};
use crate::sign::{GG18SignContext1, GG18SignContext2, GG18SignContext3, GG18SignContext4,
    GG18SignContext5, GG18SignContext6, GG18SignContext7, GG18SignContext8, GG18SignContext9,
    gg18_sign1, gg18_sign2, gg18_sign3, gg18_sign4, gg18_sign5, gg18_sign6, gg18_sign7, gg18_sign8,
    gg18_sign9, gg18_sign10};
use chrono::{Duration, TimeZone, Utc};
use sha2::{Sha256, Digest};

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
    data: Vec<Vec<u8>>,
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

const SIGNCONTEXTPATH: &str = "/some/path/";
const ACCEPTABLE_SECONDS: i64 = 60;
const PARTIES: u16 = 2;
const THRESHOLD: u16 = 2;
const INDEX: u16 = 0;

fn data_to_gen_info(_data: Vec<Vec<u8>>) -> (u16, u16, u16) {
    (PARTIES, THRESHOLD, INDEX)
}

fn check_time(time_data: Vec<u8>) -> bool {
    let str_timestamp = match std::str::from_utf8(&time_data) {
        Ok(v) => v,
        Err(_e) => return false,
    };
    let unix_timestamp = match str_timestamp.parse::<i64>() {
        Ok(v) => v,
        Err(_e) => return false,
    };
    let time = Utc.timestamp(unix_timestamp, 0);
    let time_error = Duration::seconds(ACCEPTABLE_SECONDS);
    return time < Utc::now() + time_error && time > Utc::now() - time_error;
}

pub fn process_request(context: &Context, request_buf: Vec<u8>) -> (Context, Response) {

    let request = serde_json::from_slice::<Request>(&request_buf);
    if request.is_err() {
            return (Context::Empty, Response{response_type: ResponseType::Abort, data: Vec::new()});
    }
    let request = request.unwrap();


    match (context, request.request_type) {
        (Context::Empty, RequestType::GenerateKey) =>
            {
            let (parties, threshold, index) = data_to_gen_info(request.data);
            gg18_key_gen_1(parties, threshold, index)
            }

        (Context::Empty, RequestType::InitSign) =>
            {
                let data = fs::read_to_string(SIGNCONTEXTPATH);
                if data.is_err() {
                    eprintln!("Failed to load setup file.");
                    return (Context::Empty, Response{response_type: ResponseType::Abort, data: Vec::new()});
                }
                let context = serde_json::from_str::<GG18SignContext>(&data.unwrap());
                if context.is_err() {
                    eprintln!("Failed to parse setup file.");
                    return (Context::Empty, Response{response_type: ResponseType::Abort, data: Vec::new()});
                }
                (Context::SignContext0(context.unwrap()),
                Response{ response_type: ResponseType::Sign, data: Vec::new()})
            }

        (Context::GenContext1(context), RequestType::GenerateKey) => gg18_key_gen_2(request.data, context),

        (Context::GenContext2(context), RequestType::GenerateKey) => gg18_key_gen_3(request.data, context),

        (Context::GenContext3(context), RequestType::GenerateKey) => gg18_key_gen_4(request.data, context),

        (Context::GenContext4(context), RequestType::GenerateKey) => gg18_key_gen_5(request.data, context),

        (Context::GenContext5(context), RequestType::GenerateKey) =>
            {
                let c = gg18_key_gen_6(request.data, context).unwrap();
                fs::write(SIGNCONTEXTPATH, serde_json::to_string(&c).unwrap()).expect("Unable to save setup file.");

                (Context::Empty, Response{ response_type: ResponseType::GenerateKey,
                                                    data: vec!(serde_json::to_vec(&c.pk).unwrap())})
            }

        (Context::SignContext0(context), RequestType::Sign) =>
            {
                if request.data.len() < 3 || !check_time(request.data[2].clone()) {
                    return (Context::Empty, Response{response_type: ResponseType::Abort, data: Vec::new()})
                }
                let mut hasher = Sha256::new();
                hasher.update(request.data[1].clone());
                hasher.update(request.data[2].clone());
                let hash = hasher.finalize();

                gg18_sign1(context, request.data[0].clone().into_iter().map(|x| x as u16).collect(),
                hash.to_vec())
            }

        (Context::SignContext1(context), RequestType::Sign) => gg18_sign2(request.data, context),

        (Context::SignContext2(context), RequestType::Sign) => gg18_sign3(request.data, context),

        (Context::SignContext3(context), RequestType::Sign) => gg18_sign4(request.data, context),

        (Context::SignContext4(context), RequestType::Sign) => gg18_sign5(request.data, context),

        (Context::SignContext5(context), RequestType::Sign) => gg18_sign6(request.data, context),

        (Context::SignContext6(context), RequestType::Sign) => gg18_sign7(request.data, context),

        (Context::SignContext7(context), RequestType::Sign) => gg18_sign8(request.data, context),

        (Context::SignContext8(context), RequestType::Sign) => gg18_sign9(request.data, context),


        (Context::SignContext9(context), RequestType::Sign) =>
            {
                let s = gg18_sign10(request.data, context);
                if s.is_err() {
                    return (Context::Empty, Response{response_type: ResponseType::Abort, data: Vec::new()})
                }
                (Context::Empty, Response{ response_type: ResponseType::GenerateKey,
                                                     data: vec!(s.unwrap())})
            }

        _ => (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()})
        }
}
