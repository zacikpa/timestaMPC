use std::fs;
use serde::{Deserialize, Serialize};
use crate::key_gen::{GG18KeyGenContext1, GG18KeyGenContext2, GG18KeyGenContext3, GG18KeyGenContext4,
    GG18KeyGenContext5, GG18SignContext, gg18_key_gen_1, gg18_key_gen_2, gg18_key_gen_3,
    gg18_key_gen_4, gg18_key_gen_5, gg18_key_gen_6,
    GG18KeyGenMsg1, GG18KeyGenMsg2, GG18KeyGenMsg3, GG18KeyGenMsg4, GG18KeyGenMsg5};
use crate::sign::{GG18SignContext1, GG18SignContext2, GG18SignContext3, GG18SignContext4,
    GG18SignContext5, GG18SignContext6, GG18SignContext7, GG18SignContext8, GG18SignContext9,
    gg18_sign1, gg18_sign2, gg18_sign3, gg18_sign4, gg18_sign5, gg18_sign6, gg18_sign7, gg18_sign8,
    gg18_sign9, gg18_sign10, GG18SignMsg1, GG18SignMsg2, GG18SignMsg3, GG18SignMsg4, GG18SignMsg5,
    GG18SignMsg6, GG18SignMsg7, GG18SignMsg8, GG18SignMsg9};

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

fn data_to_gen_info( data: Vec<Vec<u8>> ) -> (u16, u16, u16) {
    (data[0][0] as u16, data[0][1] as u16, data[0][2] as u16)
}

pub fn process_request(context: &Context, request_buf: Vec<u8>) -> (Context, Response) {

    let request = serde_json::from_slice::<Request>(&request_buf);
    if request.is_err() {
            return (Context::Empty, Response{
                    response_type: ResponseType::Abort,
                    data: Vec::new()});
    }
    let request = request.unwrap();


    match (context, request.request_type) {
        (Context::Empty, RequestType::GenerateKey) =>
            {
            let (parties, threshold, index) = data_to_gen_info(request.data);
            let (m, c) = gg18_key_gen_1(parties, threshold, index).unwrap();
            (Context::GenContext1(c), Response{ response_type: ResponseType::GenerateKey,
                                                data: vec!(serde_json::to_vec(&m).unwrap())})
            }

        (Context::Empty, RequestType::InitSign) =>
            {
                let data = fs::read_to_string(SIGNCONTEXTPATH).expect("Unable to load setup file.");
                let context = Context::SignContext0(serde_json::from_str(&data).expect("Unable to parse setup file."));
                (context, Response{ response_type: ResponseType::Sign, data: Vec::new()})
            }

        (Context::GenContext1(context), RequestType::GenerateKey) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18KeyGenMsg1>>();
                let (m, c) = gg18_key_gen_2(messages, context).unwrap();
                (Context::GenContext2(c), Response{ response_type: ResponseType::GenerateKey,
                                                    data: vec!(serde_json::to_vec(&m).unwrap())})
            }

        (Context::GenContext2(context), RequestType::GenerateKey) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18KeyGenMsg2>>();
                let (m, c) = gg18_key_gen_3(messages, context).unwrap();
                (Context::GenContext3(c), Response{ response_type: ResponseType::GenerateKey,
                                                    data: m.into_iter()
                                                           .map(|x| serde_json::to_vec(&x).unwrap())
                                                           .collect()})
            }

        (Context::GenContext3(context), RequestType::GenerateKey) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18KeyGenMsg3>>();
                let (m, c) = gg18_key_gen_4(messages, context).unwrap();
                (Context::GenContext4(c), Response{ response_type: ResponseType::GenerateKey,
                                                    data: vec!(serde_json::to_vec(&m).unwrap())})
            }

        (Context::GenContext4(context), RequestType::GenerateKey) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18KeyGenMsg4>>();
                let (m, c) = gg18_key_gen_5(messages, context).unwrap();
                (Context::GenContext5(c), Response{ response_type: ResponseType::GenerateKey,
                                                    data: vec!(serde_json::to_vec(&m).unwrap())})
            }

        (Context::GenContext5(context), RequestType::GenerateKey) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18KeyGenMsg5>>();
                let c = gg18_key_gen_6(messages, context).unwrap();
                fs::write(SIGNCONTEXTPATH, serde_json::to_string(&c).unwrap()).expect("Unable to save setup file.");

                (Context::Empty, Response{ response_type: ResponseType::GenerateKey,
                                                    data: vec!(serde_json::to_vec(&c.pk).unwrap())})
            }

        (Context::SignContext0(context), RequestType::Sign) =>
            {
                let (m, c) = gg18_sign1(context, request.data[0].clone().into_iter().map(|x| x as u16).collect()
                , request.data[1].clone()).unwrap();
                (Context::SignContext1(c), Response{ response_type: ResponseType::GenerateKey,
                                                    data: vec!(serde_json::to_vec(&m).unwrap())})
            }

        (Context::SignContext1(context), RequestType::Sign) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18SignMsg1>>();
                let (m, c) = gg18_sign2(messages, context).unwrap();
                (Context::SignContext2(c), Response{ response_type: ResponseType::Sign,
                                                     data: m.into_iter()
                                                            .map(|x| serde_json::to_vec(&x).unwrap())
                                                            .collect()})
            }

        (Context::SignContext2(context), RequestType::Sign) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18SignMsg2>>();
                let (m, c) = gg18_sign3(messages, context).unwrap();
                (Context::SignContext3(c), Response{ response_type: ResponseType::GenerateKey,
                                                     data: vec!(serde_json::to_vec(&m).unwrap())})
            }

        (Context::SignContext3(context), RequestType::Sign) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18SignMsg3>>();
                let (m, c) = gg18_sign4(messages, context).unwrap();
                (Context::SignContext4(c), Response{ response_type: ResponseType::GenerateKey,
                                                     data: vec!(serde_json::to_vec(&m).unwrap())})
            }
        (Context::SignContext4(context), RequestType::Sign) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18SignMsg4>>();
                let (m, c) = gg18_sign5(messages, context).unwrap();
                (Context::SignContext5(c), Response{ response_type: ResponseType::GenerateKey,
                                                     data: vec!(serde_json::to_vec(&m).unwrap())})
            }
        (Context::SignContext5(context), RequestType::Sign) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18SignMsg5>>();
                let (m, c) = gg18_sign6(messages, context).unwrap();
                (Context::SignContext6(c), Response{ response_type: ResponseType::GenerateKey,
                                                     data: vec!(serde_json::to_vec(&m).unwrap())})
            }

        (Context::SignContext6(context), RequestType::Sign) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18SignMsg6>>();
                let (m, c) = gg18_sign7(messages, context).unwrap();
                (Context::SignContext7(c), Response{ response_type: ResponseType::GenerateKey,
                                                     data: vec!(serde_json::to_vec(&m).unwrap())})
            }

        (Context::SignContext7(context), RequestType::Sign) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18SignMsg7>>();
                let (m, c) = gg18_sign8(messages, context).unwrap();
                (Context::SignContext8(c), Response{ response_type: ResponseType::GenerateKey,
                                                     data: vec!(serde_json::to_vec(&m).unwrap())})
            }

        (Context::SignContext8(context), RequestType::Sign) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18SignMsg8>>();
                let (m, c) = gg18_sign9(messages, context).unwrap();
                (Context::SignContext9(c), Response{ response_type: ResponseType::GenerateKey,
                                                     data: vec!(serde_json::to_vec(&m).unwrap())})
            }

        (Context::SignContext9(context), RequestType::Sign) =>
            {
                let messages = request.data.into_iter()
                                            .map(| x | serde_json::from_slice(&x).unwrap())
                                            .collect::<Vec<GG18SignMsg9>>();
                let s = gg18_sign10(messages, context).unwrap();
                (Context::Empty, Response{ response_type: ResponseType::GenerateKey,
                                                     data: vec!(s)})
            }

        _ => {let response = b"Ok\n";
                return (Context::Empty, Response{
                        response_type: ResponseType::Abort,
                        data: vec![response.to_vec()]});}
        }
}
