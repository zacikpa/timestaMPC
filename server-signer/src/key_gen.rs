use curv::{
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar}
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, SharedKeys, Parameters,
};
use paillier::EncryptionKey;
use sha2::Sha256;
use serde::{Serialize, Deserialize};

use crate::requests::{Response, Context, ResponseType};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GG18KeyGenContext1 {
    threshold: u16,
    parties: u16,
    index: u16,
    party_keys: Keys,
    bc_i: KeyGenBroadcastMessage1,
    decom_i: KeyGenDecommitMessage1
}

pub type GG18KeyGenMsg1 = KeyGenBroadcastMessage1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GG18KeyGenContext2 {
    threshold: u16,
    parties: u16,
    index: u16,
    party_keys: Keys,
    bc1_vec: Vec<KeyGenBroadcastMessage1>,
    decom_i: KeyGenDecommitMessage1

}

pub type GG18KeyGenMsg2 = KeyGenDecommitMessage1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GG18KeyGenContext3 {
    threshold: u16,
    parties: u16,
    index: u16,
    party_keys: Keys,
    bc1_vec: Vec<KeyGenBroadcastMessage1>,
    vss_scheme: VerifiableSS<Secp256k1>,
    secret_shares: Vec<Scalar<Secp256k1>>,
    y_sum:  Point<Secp256k1>,
    point_vec: Vec<Point<Secp256k1>>,
}

pub type GG18KeyGenMsg3 = Scalar<Secp256k1>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GG18KeyGenContext4 {
    threshold: u16,
    parties: u16,
    index: u16,
    party_keys: Keys,
    bc1_vec: Vec<KeyGenBroadcastMessage1>,
    vss_scheme: VerifiableSS<Secp256k1>,
    y_sum: Point<Secp256k1>,
    point_vec: Vec<Point<Secp256k1>>,
    party_shares: Vec<Scalar<Secp256k1>>,
}

pub type GG18KeyGenMsg4 = VerifiableSS<Secp256k1>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GG18KeyGenContext5 {
    threshold: u16,
    parties: u16,
    index: u16,
    party_keys: Keys,
    bc1_vec: Vec<KeyGenBroadcastMessage1>,
    vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    y_sum: Point<Secp256k1>,
    point_vec: Vec<Point<Secp256k1>>,
    shared_keys: SharedKeys,
    dlog_proof: DLogProof<Secp256k1, Sha256>
}

pub type GG18KeyGenMsg5 = DLogProof<Secp256k1, Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GG18SignContext {
    pub threshold: u16,
    pub index: u16,
    pub party_keys: Keys,
    pub vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    pub shared_keys: SharedKeys,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub pk: Point<Secp256k1>,
}


pub fn gg18_key_gen_1(parties : u16, threshold : u16, index : u16) -> (Context, Response) {

    let party_keys = Keys::create_safe_prime(index);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    let context1 = GG18KeyGenContext1 {
        threshold,
        parties,
        index,
        party_keys,
        bc_i: bc_i.clone(),
        decom_i,
    };
    let m = serde_json::to_vec(&bc_i);
    if m.is_err() {
        return (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()});
    }
    (Context::GenContext1(context1), Response{ response_type: ResponseType::GenerateKey,
                                        data: vec!(m.unwrap())})
}

pub fn gg18_key_gen_2(messages: Vec<Vec<u8>>, context: &GG18KeyGenContext1) -> (Context, Response) {

    let messages : Option<Vec<GG18KeyGenMsg1>> = messages.into_iter()
                                .map(| x | serde_json::from_slice(&x).ok())
                                .collect();
    if messages.is_none() {
        return (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()});
    }

    let (bc_i, decom_i) = (context.bc_i.clone(), context.decom_i.clone());

    let mut bc1_vec = messages.unwrap();

    bc1_vec.insert(context.index as usize, bc_i);

    let context2 = GG18KeyGenContext2 {
        threshold: context.threshold,
        parties: context.parties,
        index: context.index,
        party_keys: context.party_keys.clone(),
        bc1_vec,
        decom_i: decom_i.clone(),
    };

    let m = serde_json::to_vec(&decom_i);
    if m.is_err() {
        return (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()});
    }
    (Context::GenContext2(context2), Response{ response_type: ResponseType::GenerateKey,
                                        data: vec!(m.unwrap())})
}

/*
Messages from this function should be sent over an encrypted channel
*/
pub fn gg18_key_gen_3(messages: Vec<Vec<u8>>, context: &GG18KeyGenContext2) -> (Context, Response) {

    let messages : Option<Vec<GG18KeyGenMsg2>> = messages.into_iter()
                                .map(| x | serde_json::from_slice(&x).ok())
                                .collect();
    if messages.is_none() {
        return (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()});
    }

    let messages = messages.unwrap();

    let params = Parameters {
        threshold: context.threshold - 1,
        share_count: context.parties,
    };

    let mut j = 0;
    let mut point_vec: Vec<Point<Secp256k1>> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    for i in 0..params.share_count {
        if i == context.index {
            point_vec.push(context.decom_i.y_i.clone());
            decom_vec.push(context.decom_i.clone());
        } else {
            let decom_j  = &messages[j];
            point_vec.push(decom_j.y_i.clone());
            decom_vec.push(decom_j.clone());
            j = j + 1;
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

     let result = context.party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &params, &decom_vec, &context.bc1_vec);

    if result.is_err() {
        return (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()});
    }

    let (vss_scheme, secret_shares, _index) = result.unwrap();

    let mut messages_output = secret_shares.clone();

    messages_output.remove(context.index as usize);

    let context3 = GG18KeyGenContext3 {
        threshold: context.threshold,
        parties: context.parties,
        index: context.index,
        party_keys: context.party_keys.clone(),
        bc1_vec: context.bc1_vec.clone(),
        vss_scheme,
        secret_shares,
        y_sum,
        point_vec,
    };

    let m : Option<Vec<Vec<u8>>> = messages_output.into_iter()
           .map(|x| serde_json::to_vec(&x).ok())
           .collect();
    if m.is_none() {
        return (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()});
    }
    (Context::GenContext3(context3), Response{ response_type: ResponseType::GenerateKey, data: m.unwrap()})
}

pub fn gg18_key_gen_4(messages: Vec<Vec<u8>>, context: &GG18KeyGenContext3) -> (Context, Response) {

    let messages : Option<Vec<GG18KeyGenMsg3>> = messages.into_iter()
                                .map(| x | serde_json::from_slice(&x).ok())
                                .collect();
    if messages.is_none() {
        return (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()});
    }

    let mut party_shares = messages.unwrap();
    party_shares.insert(context.index as usize, context.secret_shares[context.index as usize].clone());

    let context4 = GG18KeyGenContext4 {
        threshold: context.threshold,
        parties: context.parties,
        index: context.index,
        party_keys: context.party_keys.clone(),
        bc1_vec: context.bc1_vec.clone(),
        vss_scheme: context.vss_scheme.clone(),
        y_sum: context.y_sum.clone(),
        point_vec: context.point_vec.clone(),
        party_shares
    };

    let m = serde_json::to_vec(&context4.vss_scheme.clone());
    if m.is_err() {
        return (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()});
    }
    (Context::GenContext4(context4), Response{ response_type: ResponseType::GenerateKey,
                                        data: vec!(m.unwrap())})
}

pub fn gg18_key_gen_5(messages: Vec<Vec<u8>>, context: &GG18KeyGenContext4) -> (Context, Response) {

    let messages : Option<Vec<GG18KeyGenMsg4>> = messages.into_iter()
                                .map(| x | serde_json::from_slice(&x).ok())
                                .collect();
    if messages.is_none() {
        return (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()});
    }

    let params = Parameters {
        threshold: context.threshold - 1,
        share_count: context.parties,
    };
    let mut vss_scheme_vec: Vec<VerifiableSS<Secp256k1>> = messages.unwrap();
    vss_scheme_vec.insert(context.index as usize, context.vss_scheme.clone());

    let result = context.party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &context.point_vec,
            &context.party_shares,
            &vss_scheme_vec,
            context.index + 1,
        );

    if result.is_err() {
        return (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()});
    }

    let (shared_keys, dlog_proof) = result.unwrap();

    let context5 = GG18KeyGenContext5 {
        threshold: context.threshold,
        parties: context.parties,
        index: context.index,
        party_keys: context.party_keys.clone(),
        bc1_vec: context.bc1_vec.clone(),
        vss_scheme_vec,
        y_sum: context.y_sum.clone(),
        point_vec: context.point_vec.clone(),
        shared_keys,
        dlog_proof
    };

    let m = serde_json::to_vec(&context5.dlog_proof.clone());
    if m.is_err() {
        return (Context::Empty, Response{ response_type: ResponseType::Abort, data: Vec::new()});
    }
    (Context::GenContext5(context5), Response{ response_type: ResponseType::GenerateKey,
                                        data: vec!(m.unwrap())})
}

pub fn gg18_key_gen_6(messages: Vec<Vec<u8>>, context: &GG18KeyGenContext5)
-> Result<GG18SignContext, &'static str> {

    let messages : Option<Vec<GG18KeyGenMsg5>> = messages.into_iter()
                                .map(| x | serde_json::from_slice(&x).ok())
                                .collect();
    if messages.is_none() {
        return Err("failed to parse messages");
    }

    let params = Parameters {
        threshold: context.threshold - 1,
        share_count: context.parties,
    };

    let bc1_vec = context.bc1_vec.clone();
    let mut dlog_proof_vec: Vec<DLogProof<Secp256k1, Sha256>> = messages.unwrap();
    dlog_proof_vec.insert(context.index as usize, context.dlog_proof.clone());

    let result = Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &context.point_vec);
    if result.is_err() {
        return Err("bad dlog proof")
    }

    let paillier_key_vec = (0..params.share_count)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let sign_context = GG18SignContext {
        threshold: context.threshold,
        index: context.index,
        party_keys: context.party_keys.clone(),
        vss_scheme_vec: context.vss_scheme_vec.clone(),
        shared_keys: context.shared_keys.clone(),
        paillier_key_vec,
        pk: context.y_sum.clone(),
    };
    Ok(sign_context)
}
