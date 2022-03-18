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


pub fn gg18_key_gen_1(parties : u16, threshold : u16, index : u16)
-> Result<(GG18KeyGenMsg1, GG18KeyGenContext1), &'static str> {

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
    Ok((bc_i, context1))
}

pub fn gg18_key_gen_2(messages: Vec<GG18KeyGenMsg1>, context: GG18KeyGenContext1)
-> Result<(GG18KeyGenMsg2, GG18KeyGenContext2), &'static str> {

    let (bc_i, decom_i) = (context.bc_i, context.decom_i);

    let mut bc1_vec = messages;

    bc1_vec.insert(context.index as usize, bc_i);

    let context2 = GG18KeyGenContext2 {
        threshold: context.threshold,
        parties: context.parties,
        index: context.index,
        party_keys: context.party_keys,
        bc1_vec,
        decom_i: decom_i.clone(),
    };
    Ok((decom_i, context2))
}

/*
Messages from this function should be sent over an encrypted channel
*/
pub fn gg18_key_gen_3(messages: Vec<GG18KeyGenMsg2>, context: GG18KeyGenContext2)
-> Result<(Vec<GG18KeyGenMsg3>, GG18KeyGenContext3), &'static str> {

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
        return Err("invalid key")
    }

    let (vss_scheme, secret_shares, _index) = result.unwrap();

    let mut messages_output = secret_shares.clone();

    messages_output.remove(context.index as usize);

    let context3 = GG18KeyGenContext3 {
        threshold: context.threshold,
        parties: context.parties,
        index: context.index,
        party_keys: context.party_keys,
        bc1_vec: context.bc1_vec,
        vss_scheme,
        secret_shares,
        y_sum,
        point_vec,
    };
    Ok((messages_output, context3))
}

pub fn gg18_key_gen_4(messages: Vec<GG18KeyGenMsg3>, context: GG18KeyGenContext3)
-> Result<(GG18KeyGenMsg4, GG18KeyGenContext4), &'static str> {

    let mut party_shares = messages;
    party_shares.insert(context.index as usize, context.secret_shares[context.index as usize].clone());

    let context4 = GG18KeyGenContext4 {
        threshold: context.threshold,
        parties: context.parties,
        index: context.index,
        party_keys: context.party_keys,
        bc1_vec: context.bc1_vec,
        vss_scheme: context.vss_scheme,
        y_sum: context.y_sum,
        point_vec: context.point_vec,
        party_shares
    };

    Ok((context4.vss_scheme.clone(), context4))
}

pub fn gg18_key_gen_5(messages: Vec<GG18KeyGenMsg4>, context: GG18KeyGenContext4)
-> Result<(GG18KeyGenMsg5, GG18KeyGenContext5), &'static str> {

    let params = Parameters {
        threshold: context.threshold - 1,
        share_count: context.parties,
    };
    let mut vss_scheme_vec: Vec<VerifiableSS<Secp256k1>> = messages;
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
        return Err("invalid vss")
    }

    let (shared_keys, dlog_proof) = result.unwrap();

    let context5 = GG18KeyGenContext5 {
        threshold: context.threshold,
        parties: context.parties,
        index: context.index,
        party_keys: context.party_keys,
        bc1_vec: context.bc1_vec,
        vss_scheme_vec,
        y_sum: context.y_sum,
        point_vec: context.point_vec,
        shared_keys,
        dlog_proof
    };

    Ok((context5.dlog_proof.clone(), context5))
}

pub fn gg18_key_gen_6(messages: Vec<GG18KeyGenMsg5>, context: GG18KeyGenContext5)
-> Result<GG18SignContext, &'static str> {

    let params = Parameters {
        threshold: context.threshold - 1,
        share_count: context.parties,
    };

    let bc1_vec = context.bc1_vec;
    let mut dlog_proof_vec: Vec<DLogProof<Secp256k1, Sha256>> = messages;
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
        party_keys: context.party_keys,
        vss_scheme_vec: context.vss_scheme_vec,
        shared_keys: context.shared_keys,
        paillier_key_vec,
        pk: context.y_sum,
    };
    Ok(sign_context)
}
