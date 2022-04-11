use curv::BigInt;
use paillier::EncryptionKey;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackStatement;
use zk_paillier::zkproofs::CompositeDLogProof;
use zk_paillier::zkproofs::NiCorrectKeyProof;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point};
use serde::{Serialize, Deserialize};
use crate::requests::{ResponseWithBytes, Context, ResponseType, ABORT};

#[derive(Clone, Debug)]
pub struct Li17KeyGenContext1 {
    index: u16,
    p1_ec_key_pair: Option<party_one::EcKeyPair>,
    p1_comm_witness: Option<party_one::CommWitness>,
}

pub type Li17KeyGenMsg1 = party_one::KeyGenFirstMsg;

#[derive(Clone, Debug)]
pub struct Li17KeyGenContext2 {
    index: u16,
    p1_ec_key_pair: Option<party_one::EcKeyPair>,
    p1_comm_witness: Option<party_one::CommWitness>,
    p2_msg1_from_p1: Option<party_one::KeyGenFirstMsg>,
    p2_ec_key_pair: Option<party_two::EcKeyPair>,
}

pub type Li17KeyGenMsg2 = party_two::KeyGenFirstMsg;

pub struct Li17KeyGenContext3 {
    index: u16,
    p1_ec_key_pair: Option<party_one::EcKeyPair>,
    p1_paillier_key_pair: Vec<u8>,//party_one::PaillierKeyPair,
    p1_public_share_p2: Option<Point<Secp256k1>>,
    p2_msg1_from_p1: Option<party_one::KeyGenFirstMsg>,
    p2_ec_key_pair: Option<party_two::EcKeyPair>,
}

pub type Li17KeyGenMsg3 = (party_one::KeyGenSecondMsg, NiCorrectKeyProof, PDLwSlackStatement,
                           PDLwSlackProof, CompositeDLogProof, EncryptionKey, BigInt);

#[derive(Serialize, Deserialize)]
pub struct Li17SignContext {
    pub index: u16,
    pub public: Point<Secp256k1>,
    pub public_p1: Point<Secp256k1>,
    pub public_p2: Point<Secp256k1>,
    pub p1_private: Option<party_one::Party1Private>,
    pub p2_private: Vec<u8>, //Option<party_two::Party2Private>,
    pub p2_paillier_public: Vec<u8> //Option<party_two::PaillierPublic>,

}


pub fn li17_key_gen1( index: u16 ) -> (Context, ResponseWithBytes) {
    if index > 1 {
        return ABORT
    }

    if index == 0 {
        let (party1_first_message, p1_comm_witness, p1_ec_key_pair) =
                        party_one::KeyGenFirstMsg::create_commitments();
        let context1 = Li17KeyGenContext1 {
            index: 0,
            p1_ec_key_pair: Some(p1_ec_key_pair),
            p1_comm_witness: Some(p1_comm_witness),
        };
        let m = serde_json::to_vec(&party1_first_message);
        if m.is_err() {
            return ABORT
        }
        (Context::Gen2pContext1(context1), ResponseWithBytes{ response_type: ResponseType::GenerateKey2p,
                                            data: vec!(m.unwrap())})
    } else {
        let context1 = Li17KeyGenContext1 {
            index: 1,
            p1_ec_key_pair: None,
            p1_comm_witness: None,
        };
        (Context::Gen2pContext1(context1), ResponseWithBytes{ response_type: ResponseType::GenerateKey2p,
                                            data: vec!(Vec::new())})
    }
}

pub fn li17_key_gen2( msg: Vec<Vec<u8>>, context: &Li17KeyGenContext1 ) -> (Context, ResponseWithBytes) {

    if context.index == 0 {
        let context2 = Li17KeyGenContext2 {
            index: 0,
            p1_ec_key_pair: context.p1_ec_key_pair.clone(),
            p1_comm_witness: context.p1_comm_witness.clone(),
            p2_msg1_from_p1: None,
            p2_ec_key_pair: None,
        };
        (Context::Gen2pContext2(context2), ResponseWithBytes{ response_type: ResponseType::GenerateKey2p,
                                            data: vec!(Vec::new())})
    } else {
        if msg.is_empty() {
            return ABORT
        }
        let msg = serde_json::from_slice::<Li17KeyGenMsg1>(&msg[0]);
        if msg.is_err() {
            return ABORT
        }
        let msg = msg.unwrap();

        let (p2_first_message, p2_ec_key_pair) = party_two::KeyGenFirstMsg::create();
        let context2 = Li17KeyGenContext2 {
            index: 1,
            p1_ec_key_pair: None,
            p1_comm_witness: None,
            p2_msg1_from_p1: Some(msg),
            p2_ec_key_pair: Some(p2_ec_key_pair),

        };
        let m = serde_json::to_vec(&p2_first_message);
        if m.is_err() {
            return ABORT
        }
        (Context::Gen2pContext2(context2), ResponseWithBytes{ response_type: ResponseType::GenerateKey2p,
                                            data: vec!(m.unwrap())})

    }
}

pub fn li17_key_gen3( msg: Vec<Vec<u8>>, context: &Li17KeyGenContext2 ) -> (Context, ResponseWithBytes) {

    if context.index == 0 {
        if msg.is_empty() {
            return ABORT
        }
        let msg = serde_json::from_slice::<Li17KeyGenMsg2>(&msg[0]);
        if msg.is_err() {
            return ABORT
        }
        let msg = msg.unwrap();

        if context.p1_comm_witness.is_none() || context.p1_ec_key_pair.is_none() {
            return ABORT
        }
        let p1_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
                                        context.p1_comm_witness.clone().unwrap(), &msg.d_log_proof);

        if p1_second_message.is_err(){
            return ABORT
        }
        let p1_second_message = p1_second_message.unwrap();
        let p1_ec_key_pair = context.p1_ec_key_pair.clone().unwrap();
        let paillier_key_pair = party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&p1_ec_key_pair);
        let party_one_private = party_one::Party1Private::set_private_key(&p1_ec_key_pair, &paillier_key_pair);

        let correct_key_proof = party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);

        let (pdl_statement, pdl_proof, composite_dlog_proof) =
                    party_one::PaillierKeyPair::pdl_proof(&party_one_private, &paillier_key_pair);
        let ek = paillier_key_pair.ek.clone();
        let encrypted_share = paillier_key_pair.encrypted_share.clone();

        let p1_paillier_key_pair = serde_json::to_vec(&paillier_key_pair);
        if p1_paillier_key_pair.is_err() {
            return ABORT
        }
        let context3 = Li17KeyGenContext3 {
            index: 0,
            p1_ec_key_pair: context.p1_ec_key_pair.clone(),
            p1_paillier_key_pair: p1_paillier_key_pair.unwrap(),
            p1_public_share_p2: Some(msg.public_share),
            p2_msg1_from_p1: None,
            p2_ec_key_pair: None,

        };

       let m = serde_json::to_vec(&(p1_second_message, correct_key_proof, pdl_statement, pdl_proof,
                                    composite_dlog_proof, ek, encrypted_share));
       if m.is_err() {
           return ABORT
       }
       (Context::Gen2pContext3(context3), ResponseWithBytes{ response_type: ResponseType::GenerateKey2p,
                                           data: vec!(m.unwrap())})


    } else {
        // PaillierKeyPair does not derive trait Clone which complicates working with Option<PaillierKeyPair>
        // in a reference to context. This is a terrible but working workaround.
        let (_, _, _not_used_) = party_one::KeyGenFirstMsg::create_commitments();
        let _not_used_ = party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&_not_used_);

        let context3 = Li17KeyGenContext3 {
            index: 1,
            p1_ec_key_pair: None,
            p1_paillier_key_pair: Vec::new(),
            p1_public_share_p2: None,
            p2_msg1_from_p1: context.p2_msg1_from_p1.clone(),
            p2_ec_key_pair: context.p2_ec_key_pair.clone(),

        };
        (Context::Gen2pContext3(context3), ResponseWithBytes{ response_type: ResponseType::GenerateKey2p,
                                            data: vec!(Vec::new())})
    }
}

pub fn li17_key_gen4( msg: Vec<Vec<u8>>, context: &Li17KeyGenContext3 ) -> Result<Li17SignContext, &'static str> {

    if context.index == 0 {
        let p1_paillier_key_pair = serde_json::from_slice::<party_one::PaillierKeyPair>(
                                                                    &context.p1_paillier_key_pair);
        if context.p1_ec_key_pair.is_none() || context.p1_public_share_p2.is_none()
           || p1_paillier_key_pair.is_err() {
               return Err("invalid context")
        }
        let p1_paillier_key_pair = p1_paillier_key_pair.unwrap();
        let party_one_private = party_one::Party1Private::set_private_key(&context.p1_ec_key_pair.clone().unwrap(),
                                                                &p1_paillier_key_pair);
        let public_key = party_one::compute_pubkey(&party_one_private, &context.p1_public_share_p2.clone().unwrap());
        let sign_context = Li17SignContext {
            index: 0,
            public: public_key.clone(),
            public_p1: context.p1_ec_key_pair.clone().unwrap().public_share,
            public_p2: context.p1_public_share_p2.clone().unwrap(),
            p1_private: Some(party_one_private),
            p2_private: Vec::new(),
            p2_paillier_public: Vec::new(),
        };
        Ok(sign_context)

    } else {
        if msg.is_empty() {
            return Err("Empty message")
        }
        let msg = serde_json::from_slice::<Li17KeyGenMsg3>(&msg[0]);
        if msg.is_err() {
            return Err("failed to parse a message")
        }

        let (party_one_second_message, correct_key_proof, pdl_statement, pdl_proof,
            composite_dlog_proof, paillier_ek, paillier_encrypted_share) = msg.unwrap();

        if context.p2_msg1_from_p1.is_none() || context.p2_ec_key_pair.is_none() {
            return Err("invalid context")
        }

        let p2_ec_key_pair = context.p2_ec_key_pair.clone().unwrap();
    	let r = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                            &context.p2_msg1_from_p1.clone().unwrap(),
                            &party_one_second_message,
                        );

        if r.is_err() {
            return Err("failed to verify commitments and DLog proof")
        }

        let party_two_paillier = party_two::PaillierPublic {
                        ek: paillier_ek.clone(),
                        encrypted_secret_share: paillier_encrypted_share.clone(),
        };

        if party_two::PaillierPublic::verify_ni_proof_correct_key( correct_key_proof,
                                                                &party_two_paillier.ek,).is_err() {
            return Err("bad paillier key")
        }

        if party_two::PaillierPublic::pdl_verify(
                        &composite_dlog_proof,
                        &pdl_statement,
                        &pdl_proof,
                        &party_two_paillier,
                        &party_one_second_message.comm_witness.public_share,
                    ).is_err() {
            return Err("PDL error")
        }

        let party_two_private = party_two::Party2Private::set_private_key(&p2_ec_key_pair);
        let public_key = party_two::compute_pubkey(&p2_ec_key_pair, &party_one_second_message.comm_witness.public_share);
        let p2_private = serde_json::to_vec(&party_two_private);
        let p2_paillier_public = serde_json::to_vec(&party_two_paillier);
        if p2_private.is_err() || p2_paillier_public.is_err() {
            return Err("Serde failed")
        }
        let sign_context = Li17SignContext {
            index: 1,
            public: public_key.clone(),
            public_p1: party_one_second_message.comm_witness.public_share,
            public_p2: context.p2_ec_key_pair.clone().unwrap().public_share,
            p1_private: None,
            p2_private: p2_private.unwrap(),
            p2_paillier_public: p2_paillier_public.unwrap()
        };

        Ok(sign_context)
    }
}
