use crate::li17_key_gen::Li17SignContext;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use curv::BigInt;
use curv::arithmetic::traits::*;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point};
use crate::requests::{ResponseWithBytes, Context, ResponseType};

pub struct Li17SignContext1 {
    pub index: u16,
    pub public: Point<Secp256k1>,
    pub p1_private: Option<party_one::Party1Private>,
    pub p2_private: Option<party_two::Party2Private>,
    pub p2_paillier_public: Option<party_two::PaillierPublic>,
    hash: BigInt,
    p2_eph_comm_witness: Option<party_two::EphCommWitness>,
    p2_eph_ec_key_pair: Option<party_two::EphEcKeyPair>,

}

pub type Li17SignMsg1 = party_two::EphKeyGenFirstMsg;

pub struct Li17SignContext2 {
    pub index: u16,
    pub public: Point<Secp256k1>,
    pub p1_private: Option<party_one::Party1Private>,
    pub p2_private: Option<party_two::Party2Private>,
    pub p2_paillier_public: Option<party_two::PaillierPublic>,
    hash: BigInt,
    p1_eph_ec_key_pair: Option<party_one::EphEcKeyPair>,
    p1_msg1_from_p2: Option<Li17SignMsg1>,
    p2_eph_comm_witness: Option<party_two::EphCommWitness>,
    p2_eph_ec_key_pair: Option<party_two::EphEcKeyPair>,

}

pub type Li17SignMsg2 = party_one::EphKeyGenFirstMsg;

pub struct Li17SignContext3 {
    pub index: u16,
    pub public: Point<Secp256k1>,
    pub p1_private: Option<party_one::Party1Private>,
    pub p2_private: Option<party_two::Party2Private>,
    pub p2_paillier_public: Option<party_two::PaillierPublic>,
    hash: BigInt,
    p1_eph_ec_key_pair: Option<party_one::EphEcKeyPair>,
    p1_msg1_from_p2: Option<Li17SignMsg1>,
}

pub type Li17SignMsg3 = (party_two::PartialSig, party_two::EphKeyGenSecondMsg);

pub fn li17_sign1( context: Li17SignContext, message_hash: Vec<u8> ) -> (Context, ResponseWithBytes) {

    if context.index == 0 {
        let context1 = Li17SignContext1 {
            index: 0,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            hash: BigInt::from_bytes(&message_hash),
            p2_eph_comm_witness: None,
            p2_eph_ec_key_pair: None,

        };
        (Context::Sign2pContext1(context1), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                            data: Vec::new()})
    } else {
        let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
                        party_two::EphKeyGenFirstMsg::create_commitments();

        let context1 = Li17SignContext1 {
            index: 1,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            hash: BigInt::from_bytes(&message_hash),
            p2_eph_comm_witness: Some(eph_comm_witness),
            p2_eph_ec_key_pair: Some(eph_ec_key_pair_party2),
        };
        let m = serde_json::to_vec(&eph_party_two_first_message);
        if m.is_err() {
            return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()})
        }
        (Context::Sign2pContext1(context1), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                            data: vec!(m.unwrap())})
    }
}

pub fn li17_sign2( msg: Vec<u8>, context: Li17SignContext1) -> (Context, ResponseWithBytes) {

    if context.index == 0 {
        let msg = serde_json::from_slice::<Li17SignMsg1>(&msg);
        if msg.is_err() {
            return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()});
        }
        let msg = msg.unwrap();

        let (eph_party_one_first_message, eph_ec_key_pair_party1) = party_one::EphKeyGenFirstMsg::create();
        let context2 = Li17SignContext2 {
            index: 0,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            hash: context.hash,
            p1_eph_ec_key_pair: Some(eph_ec_key_pair_party1),
            p1_msg1_from_p2: Some(msg),
            p2_eph_comm_witness: None,
            p2_eph_ec_key_pair: None,

        };
        let m = serde_json::to_vec(&eph_party_one_first_message);
        if m.is_err() {
            return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()})
        }
        (Context::Sign2pContext2(context2), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                            data: vec!(m.unwrap())})

    } else {
        let context2 = Li17SignContext2 {
            index: 1,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            hash: context.hash,
            p1_eph_ec_key_pair: None,
            p1_msg1_from_p2: None,
            p2_eph_comm_witness: context.p2_eph_comm_witness,
            p2_eph_ec_key_pair: context.p2_eph_ec_key_pair,

        };
        (Context::Sign2pContext2(context2), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                            data: Vec::new()})
    }
}

pub fn li17_sign3( msg: Vec<u8>, context: Li17SignContext2) -> (Context, ResponseWithBytes) {

    if context.index == 0 {
        let context3 = Li17SignContext3 {
            index: 0,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            hash: context.hash,
            p1_eph_ec_key_pair: context.p1_eph_ec_key_pair,
            p1_msg1_from_p2: context.p1_msg1_from_p2,
        };
        (Context::Sign2pContext3(context3), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                            data: Vec::new()})

    } else {
        let msg = serde_json::from_slice::<Li17SignMsg2>(&msg);
        if msg.is_err() {
            return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()})
        }

        if context.p2_eph_comm_witness.is_none() || context.p2_eph_ec_key_pair.is_none()
           || context.p2_private.is_none() || context.p2_eph_ec_key_pair.is_none() {
            return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()})
        }
        let msg = msg.unwrap();
        let p2_paillier_public = context.p2_paillier_public.unwrap();
        let p2_private = context.p2_private.unwrap();
        let p2_eph_comm_witness = context.p2_eph_comm_witness.unwrap();
        let p2_eph_ec_key_pair = context.p2_eph_ec_key_pair.unwrap();

    	let eph_party_two_second_message =
            party_two::EphKeyGenSecondMsg::verify_and_decommit(
                p2_eph_comm_witness.clone(),
                &msg,
            );

        if eph_party_two_second_message.is_err(){
            return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()})
        }

        let partial_sig = party_two::PartialSig::compute(
            &p2_paillier_public.ek,
            &p2_paillier_public.encrypted_secret_share,
            &p2_private,
            &p2_eph_ec_key_pair,
            &msg.public_share,
            &context.hash,
        );

        let context3 = Li17SignContext3 {
            index: 1,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: Some(p2_private),
            p2_paillier_public: Some(p2_paillier_public),
            hash: context.hash,
            p1_eph_ec_key_pair: None,
            p1_msg1_from_p2: None,

        };

        let m = serde_json::to_vec(&(partial_sig, eph_party_two_second_message.unwrap()));
        if m.is_err() {
            return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()})
        }
        (Context::Sign2pContext3(context3), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                            data: vec!(m.unwrap())})
    }
}

pub fn li17_sign4( msg: Vec<u8>, context: Li17SignContext3) -> Result<Option<Vec<u8>>, &'static str> {

    if context.index == 0 {
        let msg = serde_json::from_slice::<Li17SignMsg3>(&msg);
        if msg.is_err() {
            return Err("failed to parse a message")
        }

        let (partial_sig, eph_party_two_second_message) = msg.unwrap();
        if context.p1_private.is_none() || context.p1_msg1_from_p2.is_none()
           || context.p1_eph_ec_key_pair.is_none() {
               return Err("invalid context")
           }

       	let _eph_party_one_second_message =
            party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &context.p1_msg1_from_p2.unwrap(),
                &eph_party_two_second_message,
            );

        let sig = party_one::Signature::compute(
            &context.p1_private.unwrap(),
            &partial_sig.c3,
            &context.p1_eph_ec_key_pair.unwrap(),
            &eph_party_two_second_message.comm_witness.public_share,
        );

        if party_one::verify(&sig, &context.public, &context.hash).is_err() {
            return Err("invalid signature")
        }
        return Ok(Some([sig.r.to_bytes(), sig.s.to_bytes()].concat()))

    } else {
        return Ok(None)
    }
}
