use crate::li17_key_gen::Li17SignContext;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use sha2::Sha256;
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackStatement;
use zk_paillier::zkproofs::CompositeDLogProof;
use zk_paillier::zkproofs::NiCorrectKeyProof;
use curv::BigInt;
use paillier::EncryptionKey;
use zk_paillier::zkproofs::SALT_STRING;
use crate::requests::{ResponseWithBytes, Context, ResponseType};

pub struct Li17RefreshContext1 {
    index: u16,
    public: Point<Secp256k1>,
    public_p1: Point<Secp256k1>,
    public_p2: Point<Secp256k1>,
    p1_private: Option<party_one::Party1Private>,
    p2_private: Option<party_two::Party2Private>,
    p2_paillier_public: Option<party_two::PaillierPublic>,
    p1_m1: Option<Scalar<Secp256k1>>,
    p1_r1: Option<Scalar<Secp256k1>>

}

pub type Li17RefreshMsg1 = coin_flip_optimal_rounds::Party1FirstMessage::<Secp256k1, Sha256>;

pub struct Li17RefreshContext2 {
    index: u16,
    public: Point<Secp256k1>,
    public_p1: Point<Secp256k1>,
    public_p2: Point<Secp256k1>,
    p1_private: Option<party_one::Party1Private>,
    p2_private: Option<party_two::Party2Private>,
    p2_paillier_public: Option<party_two::PaillierPublic>,
    p1_m1: Option<Scalar<Secp256k1>>,
    p1_r1: Option<Scalar<Secp256k1>>,
    p2_coin_flip_first_message: Option<Li17RefreshMsg2>,
    p2_msg1_from_p1: Option<coin_flip_optimal_rounds::Party1FirstMessage::<Secp256k1, Sha256>>

}

pub type Li17RefreshMsg2 = coin_flip_optimal_rounds::Party2FirstMessage::<Secp256k1>;

pub struct Li17RefreshContext3 {
    index: u16,
    public: Point<Secp256k1>,
    public_p1: Point<Secp256k1>,
    public_p2: Point<Secp256k1>,
    p1_private: Option<party_one::Party1Private>,
    p2_private: Option<party_two::Party2Private>,
    p2_paillier_public: Option<party_two::PaillierPublic>,
    p2_coin_flip_first_message: Option<Li17RefreshMsg2>,
    p2_msg1_from_p1: Option<coin_flip_optimal_rounds::Party1FirstMessage::<Secp256k1, Sha256>>
}

pub type Li17RefreshMsg3 = (coin_flip_optimal_rounds::Party1SecondMessage::<Secp256k1, Sha256>,
                            NiCorrectKeyProof, PDLwSlackStatement, PDLwSlackProof,
                            CompositeDLogProof, EncryptionKey, BigInt);

pub fn li17_refresh1( context: Li17SignContext ) -> (Context, ResponseWithBytes) {

    if context.index == 0 {
        let (p1_coin_flip_first_message, m1, r1) = coin_flip_optimal_rounds::Party1FirstMessage::<Secp256k1, Sha256>::commit();
        let context1 = Li17RefreshContext1 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p1_m1: Some(m1),
            p1_r1: Some(r1),
        };
        let m = serde_json::to_vec(&p1_coin_flip_first_message);
        if m.is_err() {
            return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()})
        }
        (Context::Refresh2pContext1(context1), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                            data: vec!(m.unwrap())})

    } else {
        let context1 = Li17RefreshContext1 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p1_m1: None,
            p1_r1: None,
        };
        (Context::Refresh2pContext1(context1), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                            data: Vec::new()})
    }
}

pub fn li17_refresh2( msg: Vec<u8>,context: Li17RefreshContext1 ) -> (Context, ResponseWithBytes) {

    if context.index == 0 {
        let context2 = Li17RefreshContext2 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p1_m1: context.p1_m1,
            p1_r1: context.p1_r1,
            p2_coin_flip_first_message: None,
            p2_msg1_from_p1: None,
        };
        (Context::Refresh2pContext2(context2), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                            data: Vec::new()})

    } else {
        let msg = serde_json::from_slice::<Li17RefreshMsg1>(&msg);
        if msg.is_err() {
            return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()});
        }
        let msg = msg.unwrap();
        let p2_coin_flip_first_message = coin_flip_optimal_rounds::Party2FirstMessage::share(&msg.proof);
        let context2 = Li17RefreshContext2 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p1_m1: None,
            p1_r1: None,
            p2_coin_flip_first_message: Some(p2_coin_flip_first_message.clone()),
            p2_msg1_from_p1: Some(msg),
        };
        let m = serde_json::to_vec(&p2_coin_flip_first_message);
        if m.is_err() {
            return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()})
        }
        (Context::Refresh2pContext2(context2), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                            data: vec!(m.unwrap())})

    }
}

pub fn li17_refresh3( msg: Vec<u8>,context: Li17RefreshContext2 ) -> (Context, ResponseWithBytes) {

    if context.index == 0 {
        let msg = serde_json::from_slice::<Li17RefreshMsg2>(&msg);
        if msg.is_err() || context.p1_m1.is_none() || context.p1_r1.is_none() || context.p1_private.is_none(){
            return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()});
        }
        let msg = msg.unwrap();

        let (p1_second_message, res) = coin_flip_optimal_rounds::Party1SecondMessage::<Secp256k1, Sha256>::reveal(
                            &msg.seed, &context.p1_m1.unwrap(), &context.p1_r1.unwrap());


        let (ek_new, c_key_new, new_private, correct_key_proof,
            pdl_statement, pdl_proof, composite_dlog_proof,) =
            party_one::Party1Private::refresh_private_key(&context.p1_private.unwrap(), &res.to_bigint());

        let context3 = Li17RefreshContext3 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1 * &res,
            public_p2: context.public_p2 * &res.invert().unwrap(),
            p1_private: Some(new_private),
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p2_coin_flip_first_message: context.p2_coin_flip_first_message,
            p2_msg1_from_p1: context.p2_msg1_from_p1,
        };

        let m = serde_json::to_vec(&(p1_second_message, correct_key_proof, pdl_statement,
                                     pdl_proof, composite_dlog_proof, ek_new, c_key_new));
        if m.is_err() {
         return (Context::Empty, ResponseWithBytes{ response_type: ResponseType::Abort, data: Vec::new()})
        }
        (Context::Refresh2pContext3(context3), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                         data: vec!(m.unwrap())})

    } else {
        let context3 = Li17RefreshContext3 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: None,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p2_coin_flip_first_message: context.p2_coin_flip_first_message,
            p2_msg1_from_p1: context.p2_msg1_from_p1,
        };

        (Context::Refresh2pContext3(context3), ResponseWithBytes{ response_type: ResponseType::GenerateKey,
                                                                  data: Vec::new()})

    }
}

pub fn li17_refresh4( msg: Vec<u8>,context: Li17RefreshContext3 ) -> Result<Li17SignContext, &'static str> {

    if context.index == 0 {

        let sign_context = Li17SignContext {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
        };

        return Ok(sign_context)

    } else {
        let msg = serde_json::from_slice::<Li17RefreshMsg3>(&msg);
        if msg.is_err() {
            return Err("failed to parse a message")
        }
        let msg = msg.unwrap();

        if context.p2_coin_flip_first_message.is_none() || context.p2_msg1_from_p1.is_none()
           || context.p2_private.is_none() {
            return Err("invalid context")
        }
        let res = coin_flip_optimal_rounds::finalize(
            &msg.0.proof,
            &context.p2_coin_flip_first_message.unwrap().seed,
            &context.p2_msg1_from_p1.unwrap().proof.com,
        );
        let party_two_paillier = party_two::PaillierPublic {
            ek: msg.5.clone(),
            encrypted_secret_share: msg.6.clone(),
        };

        if party_two::PaillierPublic::pdl_verify(&msg.4, &msg.2, &msg.3, &party_two_paillier,
                                                 &(context.public_p1.clone() * &res)).is_err() {
            return Err("proof failed")
        }

        if msg.1.verify(&party_two_paillier.ek, SALT_STRING).is_err() {
            return Err("proof failed")
        }

        let sign_context = Li17SignContext {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1 * &res,
            public_p2: context.public_p2 * &res.invert().unwrap(),
            p1_private: None,
            p2_private: Some(party_two::Party2Private::update_private_key(
                &context.p2_private.unwrap(),
                &res.invert().unwrap().to_bigint(),
            )),
            p2_paillier_public: Some(party_two_paillier),
        };
        Ok(sign_context)
    }
}
