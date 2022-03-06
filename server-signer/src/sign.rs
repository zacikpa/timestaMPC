use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof,
        secret_sharing::feldman_vss::VerifiableSS
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, LocalSignature, PartyPrivate, Phase5ADecom1, Phase5Com1, Phase5Com2, Phase5DDecom2, SignBroadcastPhase1, SignDecommitPhase1, SignKeys
};
use paillier::EncryptionKey;
use multi_party_ecdsa::utilities::mta::*;
use sha2::Sha256;
use crate::key_gen::GG18SignContext;

pub struct GG18SignContext1 {
    indices: Vec<u16>,
    threshold_index: usize,
    message_hash: Vec<u8>,
    threshold: u16,
    party_id: u16,
    party_keys: Keys,
    vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    paillier_key_vec: Vec<EncryptionKey>,
    y_sum: Point<Secp256k1>,
    sign_keys: SignKeys,
    xi_com_vec: Vec<Point<Secp256k1>>,
    com: SignBroadcastPhase1,
    decommit: SignDecommitPhase1
}

pub type GG18SignMsg1 = (SignBroadcastPhase1, MessageA);

pub struct GG18SignContext2 {
    indices: Vec<u16>,
    threshold_index: usize,
    message_hash: Vec<u8>,
    threshold: u16,
    party_id: u16,
    party_keys: Keys,
    vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    y_sum: Point<Secp256k1>,
    sign_keys: SignKeys,
    xi_com_vec: Vec<Point<Secp256k1>>,
    decommit: SignDecommitPhase1,
    bc1_vec: Vec<SignBroadcastPhase1>,
    beta_vec: Vec<Scalar<Secp256k1>>,
    ni_vec: Vec<Scalar<Secp256k1>>
}

pub type GG18SignMsg2 = (MessageB, MessageB);

pub struct GG18SignContext3 {
    indices: Vec<u16>,
    threshold_index: usize,
    message_hash: Vec<u8>,
    threshold: u16,
    party_id: u16,
    y_sum: Point<Secp256k1>,
    sign_keys: SignKeys,
    decommit: SignDecommitPhase1,
    bc1_vec: Vec<SignBroadcastPhase1>,
    m_b_gamma_rec_vec: Vec<MessageB>,
    delta_i: Scalar<Secp256k1>,
    sigma: Scalar<Secp256k1>
}

pub type GG18SignMsg3 = Scalar<Secp256k1>;

pub struct GG18SignContext4 {
    indices: Vec<u16>,
    threshold_index: usize,
    message_hash: Vec<u8>,
    threshold: u16,
    party_id: u16,
    y_sum: Point<Secp256k1>,
    sign_keys: SignKeys,
    decommit: SignDecommitPhase1,
    bc1_vec: Vec<SignBroadcastPhase1>,
    m_b_gamma_rec_vec: Vec<MessageB>,
    sigma: Scalar<Secp256k1>,
    delta_inv: Scalar<Secp256k1>
}

pub type GG18SignMsg4 = SignDecommitPhase1;

pub struct GG18SignContext5 {
    indices: Vec<u16>,
    threshold_index: usize,
    threshold: u16,
    party_id: u16,
    local_sig: LocalSignature,
    phase5_com: Phase5Com1,
    phase_5a_decom: Phase5ADecom1,
    helgamal_proof: HomoELGamalProof<Secp256k1, Sha256>,
    dlog_proof_rho: DLogProof<Secp256k1, Sha256>,
    r: Point<Secp256k1>
}

pub type GG18SignMsg5 = Phase5Com1;

pub struct GG18SignContext6 {
    indices: Vec<u16>,
    threshold_index: usize,
    threshold: u16,
    party_id: u16,
    local_sig: LocalSignature,
    phase_5a_decom: Phase5ADecom1,
    helgamal_proof: HomoELGamalProof<Secp256k1, Sha256>,
    dlog_proof_rho: DLogProof<Secp256k1, Sha256>,
    r: Point<Secp256k1>,
    commit5a_vec: Vec<Phase5Com1>
}

pub type GG18SignMsg6 = (Phase5ADecom1, HomoELGamalProof<Secp256k1, Sha256>, DLogProof<Secp256k1, Sha256>);

pub struct GG18SignContext7 {
    indices: Vec<u16>,
    threshold_index: usize,
    threshold: u16,
    party_id: u16,
    local_sig: LocalSignature,
    phase_5a_decom: Phase5ADecom1,
    decommit5a_and_elgamal_and_dlog_vec_includes_i: Vec<(Phase5ADecom1, HomoELGamalProof<Secp256k1, Sha256>, DLogProof<Secp256k1, Sha256>)>,
    phase_5a_decomm_vec: Vec<Phase5ADecom1>,
    phase5_com2: Phase5Com2,
    phase_5d_decom2: Phase5DDecom2
}

pub type GG18SignMsg7 = Phase5Com2;

pub struct GG18SignContext8 {
    indices: Vec<u16>,
    threshold_index: usize,
    threshold: u16,
    party_id: u16,
    local_sig: LocalSignature,
    phase_5a_decom: Phase5ADecom1,
    decommit5a_and_elgamal_and_dlog_vec_includes_i: Vec<(Phase5ADecom1, HomoELGamalProof<Secp256k1, Sha256>, DLogProof<Secp256k1, Sha256>)>,
    phase_5a_decomm_vec: Vec<Phase5ADecom1>,
    phase_5d_decom2: Phase5DDecom2,
    commit5c_vec: Vec<Phase5Com2>
}

pub type GG18SignMsg8 = Phase5DDecom2;

pub struct GG18SignContext9 {
    threshold: u16,
    local_sig: LocalSignature
}

pub type GG18SignMsg9 = Scalar<Secp256k1>;

pub fn gg18_sign1(context: GG18SignContext, indices: Vec<u16>, threshold_index: usize, message_hash: Vec<u8>) -> (GG18SignMsg1, GG18SignContext1) {

    let private = PartyPrivate::set_private(context.party_keys.clone(), context.shared_keys);
    let sign_keys = SignKeys::create(
        &private,
        &context.vss_scheme_vec[context.index as usize],
        context.index,
        &indices,
    );

    let xi_com_vec = Keys::get_commitments_to_xi(&context.vss_scheme_vec);
    let (com, decommit) = sign_keys.phase1_broadcast();
    let (m_a_k, _) = MessageA::a(&sign_keys.k_i, &context.party_keys.ek, &[]);

    let context1 = GG18SignContext1 {
        indices,
        threshold_index,
        message_hash,
        threshold: context.threshold,
        party_id: context.index,
        party_keys: context.party_keys,
        vss_scheme_vec: context.vss_scheme_vec,
        paillier_key_vec: context.paillier_key_vec,
        y_sum: context.pk,
        sign_keys,
        xi_com_vec,
        com,
        decommit
    };

    ((context1.com.clone(), m_a_k), context1)
}

pub fn gg18_sign2(messages: Vec<GG18SignMsg1>, context: GG18SignContext1) -> (Vec<GG18SignMsg2>, GG18SignContext2) {

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();

    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            bc1_vec.push(context.com.clone());

        } else {

            let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) = messages[j].clone();
            bc1_vec.push(bc1_j);
            m_a_vec.push(m_a_party_j);

            j += 1;

        }
    }
    assert_eq!(context.indices.len(), bc1_vec.len());

    //////////////////////////////////////////////////////////////////////////////
    let mut send_vec: Vec<(MessageB, MessageB)> = Vec::new();
    let mut beta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut ni_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) != context.threshold_index{
            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &context.sign_keys.gamma_i,
                &context.paillier_key_vec[context.indices[i as usize] as usize],
                m_a_vec[j].clone(),
                &[]
            ).unwrap();
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &context.sign_keys.w_i,
                &context.paillier_key_vec[context.indices[i as usize] as usize],
                m_a_vec[j].clone(),
                &[]
            ).unwrap();
            send_vec.push((m_b_gamma, m_b_w));
            beta_vec.push(beta_gamma);
            ni_vec.push(beta_wi);
            j += 1;
        }
    }

    let context2 = GG18SignContext2 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        message_hash: context.message_hash,
        threshold: context.threshold,
        party_id: context.party_id,
        party_keys: context.party_keys,
        vss_scheme_vec: context.vss_scheme_vec,
        y_sum: context.y_sum,
        sign_keys: context.sign_keys,
        xi_com_vec: context.xi_com_vec,
        decommit: context.decommit,
        bc1_vec,
        beta_vec,
        ni_vec
    };

    (send_vec, context2)

}

pub fn gg18_sign3(messages: Vec<GG18SignMsg2>, context: GG18SignContext2) -> (GG18SignMsg3, GG18SignContext3) {

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();
    for i in 0..(context.threshold - 1) {

        let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) = messages[i as usize].clone();
        m_b_gamma_rec_vec.push(m_b_gamma_i);
        m_b_w_rec_vec.push(m_b_w_i);

    }
    let mut alpha_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut miu_vec: Vec<Scalar<Secp256k1>> = Vec::new();

    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) != context.threshold_index {
            let m_b = m_b_gamma_rec_vec[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&context.party_keys.dk, &context.sign_keys.k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_rec_vec[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&context.party_keys.dk, &context.sign_keys.k_i)
                .expect("wrong dlog or m_b");
            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            let g_w_i = Keys::update_commitments_to_xi(
                &context.xi_com_vec[context.indices[i as usize] as usize],
                &context.vss_scheme_vec[context.indices[i as usize] as usize],
                context.indices[i as usize],
                &context.indices,
            );
            assert_eq!(m_b.b_proof.pk, g_w_i);
            j += 1;
        }
    }


    let delta_i = context.sign_keys.phase2_delta_i(&alpha_vec, &context.beta_vec);
    let sigma = context.sign_keys.phase2_sigma_i(&miu_vec, &context.ni_vec);

    let context3 = GG18SignContext3 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        message_hash: context.message_hash,
        threshold: context.threshold,
        party_id: context.party_id,
        y_sum: context.y_sum,
        sign_keys: context.sign_keys,
        decommit: context.decommit,
        bc1_vec: context.bc1_vec,
        m_b_gamma_rec_vec,
        delta_i: delta_i.clone(),
        sigma
    };

    (delta_i, context3)
}

pub fn gg18_sign4(messages: Vec<GG18SignMsg3>, context: GG18SignContext3) -> (GG18SignMsg4, GG18SignContext4) {
    let mut delta_vec: Vec<Scalar<Secp256k1>> = Vec::new();

    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            delta_vec.push(context.delta_i.clone());
        } else {
            delta_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    let context4 = GG18SignContext4 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        message_hash: context.message_hash,
        threshold: context.threshold,
        party_id: context.party_id,
        y_sum: context.y_sum,
        sign_keys: context.sign_keys,
        decommit: context.decommit,
        bc1_vec: context.bc1_vec,
        m_b_gamma_rec_vec: context.m_b_gamma_rec_vec,
        sigma: context.sigma,
        delta_inv
    };

    (context4.decommit.clone(), context4)
}

pub fn gg18_sign5(messages: Vec<GG18SignMsg4>, context: GG18SignContext4) -> (GG18SignMsg5, GG18SignContext5) {
    let mut bc1_vec = context.bc1_vec.clone();
    let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();

    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            decommit_vec.push(context.decommit.clone());
        } else {

            decommit_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let decomm_i = decommit_vec.remove(context.threshold_index);
    bc1_vec.remove(context.threshold_index);
    let b_proof_vec = (0..context.m_b_gamma_rec_vec.len())
        .map(|i| &context.m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
    let r = SignKeys::phase4(&context.delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
        .expect("bad gamma_i decommit");

    // adding local g_gamma_i
    let r = r + decomm_i.g_gamma_i * context.delta_inv;

    let message_bn = BigInt::from_bytes(&context.message_hash);
    let local_sig =
        LocalSignature::phase5_local_sig(&context.sign_keys.k_i, &message_bn, &r, &context.sigma, &context.y_sum);

    let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
        local_sig.phase5a_broadcast_5b_zkproof();

    let context5 = GG18SignContext5 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        threshold: context.threshold,
        party_id: context.party_id,
        local_sig,
        phase5_com,
        phase_5a_decom,
        helgamal_proof,
        dlog_proof_rho,
        r
    };
    (context5.phase5_com.clone(), context5)

}

pub fn gg18_sign6(messages: Vec<GG18SignMsg5>, context: GG18SignContext5) -> (GG18SignMsg6, GG18SignContext6) {
    let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();

    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            commit5a_vec.push(context.phase5_com.clone());
        } else {
            commit5a_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let context6 = GG18SignContext6 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        threshold: context.threshold,
        party_id: context.party_id,
        local_sig: context.local_sig,
        phase_5a_decom: context.phase_5a_decom,
        helgamal_proof: context.helgamal_proof,
        dlog_proof_rho: context.dlog_proof_rho,
        r: context.r,
        commit5a_vec

    };

    ((context6.phase_5a_decom.clone(), context6.helgamal_proof.clone(),
    context6.dlog_proof_rho.clone()), context6)

}

pub fn gg18_sign7(messages: Vec<GG18SignMsg6>, context: GG18SignContext6) -> (GG18SignMsg7, GG18SignContext7) {
    let mut commit5a_vec = context.commit5a_vec;
    let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>,
    )> = Vec::new();

    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            decommit5a_and_elgamal_and_dlog_vec.push((
            context.phase_5a_decom.clone(),
            context.helgamal_proof.clone(),
            context.dlog_proof_rho.clone(),
        ));
        } else {
            decommit5a_and_elgamal_and_dlog_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let decommit5a_and_elgamal_and_dlog_vec_includes_i =
        decommit5a_and_elgamal_and_dlog_vec.clone();
    decommit5a_and_elgamal_and_dlog_vec.remove(context.threshold_index);
    commit5a_vec.remove(context.threshold_index);
    let phase_5a_decomm_vec = (0..(context.threshold - 1))
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let phase_5a_elgamal_vec = (0..(context.threshold - 1))
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].1.clone())
        .collect::<Vec<HomoELGamalProof<Secp256k1, Sha256>>>();
    let phase_5a_dlog_vec = (0..(context.threshold - 1))
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].2.clone())
        .collect::<Vec<DLogProof<Secp256k1, Sha256>>>();
    let (phase5_com2, phase_5d_decom2) = context.local_sig
        .phase5c(
            &phase_5a_decomm_vec,
            &commit5a_vec,
            &phase_5a_elgamal_vec,
            &phase_5a_dlog_vec,
            &context.phase_5a_decom.V_i,
            &context.r,
        )
        .expect("error phase5");

    let context7 = GG18SignContext7 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        threshold: context.threshold,
        party_id: context.party_id,
        local_sig: context.local_sig,
        phase_5a_decom: context.phase_5a_decom,
        decommit5a_and_elgamal_and_dlog_vec_includes_i,
        phase_5a_decomm_vec,
        phase5_com2,
        phase_5d_decom2
    };

    (context7.phase5_com2.clone(), context7)
}

pub fn gg18_sign8(messages: Vec<GG18SignMsg7>, context: GG18SignContext7) -> (GG18SignMsg8, GG18SignContext8) {
    let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            commit5c_vec.push(context.phase5_com2.clone());
        } else {
            commit5c_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let context8 = GG18SignContext8 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        threshold: context.threshold,
        party_id: context.party_id,
        local_sig: context.local_sig,
        phase_5a_decom: context.phase_5a_decom,
        decommit5a_and_elgamal_and_dlog_vec_includes_i: context.decommit5a_and_elgamal_and_dlog_vec_includes_i,
        phase_5a_decomm_vec: context.phase_5a_decomm_vec,
        phase_5d_decom2: context.phase_5d_decom2,
        commit5c_vec
    };

    (context8.phase_5d_decom2.clone(), context8)

}

pub fn gg18_sign9(messages: Vec<GG18SignMsg8>, context: GG18SignContext8) -> (GG18SignMsg9, GG18SignContext9) {
    let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            decommit5d_vec.push(context.phase_5d_decom2.clone());
        } else {

            decommit5d_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let phase_5a_decomm_vec_includes_i = (0..context.threshold)
        .map(|i| {
            context.decommit5a_and_elgamal_and_dlog_vec_includes_i[i as usize]
                .0
                .clone()
        })
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = context.local_sig
        .phase5d(
            &decommit5d_vec,
            &context.commit5c_vec,
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");

    let context9 = GG18SignContext9 {
        threshold: context.threshold,
        local_sig: context.local_sig
    };

    (s_i, context9)

}

pub fn gg18_sign10(messages: Vec<GG18SignMsg9>, context: GG18SignContext9) -> Vec<u8> {

    let mut s_i_vec: Vec<Scalar<Secp256k1>> = Vec::new();

    for i in 0..(context.threshold - 1) {
        s_i_vec.push(messages[i as usize].clone());
    }

    let sig = context.local_sig.output_signature(&s_i_vec).expect("verification failed");

    [sig.r.to_bytes().as_ref(), sig.s.to_bytes().as_ref()].concat()
}
