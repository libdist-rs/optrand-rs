use std::collections::VecDeque;

use config::Node;
use crypto::{hash::EMPTY_HASH, rand::Rng};
use types::{AggregatePVSS, Block, BlockBuilder, Certificate, DecompositionProof, DeliverData, DirectProposal, MTAccumulatorBuilder, Proof, ProofBuilder, ProposalBuilder, ProposalData, ProtocolMsg, RespCertData, RespCertProposal, Signature, Type, Vote, VoteBuilder, reed_solomon_threshold};
use util::io::to_bytes;

use super::TEST_POINTS;

fn _get_test_agg<R>(mut configs: VecDeque<Node>, rng: &mut R) -> (AggregatePVSS, DecompositionProof) 
where R: Rng,
{
    let (c1, c2) = (configs.pop_front().unwrap(), configs.pop_front().unwrap());
    let (sk1, sk2) = (c1.get_secret_key(), c2.get_secret_key());
    let (pvec1, pvec2) = (
        c1.pvss_ctx.generate_shares(&sk1, rng),
        c2.pvss_ctx.generate_shares(&sk2, rng),
    );
    let indices = [0 as usize,1];
    let pvec = [pvec1, pvec2].to_vec();
    c1.pvss_ctx.aggregate(&indices, pvec)
}

pub fn dummy_vote(_n:usize) -> Vote {
    let mut vote = VoteBuilder::default();
    let vote = vote.epoch(1).prop_hash(EMPTY_HASH).tp(Type::Sync).build().unwrap();

    vote
}

pub fn dummy_certificate(n:usize) -> Certificate<Vote> 
{
    let sk = crypto_lib::Keypair::generate_ed25519();
    let vote = dummy_vote(n);
    let mut cert = Certificate::new_cert(&vote, 1, &sk).unwrap();
    for i in 1..n {
        let sig = Signature::new_signature(&vote, &sk).unwrap();
        cert.add_signature(i, sig);
    }
    cert
}

pub fn dummy_block(n:usize) -> Block {
    let (_,y,z) = crypto::test_messages(n);
    let mut block = BlockBuilder::default();
    block
        .aggregate_proof(z)
        .aggregate_pvss(y)
        .parent_hash(EMPTY_HASH)
        .proposer(1)
        .height(1)
        .build()
        .unwrap()
}

pub fn dummy_direct_proposal(n:usize) -> DirectProposal 
{
    let mut prop = ProposalBuilder::default();
    prop.witnesses(None)
    .data(ProposalData{
        epoch: 1,
        highest_cert: dummy_certificate(n),
        block: dummy_block(n),
        highest_cert_data: dummy_vote(n),
    })
    .codewords(None)
    .build().unwrap()
}

pub fn dummy_direct_proposal_proof(n:usize) -> Proof<DirectProposal> 
{
    //     let (acc, _codes, _wits) = self.prop_acc_builder.build(&prop)?;
    let prop = dummy_direct_proposal(n);
    let mut prop_acc_builder = MTAccumulatorBuilder::new();
    let (acc, _,_) = prop_acc_builder.set_n(n)
        .set_f(reed_solomon_threshold(n)-1)
        .build(&prop).unwrap();
    let sk = crypto_lib::Keypair::generate_ed25519();
    // let proof = {
        let sign = Certificate::new_cert(&(1, acc.clone()),1, &sk).unwrap();
    //     let mut proof = ProofBuilder::default(); 
    //     proof
    //         .acc(acc)
    //         .sign(sign)
    //         .build()
    //         .map_err(|e| format!("Proof Build Error: {}", e))?
    // };
    let mut proof = ProofBuilder::default();
    proof
        .acc(acc)
        .sign(sign)
        .build().unwrap()
}

#[test]
fn bench_msgs() -> types::Result<()> {
    // let mut configs = Vec::with_capacity(TEST_POINTS.len());
    // for n in TEST_POINTS {
    //     configs.push(generate_test_configs(n, (n-1)/2, 50, 5000)?);
    // }
    // Bench propose messages
    for i in 0..TEST_POINTS.len() {
        let n = TEST_POINTS[i];
        let msg = ProtocolMsg::Propose(dummy_direct_proposal(n), dummy_direct_proposal_proof(n));
        println!("Direct Proposal size for {}: {}", n, to_bytes(&msg).len());
    }
    // Bench Status
    for i in 0..TEST_POINTS.len() {
        let n = TEST_POINTS[i];
        let (x,_,_) = crypto::test_messages(n);
        let msg = ProtocolMsg::Status(dummy_vote(n),dummy_certificate(n),x);
        println!("Status size for {}: {}", n, to_bytes(&msg).len());
    }
    // Bench DeliverPropose
    for i in 0..TEST_POINTS.len() {
        let n = TEST_POINTS[i];
        let msg = ProtocolMsg::DeliverPropose(1, dummy_deliver_propose_data(n));
        println!("Deliver Propose size for {}: {}", n, to_bytes(&msg).len());
    }

    // Bench RespCert
    for i in 0..TEST_POINTS.len() {
        let n = TEST_POINTS[i];
        let (x,y)= dummy_resp_cert_prop(n);
        let msg = ProtocolMsg::RespCert(x,y);
        println!("RespCert size for {}: {}", n, to_bytes(&msg).len());
    }

    // Bench DeliverRespCert
    for i in 0..TEST_POINTS.len() {
        let n = TEST_POINTS[i];
        let msg = ProtocolMsg::DeliverRespCert(1, dummy_resp_cert_deliver_data(n));
        println!("BeaconReady size for {}: {}", n, to_bytes(&msg).len());
    }

    // Bench BeaconReady
    let (x,y) = crypto::test_beacon();
    for i in 0..TEST_POINTS.len() {
        let n = TEST_POINTS[i];
        let msg = ProtocolMsg::BeaconReady(1, x.clone());
        println!("BeaconReady size for {}: {}", n, to_bytes(&msg).len());
    }
    // Bench BeaconShare
    for i in 0..TEST_POINTS.len() {
        let n = TEST_POINTS[i];
        let msg = ProtocolMsg::BeaconShare(1, y.clone());
        println!("BeaconShare size for {}: {}", n, to_bytes(&msg).len());
    }
    Ok(())
}

fn dummy_resp_cert_deliver_data(n: usize) -> DeliverData<types::Proposal<RespCertData>> {
    let (mut prop, proof) = dummy_resp_cert_prop(n);
    let mut prop_acc_builder = MTAccumulatorBuilder::new();
    prop_acc_builder.set_f(reed_solomon_threshold(n)-1)
    .set_n(n);
    let codes = prop.get_codewords(&prop_acc_builder).unwrap();
    let wits = prop.get_witnesses(&prop_acc_builder).unwrap();
    // Send my share to all the nodes first
    let deliver_data_my_share = DeliverData{
        acc: proof.acc().clone(),
        sign: proof.sign().clone(),
        shard: codes[0].clone(),
        wit: wits[0].clone(),
    };

    deliver_data_my_share
}

fn dummy_resp_cert_prop(n: usize) -> (types::Proposal<types::RespCertData>, Proof<RespCertProposal>) {
    let mut resp_cert_acc_builder = MTAccumulatorBuilder::new();
    resp_cert_acc_builder.set_f(reed_solomon_threshold(n)-1)
    .set_n(n);
    let sk = crypto_lib::Keypair::generate_ed25519();
    let cert = dummy_certificate(n);
        let prop = {
            let mut prop_builder = ProposalBuilder::default();
            prop_builder
                .data(RespCertData {
                    vote: dummy_vote(n),
                    cert: cert,
                })
                .codewords(None)
                .witnesses(None)
                .build()
                .map_err(|e| format!("Proposal Builder Error: {}", e)).unwrap()
        };
        let proof = {
            let (acc, _codes, _wits) = resp_cert_acc_builder.build(&prop).unwrap();
            let sign = Certificate::new_cert(&(1, acc.clone()),1, &sk).unwrap();
            let mut proof = ProofBuilder::default(); 
            proof
                .acc(acc)
                .sign(sign)
                .build()
                .map_err(|e| format!("Proof Build Error: {}", e)).unwrap()
        };
    
    (prop, proof)
}

pub fn dummy_deliver_propose_data(n: usize) -> types::DeliverData<types::Proposal<ProposalData>> {
    let mut prop = dummy_direct_proposal(n);
    let proof = dummy_direct_proposal_proof(n);
    let mut prop_acc_builder = MTAccumulatorBuilder::new();
    prop_acc_builder.set_f(reed_solomon_threshold(n)-1)
    .set_n(n);
    let codes = prop.get_codewords(&prop_acc_builder).unwrap();
    let wits = prop.get_witnesses(&prop_acc_builder).unwrap();
    // Send my share to all the nodes first
    let deliver_data_my_share = DeliverData{
        acc: proof.acc().clone(),
        sign: proof.sign().clone(),
        shard: codes[0].clone(),
        wit: wits[0].clone(),
    };

    deliver_data_my_share
}