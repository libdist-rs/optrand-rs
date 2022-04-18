
use crypto::{DSSSecretKey, hash::EMPTY_HASH};
use types::{AggregatePVSS, Block, BlockBuilder, Certificate, DecompositionProof, PVSSVec, ProofBuilder, ProposalBuilder, ProposalData, ProtocolMsg, Result, Type, VoteBuilder};
use types_upstream::WireReady;

use super::super::OptRandStateMachine;

impl OptRandStateMachine {
    pub fn bench_deliver_propose(&self, 
    ) -> Result<ProtocolMsg>
    {
        Ok(ProtocolMsg::InvalidMessage)
    }

    pub fn bench_status(sk: &DSSSecretKey,
        num_faults: usize, 
        pvec: PVSSVec,
    ) -> Result<ProtocolMsg>
    {
        let vote = {
            let mut vote = VoteBuilder::default();
            vote.epoch(1)
            .prop_hash(EMPTY_HASH)
            .tp(Type::Sync)
            .build()
            .unwrap()
        };
        let mut cert = Certificate::new_cert(&vote, 0, &sk)?;
        let sig = cert.sigs.get(&0).unwrap().clone();
        for i in 1..=num_faults {
            cert.add_signature(i , sig.clone());
        }
        let msg = ProtocolMsg::Status(vote, cert, pvec);
        Ok(msg)
    }

    pub fn bench_direct_propose(&self, 
        agg_vec: AggregatePVSS, 
        pi: DecompositionProof
    ) -> Result<ProtocolMsg>
    {
        // Build the proposal 
        let parent = Block::genesis();
        let block = {
            let mut block_builder = BlockBuilder::default();
            block_builder
                .height(parent.height() + 1) 
                .parent_hash(*parent.hash()) 
                .aggregate_pvss(agg_vec)
                .aggregate_proof(pi)
                .proposer(self.config.id)
                .build()?
        };
        let prop = {
            let mut prop_builder = ProposalBuilder::default();
            prop_builder
                .data(ProposalData {
                    epoch: 1,
                    highest_cert_data: self.highest_certified_data().clone(),
                    highest_cert:self.highest_certificate().clone(),
                    block,
                })
                .codewords(None)
                .witnesses(None)
                .build()
                .map_err(|e| format!("Proposal Builder Error: {}", e))?
                .init()
        };
        let proof = {
            let (acc, _codes, _wits) = self.prop_acc_builder.build(&prop)?;
            let sign = Certificate::new_cert(&(self.epoch, acc.clone()),self.config.id, &self.sk)?;
            let mut proof = ProofBuilder::default(); 
            proof
                .acc(acc)
                .sign(sign)
                .build()
                .map_err(|e| format!("Proof Build Error: {}", e))?
        };
        // Multicast the proposal
        let msg = self.new_proposal_msg(prop.clone(), proof.clone())?;
        Ok(msg.1.as_ref().clone())
    }
}