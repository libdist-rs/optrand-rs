use std::sync::Arc;

use crypto::{DSSPublicKey, DSSSecretKey, std_rng};
use fnv::FnvHashMap;
use tokio::sync::mpsc::UnboundedSender;
use types::{AggregatePVSS, DbsContext, DecompositionProof, PVSSVec, Replica};

pub type PvecReceiver = tokio::sync::mpsc::Receiver<PVSSVec>;
pub type ThreadSender = tokio::sync::mpsc::UnboundedSender<ThreadSendMsg>;
pub type ThreadReceiver = tokio::sync::mpsc::UnboundedReceiver<ThreadRecvMsg>;

pub fn spawn_generator_thread(
    num_nodes: usize,
    dbs_ctx: DbsContext,
    sk: DSSSecretKey,
) -> PvecReceiver
{
    let (ch_in, ch_out) = tokio::sync::mpsc::channel(num_nodes);
    tokio::spawn(async move {
        let mut rng= std_rng();
        loop {
            let pvec = dbs_ctx.generate_shares(&sk, &mut rng);
            ch_in.send(pvec).await
                .expect("Failed to send a freshly generated pvec");
        }
    });
    ch_out
}

#[derive(Debug)]
pub enum ThreadSendMsg {
    NewContribution(Replica, PVSSVec),
    NewAggregateSharing(Replica, AggregatePVSS, DecompositionProof),
}

#[derive(Debug, Clone)]
pub enum ThreadRecvMsg {
    AggregateReady(AggregatePVSS, DecompositionProof),
    VerifiedAggregateSharing(Replica, AggregatePVSS),
}

/// The job of this thread is to take shares and verify them
pub fn spawn_leader_thread(
    num_faults: usize,
    dbs_ctx: DbsContext,
    pk_map: FnvHashMap<Replica, DSSPublicKey>,
) -> (ThreadSender, ThreadReceiver)
{
    let dbs_ctx = Arc::new(dbs_ctx);
    let pk_map = Arc::new(pk_map);
    let (sh_sender, mut sh_recv) = tokio::sync::mpsc::unbounded_channel();
    let (agg_sender, agg_recv) = tokio::sync::mpsc::unbounded_channel();
    let (internal_send, mut internal_recv) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buffer = Vec::with_capacity(num_faults+1);
        let mut indices = Vec::with_capacity(num_faults + 1);
        loop {
            tokio::select! {
                ev = sh_recv.recv() => {
                    let ev = ev.unwrap();
                    if let ThreadSendMsg::NewContribution(from, sh) = ev
                    {
                        let dbs_ctx = dbs_ctx.clone();
                        let pk_map = pk_map.clone();
                        let internal_send = internal_send.clone();
                        let _task = Box::pin(tokio::task::spawn_blocking(move || {
                            handle_new_contribution(
                                dbs_ctx, 
                                pk_map, 
                                from, 
                                sh, 
                                internal_send
                            )
                        }));
                        continue;
                    }
                    if let ThreadSendMsg::NewAggregateSharing(from, agg, decom) = ev {
                        let agg_sender = agg_sender.clone();
                        let dbs_ctx = dbs_ctx.clone();
                        let pk_map = pk_map.clone();
                        tokio::task::spawn_blocking(move || {
                            handle_new_aggregation(
                                dbs_ctx, 
                                pk_map, 
                                agg, 
                                decom, 
                                from, 
                                agg_sender
                            )
                        });
                    }
                },
                job_opt = internal_recv.recv() => {
                    match job_opt.unwrap() {
                        InternalMsg::CorrectPVec(from, pvec) => {
                        buffer.push(pvec);
                        indices.push(from);
                        let (pvec, inds) = if buffer.len() > num_faults {
                            (
                                std::mem::take(&mut buffer), 
                                std::mem::take(&mut indices)
                            )
                        } else {
                            continue;
                        };
                        let data = dbs_ctx.aggregate(&inds, pvec);
                        agg_sender.send(
                            ThreadRecvMsg::AggregateReady(
                                data.0, 
                                data.1
                            )
                        ).expect("Failed to send aggregated values");
                        },
                        // _ => continue,
                    }
                }
            }
        }
    });
    (sh_sender, agg_recv)
}

#[derive(Debug)]
enum InternalMsg {
    CorrectPVec(Replica, PVSSVec),
}

fn handle_new_contribution(
    dbs_ctx: Arc<DbsContext>, 
    pk_map: Arc<FnvHashMap<Replica, DSSPublicKey>>,
    from: Replica,
    sh: PVSSVec,
    internal_send: UnboundedSender<InternalMsg>,
)
{
    if let None = dbs_ctx.verify_sharing(&sh, &pk_map[&from]) {
        internal_send.send(InternalMsg::CorrectPVec(from, sh)).unwrap();
    } else {
        log::warn!("Got an invalid pvec from {}", from);
        
    }
}

fn handle_new_aggregation(dbs_ctx: Arc<DbsContext>, 
    pk_map: Arc<FnvHashMap<Replica, DSSPublicKey>>,
    agg: AggregatePVSS,
    decom: DecompositionProof,
    from: Replica,
    agg_sender: tokio::sync::mpsc::UnboundedSender<ThreadRecvMsg>,
)
{
    if let Some(x) = dbs_ctx.pverify(&agg) {
        log::warn!("Got an invalid agg sharing from {} with {:?}", from, x);
        return;
    } 
    if let Some(x) = dbs_ctx.decomp_verify(&agg, &decom, &pk_map) {
        log::warn!("Got an invalid decomp from {} with {:?}", from, x);
        return;
    }
    agg_sender.send(
        ThreadRecvMsg::VerifiedAggregateSharing(
            from, 
            agg
        )
    ).expect("Failed to send verified agg sharing");
}