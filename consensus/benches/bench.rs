extern crate consensus;
use criterion::{
    criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, Throughput,
};
use crypto::*;
use serde::Serialize;
use types::{DataWithAcc, Replica, SignedShard, Certificate};
use util::io::to_bytes;
use consensus::{to_shards, get_size};

const _SEED: u64 = 42;
static TEST_POINTS: [usize; 7] = [3, 10, 20, 30, 50, 75, 100];
const BENCH_COUNT: usize = 10;

fn tree_get_dummy_acc<T: Serialize>(
    cx_num_nodes: Replica,
    data: &T,
) -> (Vec<Vec<u8>>, DataWithAcc) {
    let shards = to_shards(
        to_bytes(data),
        cx_num_nodes as usize,
    );
    let size = get_size(cx_num_nodes) as usize;
    let mut tree = vec![Vec::new(); (1 << size) + 1];
    for i in 0..cx_num_nodes as usize {
        tree[1 << size - 1 | i] = hash::ser_and_hash(&shards[i]).to_vec();
    }
    for i in 0..(1 << size - 1) - 1 {
        let index = (1 << size - 1) - 1 - i;
        tree[index] =
            hash::ser_and_hash(&(tree[index << 1].clone(), tree[index << 1 | 1].clone())).to_vec();
    }
    (
        shards,
        DataWithAcc {
            sign: Certificate::empty_cert(),
            tree: tree,
            size: size as Replica,
        },
    )
}

fn tree_check_dummy_share(sign: SignedShard) {
    let mut change = sign.index;
    change >>= 1;
    for i in 0..sign.chain.len() - 1 {
        if change & 1 == 0 {
            hash::ser_and_hash(&(sign.chain[i].1.clone(), sign.chain[i + 1].0.clone())).to_vec();
        } else {
            hash::ser_and_hash(&(sign.chain[i + 1].0.clone(), sign.chain[i].1.clone())).to_vec();
        }
        change >>= 1;
    }
}

fn test(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_propose_to_shards");
    BenchmarkGroup::sampling_mode(&mut group, criterion::SamplingMode::Flat);
    for n in &TEST_POINTS {
        let data = vec![0 as u8; *n];
        group.throughput(Throughput::Bytes(*n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(*n), n, |b, &n| {
            b.iter(|| tree_get_dummy_acc(n, &data))
        });
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(BENCH_COUNT);
    targets = test,
);
criterion_main!(benches);
