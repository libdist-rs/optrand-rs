use super::context::Context;
use crypto::*;
use crypto_lib::PublicKey;
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use types::{DataWithAcc, Replica, SignedShard, Certificate, Vote};
use util::io::to_bytes;

pub fn to_shards(data: &[u8], num_nodes: usize) -> Vec<Vec<u8>> {
    let num_data_shards = (num_nodes/4) + 1;// (num_nodes/4) + 1
    let num_faults = num_nodes - num_data_shards;
    let shard_size = (data.len() + num_data_shards - 1) / num_data_shards;
    let mut data_with_suffix = data.to_vec();
    let suffix_size = shard_size * num_data_shards - data.len();
    for _ in 0..suffix_size {
        data_with_suffix.push(suffix_size as u8)
    }
    let mut result = Vec::with_capacity(num_nodes);
    for shard in 0..num_data_shards {
        result.push(data_with_suffix[shard * shard_size..(shard + 1) * shard_size].to_vec());
    }
    for _shard in 0..num_faults {
        result.push(vec![0; shard_size]);
    }
    let r = ReedSolomon::new(num_data_shards, num_faults).unwrap();
    r.encode(&mut result).unwrap();
    result
}

pub fn from_shards(mut data: Vec<Option<Vec<u8>>>, num_nodes: usize, num_faults: usize) -> Vec<u8> {
    let num_data_shards = num_nodes - num_faults;
    let r = ReedSolomon::new(num_data_shards, num_faults).unwrap();
    r.reconstruct(&mut data).unwrap();
    let mut result = Vec::with_capacity(num_data_shards * data[0].as_ref().unwrap().len());
    for shard in 0..num_data_shards {
        result.append(&mut data[shard].clone().unwrap());
    }
    result.truncate(result.len() - *result.last().unwrap() as usize);
    result
}


#[cfg(test)]
mod tests {
    #[test]
    fn shards() {
        const SIZE: usize = 1024 * 1024;
        let mut array = [0 as u8; SIZE];
        for i in 0..SIZE {
            array[i] = crypto::rand::random();
        }
        let shards = super::to_shards(&array, 4);
        let mut received: Vec<_> = shards.iter().cloned().map(Some).collect();
        received[0] = None;
        let reconstructed = super::from_shards(received, 4, 1);
        assert_eq!(array.to_vec(), reconstructed);
    }
}

pub fn get_size(num_nodes: Replica) -> Replica {
    let mut n: Replica = 1;
    // num_nodes.next_power_of_two(num_nodes).unwrap()
    while 1 << n < num_nodes {
        n += 1;
    }
    n + 1
}

/// Check if the accumulator is signed correctly
pub fn check_valid(new_acc: &[Vec<u8>], acc: &DataWithAcc, pk: &crypto_lib::PublicKey) -> bool {
    if new_acc  != acc.tree {
        return false;
    } 
    if !pk.verify(&hash::ser_and_hash(&acc.tree[1]), &acc.sign.votes[0].auth) {
        return false;
    }
    true
}

/// get_acc returns shards for every node and the signed merkle tree root
pub fn get_acc<T: Serialize>(cx: &Context, data: &T) -> (Vec<Vec<u8>>, DataWithAcc) {
    let shards = to_shards(
        &to_bytes(data),
        cx.num_nodes(),
    );
    let size = get_size(cx.num_nodes()) as usize;
    let mut tree = vec![Vec::new(); (1 << size) + 1];
    for i in 0..cx.num_nodes() {
        tree[1 << size - 1 | i] = hash::ser_and_hash(&shards[i]).to_vec();
    }
    for i in 0..(1 << size - 1) - 1 {
        let index = (1 << size - 1) - 1 - i;
        tree[index] =
            hash::ser_and_hash(&(tree[index << 1].clone(), tree[index << 1 | 1].clone())).to_vec();
    }
    let mut cert = Certificate::empty_cert();
    cert.msg = hash::ser_and_hash(&tree[1]).to_vec();
    cert.add_vote(
        Vote{
            origin: cx.id(),
            auth: cx.my_secret_key.sign(&cert.msg).unwrap(),
        }
    );
    (
        shards,
        DataWithAcc {
            sign: cert,
            tree,
            size,
        },
    )
}

/// get_acc returns shards for every node and the signed merkle tree root
pub fn get_acc_with_shard<T: Serialize>(cx: &Context, data: &T, auth: SignedShard) -> (Vec<Vec<u8>>, DataWithAcc) {
    let shards = to_shards(
        &to_bytes(data),
        cx.num_nodes() as usize,
    );
    let size = get_size(cx.num_nodes()) as usize;
    let mut tree = vec![Vec::new(); (1 << size) + 1];
    for i in 0..cx.num_nodes() {
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
            sign: auth.sign.clone(),
            tree,
            size,
        },
    )
}

pub fn get_tree<T: Serialize>(n:Replica,data: &T) -> Vec<Vec<u8>> {
    let shards = to_shards(
        &to_bytes(data),
        n,
    );
    let size = get_size(n) as usize;
    let mut tree = vec![Vec::new(); (1 << size) + 1];
    for i in 0..n {
        tree[1 << size - 1 | i] = hash::ser_and_hash(&shards[i]).to_vec();
    }
    for i in 0..(1 << size - 1) - 1 {
        let index = (1 << size - 1) - 1 - i;
        tree[index] =
            hash::ser_and_hash(&(tree[index << 1].clone(), tree[index << 1 | 1].clone())).to_vec();
    }
    tree
}


pub fn get_sign(acc: &DataWithAcc, origin: Replica) -> SignedShard {
    let mut vec = Vec::with_capacity(acc.size as usize - 1);
    let mut p = (1 << acc.size - 1 | origin) as usize;
    for _ in 0..acc.size - 1 {
        vec.push((acc.tree[p ^ 1].clone(), acc.tree[p >> 1].clone()));
        p >>= 1;
    }
    SignedShard {
        sign: acc.sign.clone(),
        start: acc.tree[(1 << acc.size - 1 | origin) as usize].clone(),
        index: origin,
        chain: vec,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShareGatherer {
    pub size: Replica,
    pub reference: Option<(Vec<u8>, Vec<u8>)>,
    pub shard: Vec<Option<Vec<u8>>>,
    pub shard_num: Replica,
}

impl ShareGatherer {
    pub fn new(num_nodes: Replica) -> Self {
        ShareGatherer {
            size: num_nodes,
            reference: None,
            shard: vec![None; num_nodes as usize],
            shard_num: 0,
        }
    }

    /// Clear all the shards
    pub fn clear(&mut self) {
        self.reference = None;
        self.shard = vec![None; self.size as usize];
        self.shard_num = 0;
    }

    /// Add a share to the accumulator when a shard is given 
    pub fn add_share(
        &mut self,
        sh: Vec<u8>,
        n: Replica,
        pk: &PublicKey,
        sign: SignedShard,
    ) {
        if self.shard[n as usize].is_some() {
            return;
        }
        // The hash should match with the sign.
        if hash::ser_and_hash(&sh).to_vec() != sign.start {
            panic!("[WARN] The hash of the shard does not match.");
        }
        if !pk.verify(
            &hash::ser_and_hash(&sign.chain.last().unwrap().1),
            &sign.sign.votes[0].auth,
        ) {
            panic!("[WARN] The signature of the shard does not match.");
        }
        if self.reference.is_none() {
            self.reference = Some((
                hash::ser_and_hash(&sign.chain.last().unwrap().1).to_vec(),
                sign.sign.votes[0].auth.clone(),
            ));
        } else {
            if self.reference.as_ref().unwrap().1 != sign.sign.votes[0].auth {
                panic!("[WARN] Equivocation detected.");
                // TODO: Broadcast the blame.
            }
        }
        // The share should match with the accumulator.
        let mut change = sign.index;
        change >>= 1;
        for i in 0..sign.chain.len() - 1 {
            let h = if change & 1 == 0 {
                hash::ser_and_hash(&(sign.chain[i].1.clone(), sign.chain[i + 1].0.clone())).to_vec()
            } else {
                hash::ser_and_hash(&(sign.chain[i + 1].0.clone(), sign.chain[i].1.clone())).to_vec()
            };
            if h != sign.chain[i + 1].1 {
                println!("[WARN] Accumulator value does not match.");
                debug_assert!(false);
                return;
            }
            change >>= 1;
        }
        self.shard[n as usize] = Some(sh);
        self.shard_num += 1;
    }

    pub fn reconstruct(&mut self, num_nodes: Replica) -> Option<Vec<u8>> {
        let num_faults = (num_nodes/4) + 1;
        if self.shard_num < num_nodes - num_faults {
            return None;
        }
        Some(from_shards(
            self.shard.clone(),
            num_nodes as usize,
            num_faults as usize,
        ))
    }
}

