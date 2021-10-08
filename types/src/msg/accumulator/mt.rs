use std::{fmt::Debug, marker::PhantomData};
use crypto::hash;
use serde::{Deserialize, Serialize};
use crate::{Codeword, Replica, Witness, error::Error, generate_codewords};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MTAccumulator<T> {
    /// The merkle tree root
    pub(crate) hash: Vec<u8>,
    _x: PhantomData<T>,
}

impl<T> Eq for MTAccumulator<T> where T: PartialEq {}

impl<T> std::fmt::Display for MTAccumulator<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for b in &self.hash {
            write!(f, "{:x}", b)?;
        }
        Ok(())
    }
}

pub struct MTAccumulatorBuilder<T> {
    pub(crate) n: Option<usize>,
    pub(crate) f: Option<usize>,
    _x: PhantomData<T>,
}

impl<T> MTAccumulatorBuilder<T> 
where T: Serialize,
{
    pub fn new() -> Self {
        Self {
            n: None,
            f: None,
            _x: PhantomData,
        }
    }

    pub fn set_n(&mut self, n:usize) -> &mut Self {
        self.n = Some(n);
        self
    }

    pub fn set_f(&mut self, f:usize) -> &mut Self {
        self.f = Some(f);
        self
    }

    pub fn build(&self, obj: &T) -> Result<(MTAccumulator<T>, Vec<Codeword<T>>, Vec<Witness<T>>), Error> {
        let bytes = bincode::serialize(obj)?;
        let n = *self.n.as_ref().ok_or(Error::BuilderUnsetField("n"))?;
        let f = *self.f.as_ref().ok_or(Error::BuilderUnsetField("f"))?;

        let codewords = generate_codewords(&bytes, n, f)?;
        let tree = Self::get_tree_from_codewords(&codewords)?;
        let acc = MTAccumulator {
            hash: tree[1].clone(),
            _x: PhantomData,
        };
        let wits = self.get_all_witness(&tree)?;
        Ok((acc, codewords, wits))
    }

    pub fn check(&self, obj: &T, acc: &MTAccumulator<T>) -> Result<(), Error> {
        let bytes = bincode::serialize(obj)?;
        let n = *self.n.as_ref().ok_or(Error::BuilderUnsetField("n"))?;
        let f = *self.f.as_ref().ok_or(Error::BuilderUnsetField("f"))?;

        let codewords = generate_codewords(&bytes, n, f)?;
        let tree = Self::get_tree_from_codewords(&codewords)?;
        let new_acc = &tree[1];
        if *new_acc == acc.hash {
            Ok(())
        } else {
            Err(Error::ShardAccumulatorMismatch)
        }
    }

    pub fn verify_witness(&self, 
        acc: &MTAccumulator<T>,
        wit: &Witness<T>, 
        code: &Codeword<T>,
        node: Replica
    ) -> Result<(), Error> 
    {
        // The hash of the code should be the hash in the witness Merkle proof
        if hash::ser_and_hash(code).to_vec() != wit.start() {
            return Err(Error::ShardLeafError);
        }
        // Check the Merkle proof
        let mut change = node;
        change >>= 1;
        for i in 0..wit.chain().len() - 1 {
            let h = if change & 1 == 0 {
                hash::ser_and_hash(&(wit.chain()[i].1.clone(), wit.chain()[i + 1].0.clone())).to_vec()
            } else {
                hash::ser_and_hash(&(wit.chain()[i + 1].0.clone(), wit.chain()[i].1.clone())).to_vec()
            };
            if h != wit.chain()[i + 1].1 {
                return Err(Error::ShardMerkleError);
            }
            change >>= 1;
        }
        let t1 = &wit.chain().last().unwrap().1;
        if t1 != &acc.hash {
            return Err(Error::ShardAccumulatorMismatch);
        }
        Ok(())
    }
}


/// get_size() returns the highest 2^x such that 2^x > n
pub fn get_size(num_nodes: Replica) -> Replica {
    if num_nodes < 2 {
        return 2;
    }
    (Replica::BITS - num_nodes.next_power_of_two().leading_zeros()) as Replica
}

// /// Check if the shards are signed correctly by the accumulator
// pub fn check_valid(new_acc: &[Vec<u8>], acc: &DataWithAcc, pk: &crypto_lib::PublicKey) -> bool {
//     if new_acc  != acc.tree {
//         return false;
//     } 
//     if !pk.verify(&hash::ser_and_hash(&acc.tree[1]), &acc.sign.votes[0].auth) {
//         return false;
//     }
//     true
// }

// /// get_acc returns shards for every node and the signed merkle tree root
// pub fn get_acc<T: Serialize>(cx: &Context, data: &T) -> (Vec<Vec<u8>>, DataWithAcc) {
//     let shards = to_shards(
//         to_bytes(data),
//         cx.num_nodes(),
//         cx.num_faults()/2 +1,
//     );
//     let size = get_size(cx.num_nodes()) as usize;
//     let mut tree = vec![Vec::new(); (1 << size) + 1];
//     for i in 0..cx.num_nodes() {
//         tree[1 << size - 1 | i] = hash::ser_and_hash(&shards[i]).to_vec();
//     }
//     for i in 0..(1 << size - 1) - 1 {
//         let index = (1 << size - 1) - 1 - i;
//         tree[index] =
//             hash::ser_and_hash(&(tree[index << 1].clone(), tree[index << 1 | 1].clone())).to_vec();
//     }
//     let mut cert = Certificate::empty_cert();
//     cert.msg = hash::ser_and_hash(&tree[1]).to_vec();
//     cert.add_vote(
//         Vote{
//             origin: cx.id(),
//             auth: cx.my_secret_key.sign(&cert.msg).unwrap(),
//         }
//     );
//     (
//         shards,
//         DataWithAcc {
//             sign: cert,
//             tree,
//             size,
//         },
//     )
// }

// /// get_acc returns shards for every node and the signed merkle tree root
// pub fn get_acc_with_shard<T: Serialize>(cx: &Context, data: &T, auth: SignedShard) -> (Vec<Vec<u8>>, DataWithAcc) {
//     let shards = to_shards(
//         to_bytes(data),
//         cx.num_nodes(),
//         cx.num_faults()/2 + 1
//     );
//     let size = get_size(cx.num_nodes()) as usize;
//     let mut tree = vec![Vec::new(); (1 << size) + 1];
//     for i in 0..cx.num_nodes() {
//         tree[1 << size - 1 | i] = hash::ser_and_hash(&shards[i]).to_vec();
//     }
//     for i in 0..(1 << size - 1) - 1 {
//         let index = (1 << size - 1) - 1 - i;
//         tree[index] =
//             hash::ser_and_hash(&(tree[index << 1].clone(), tree[index << 1 | 1].clone())).to_vec();
//     }
//     (
//         shards,
//         DataWithAcc {
//             sign: auth.sign.clone(),
//             tree,
//             size,
//         },
//     )
// }

// /// get_tree returns the shards 
// pub fn get_tree<T: Serialize>(n:Replica,data: &T) -> Vec<Vec<u8>> {
//     let shards = to_shards(
//         to_bytes(data),
//         n,
//         n/4+1
//     );
//     let size = get_size(n) as usize;
//     let mut tree = vec![Vec::new(); (1 << size) + 1];
//     for i in 0..n {
//         tree[1 << size - 1 | i] = hash::ser_and_hash(&shards[i]).to_vec();
//     }
//     for i in 0..(1 << size - 1) - 1 {
//         let index = (1 << size - 1) - 1 - i;
//         tree[index] =
//             hash::ser_and_hash(&(tree[index << 1].clone(), tree[index << 1 | 1].clone())).to_vec();
//     }
//     tree
// }

// /// Get the signature
// pub fn get_sign(acc: &DataWithAcc, origin: Replica) -> SignedShard {
//     let mut vec = Vec::with_capacity(acc.size as usize - 1);
//     let mut p = (1 << acc.size - 1 | origin) as usize;
//     for _ in 0..acc.size - 1 {
//         vec.push((acc.tree[p ^ 1].clone(), acc.tree[p >> 1].clone()));
//         p >>= 1;
//     }
//     SignedShard {
//         sign: acc.sign.clone(),
//         start: acc.tree[(1 << acc.size - 1 | origin) as usize].clone(),
//         index: origin,
//         chain: vec,
//     }
// }

// #[derive(Serialize, Deserialize, Debug, Clone, Default)]
// pub struct ShareGatherer {
//     pub size: Replica,
//     pub reference: Option<(Vec<u8>, Vec<u8>)>,
//     pub shard: Vec<Option<Vec<u8>>>,
//     pub shard_num: Replica,
// }

// impl ShareGatherer {
//     pub fn new(num_nodes: Replica) -> Self {
//         ShareGatherer {
//             size: num_nodes,
//             reference: None,
//             shard: vec![None; num_nodes as usize],
//             shard_num: 0,
//         }
//     }

//     /// Clear all the shards
//     pub fn clear(&mut self) {
//         self.reference = None;
//         self.shard = vec![None; self.size as usize];
//         self.shard_num = 0;
//     }

//     /// Add a share to the accumulator when a shard is given 
//     pub fn add_share(
//         &mut self,
//         sh: Vec<u8>,
//         n: Replica,
//         pk: &PublicKey,
//         sign: SignedShard,
//     ) {
//         if self.shard[n as usize].is_some() {
//             return;
//         }
//         // The hash should match with the sign.
//         if hash::ser_and_hash(&sh).to_vec() != sign.start {
//             panic!("[WARN] The hash of the shard does not match.");
//         }
//         if !pk.verify(
//             &hash::ser_and_hash(&sign.chain.last().unwrap().1),
//             &sign.sign.votes[0].auth,
//         ) {
//             panic!("[WARN] The signature of the shard does not match.");
//         }
//         if self.reference.is_none() {
//             self.reference = Some((
//                 hash::ser_and_hash(&sign.chain.last().unwrap().1).to_vec(),
//                 sign.sign.votes[0].auth.clone(),
//             ));
//         } else {
//             if self.reference.as_ref().unwrap().1 != sign.sign.votes[0].auth {
//                 panic!("[WARN] Equivocation detected.");
//                 // TODO: Broadcast the blame.
//             }
//         }
//         // The share should match with the accumulator.
//         let mut change = sign.index;
//         change >>= 1;
//         for i in 0..sign.chain.len() - 1 {
//             let h = if change & 1 == 0 {
//                 hash::ser_and_hash(&(sign.chain[i].1.clone(), sign.chain[i + 1].0.clone())).to_vec()
//             } else {
//                 hash::ser_and_hash(&(sign.chain[i + 1].0.clone(), sign.chain[i].1.clone())).to_vec()
//             };
//             if h != sign.chain[i + 1].1 {
//                 println!("[WARN] Accumulator value does not match.");
//                 debug_assert!(false);
//                 return;
//             }
//             change >>= 1;
//         }
//         self.shard[n as usize] = Some(sh);
//         self.shard_num += 1;
//     }

//     pub fn reconstruct(&mut self, num_nodes: Replica) -> Option<Vec<u8>> {
//         let num_faults = (num_nodes/4) + 1;
//         if self.shard_num < num_nodes - num_faults {
//             return None;
//         }
//         Some(from_shards(
//             self.shard.clone(),
//             num_nodes as usize,
//         ))
//     }
// }

