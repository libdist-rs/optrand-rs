use std::{fmt::Debug, marker::PhantomData};
use crypto::hash;
use serde::{Deserialize, Serialize};
use crate::{Codeword, Replica, Witness, error::Error, generate_codewords};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
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
        sh_for: Replica
    ) -> Result<(), Error> 
    {
        // The hash of the code should be the hash in the witness Merkle proof
        if hash::ser_and_hash(code).to_vec() != wit.start() {
            return Err(Error::ShardLeafError);
        }
        // Check the Merkle proof
        let mut change = sh_for;
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