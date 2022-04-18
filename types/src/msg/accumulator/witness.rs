use std::marker::PhantomData;
use serde::{Serialize, Deserialize};
use crypto::hash::{self};

use crate::{Codeword, MTAccumulatorBuilder, Replica, error::Error, get_size};

#[derive(Clone, Serialize, Deserialize)]
pub struct Witness<T> {
    start: Vec<u8>,
    chain: Vec<(Vec<u8>, Vec<u8>)>,
    node: Replica,
    _x: PhantomData<T>,
}

impl<T> Witness<T> {
    pub fn node(&self) -> Replica {
        self.node
    }

    pub fn chain(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.chain
    }

    pub fn start(&self) -> &[u8] {
        &self.start
    }
}

impl<T> std::fmt::Debug for Witness<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"{{ Start: 0x")?;
        for b in &self.start {
            write!(f, "{:x}", b)?;
        }
        write!(f, ", ")?;
        write!(f,"Chain: ")?;
        for (b1, b2) in &self.chain {
            write!(f, "(0x")?;
            for v in b1 {
                write!(f, "{:x}", v)?;
            }
            write!(f, ", 0x")?;
            for v in b2 {
                write!(f, "{:x}", v)?;
            }
            write!(f, "), ")?;
        }
        write!(f, ", ")?;
        write!(f, "Node: {} }}", self.node)?;
        Ok(())
    }
}

type Tree = Vec<Vec<u8>>;

pub fn get_tree(shards: &[Vec<u8>]) -> Result<Tree, Error> {
    let n = shards.len();
    let size = get_size(n);
    let mut tree = vec![Vec::with_capacity(hash::HASH_SIZE); (1 << size) + 1];
    for i in 0..n {
        tree[1 << size - 1 | i] = hash::ser_and_hash(&shards[i]).to_vec();
    }
    for i in 0..(1 << size - 1) - 1 {
        let index = (1 << size - 1) - 1 - i;
        tree[index] =
            hash::ser_and_hash(&(tree[index << 1].clone(), tree[index << 1 | 1].clone())).to_vec();
    }
    Ok(tree)
}

impl<T> MTAccumulatorBuilder<T> {
    pub fn get_tree_from_codewords(codes: &[Codeword<T>]) -> Result<Tree, Error> {
        let n = codes.len();
        let size = get_size(n);
        let mut tree = vec![Vec::with_capacity(hash::HASH_SIZE); (1 << size) + 1];
        for i in 0..n {
            tree[1 << size - 1 | i] = hash::ser_and_hash(&codes[i].shard()).to_vec();
        }
        for i in 0..(1 << size - 1) - 1 {
            let index = (1 << size - 1) - 1 - i;
            tree[index] =
                hash::ser_and_hash(&(tree[index << 1].clone(), tree[index << 1 | 1].clone())).to_vec();
        }
        Ok(tree)
    }

    pub fn get_witness(&self, tree: &Tree, node: Replica) -> Result<Witness<T>, Error> {
        let n = self.n.ok_or(Error::BuilderUnsetField("n"))?;
        let size = get_size(n);
        let mut vec = Vec::with_capacity(size - 1);
        let mut p = (1 << size - 1 | node) as usize;
        for _ in 0..size - 1 {
            vec.push((tree[p ^ 1].clone(), tree[p >> 1].clone()));
            p >>= 1;
        }
        let wit = Witness {
            start: tree[(1 << size - 1 | node) as usize].clone(), 
            chain: vec,
            node,
            _x: PhantomData,
        };
        Ok(wit)

    }

    pub fn get_all_witness(&self, tree: &Tree) -> Result<Vec<Witness<T>>, Error> {
        let n = self.n.ok_or(Error::BuilderUnsetField("n"))?;
        let mut wit = Vec::with_capacity(n);
        for i in 0..n {
            let w = self.get_witness(tree, i as Replica)?;
            wit.push(w);
        }
        Ok(wit)
    } 
}