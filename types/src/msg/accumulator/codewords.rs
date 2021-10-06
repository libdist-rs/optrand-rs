use std::marker::PhantomData;
use bytes::{Bytes, BytesMut};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use crate::error::Error;

use super::Shard;

#[derive(Clone, Serialize, Deserialize)]
pub struct Codeword<T> {
    data: Vec<u8>,
    _x: PhantomData<T>,
}

impl<T> Codeword<T> {
    pub fn shard(&self) -> &[u8] {
        &self.data
    }
}

impl<T> std::fmt::Debug for Codeword<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Data: 0x")?;
        for b in &self.data {
            write!(f, "{:x}", *b)?;
        }
        Ok(())
    }
}

/// This function takes a data and the number of nodes n and creates a (n,n/4) erasure coding 
pub fn generate_codewords<T>(data: &[u8], num_nodes: usize, num_faults: usize) -> Result<Vec<Codeword<T>>, Error> {
    let num_data_shards = num_nodes - num_faults;

    // Change data into length encoded data here
    let new_data = {
        let mut encoder  = LengthDelimitedCodec::new();
        let mut x= BytesMut::with_capacity(data.len());
        let buf = Bytes::copy_from_slice(data);
        encoder.encode(buf, &mut x).unwrap();
        x
    }; 
    
    // Get the size of each shard
    let shard_size = (new_data.len() + num_data_shards - 1) / num_data_shards;

    // Build [[shard size], [shard size], ..., [0; shard size], [0; shard size]]
    let mut shards:Vec<Shard> = {
        let mut new_data = new_data.to_vec();
        let suffix_size = shard_size * num_nodes - new_data.len();
        new_data.reserve(suffix_size);
        new_data.extend((0..suffix_size).map(|_i| 0));
        (0..num_nodes).map(|i| {
            new_data[i*shard_size..(i+1)*shard_size].to_vec()
        }).collect()
    };
    let r = ReedSolomon::new(num_data_shards, num_faults)?;
    r.encode(&mut shards)?;
    let mut codewords = Vec::with_capacity(num_nodes);
    for shard in shards {
        codewords.push(Codeword{
            data:shard,
            _x:PhantomData,
        });
    }
    Ok(codewords)
}

/// From Shards: takes a vector of shares and number of nodes n and reconstructs the original message
pub fn from_codewords<T>(data: Vec<Option<Codeword<T>>>, num_nodes: usize, num_faults: usize) -> Result<T, Error> 
where T: DeserializeOwned
{
    let num_data_shards = num_nodes - num_faults;
    let new_data = {
        let mut data_vec = Vec::with_capacity(num_nodes);
        for code in data {
            if let Some(x) = code {
                data_vec.push(Some(x.data));
            } else {
                data_vec.push(None);
            }
        }
        let r = ReedSolomon::new(num_data_shards, num_faults)?;
        r.reconstruct(&mut data_vec)?;
        let mut result = Vec::with_capacity(
            num_data_shards * data_vec[0]
                .as_ref()
                .map(|val| val.len())
                .unwrap()
        );
        for shard in 0..num_data_shards {
            result.append(data_vec[shard].as_mut().unwrap());
            // result.append(&mut data_vec[shard].clone().unwrap());
        }
        let mut decoder = LengthDelimitedCodec::new();
        let mut buf = BytesMut::from(&result[..]);
        decoder.decode(&mut buf).unwrap().unwrap().freeze().to_vec()
    };
    let obj = bincode::deserialize(&new_data)?;
    Ok(obj)
}

