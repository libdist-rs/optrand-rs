use crate::{MTAccumulatorBuilder, Replica, error::Error, from_codewords};
use super::get_size as gs;

const SIZE: usize = 1025;
const NUM_NODES:usize = 4;
const NUM_FAULTS:usize = 1;

fn fill_random_data(buf: &mut [u8]) {
    for i in 0..buf.len() {
        buf[i] = crypto::rand::random();
    }
}

#[test]
fn shards() -> Result<(), Error> {
    let mut data = [0 as u8; SIZE];
    fill_random_data(&mut data);
    let data = (data.to_vec(), 0);
    type DATA = (Vec<u8>, usize);
    let bytes = bincode::serialize(&data)?;
    let shards = super::generate_codewords::<DATA>(&bytes, NUM_NODES, NUM_FAULTS)?;
    let mut received: Vec<_> = shards.iter().cloned().map(Some).collect();
    received[0] = None;
    let reconstructed = from_codewords::<(Vec<u8>, usize)>(received, NUM_NODES, NUM_FAULTS)?;
    assert_eq!(data, reconstructed);
    Ok(())
}

#[test]
fn test_codes() -> Result<(), Error> {
    let mut data = [0 as u8; SIZE];
    fill_random_data(&mut data);
    let data = (data.to_vec(), 0);
    type DATA = (Vec<u8>, usize);
    let mut accumulator = MTAccumulatorBuilder::new();
    accumulator
        .set_n(NUM_NODES)
        .set_f(NUM_FAULTS);
    let (_, codes, _) = accumulator.build(&data)?;
    let mut received: Vec<_> = codes.iter().cloned().map(Some).collect();
    received[0] = None;
    let reconstructed = from_codewords::<DATA>(received, NUM_NODES, NUM_FAULTS)?;
    assert_eq!(data, reconstructed);
    Ok(())
}

#[test]
fn test_acc() -> Result<(), Error> {
    let mut data = [0 as u8; SIZE];
    fill_random_data(&mut data);
    let data = (data.to_vec(), 0);
    let mut accumulator = MTAccumulatorBuilder::new();
    accumulator
        .set_n(NUM_NODES)
        .set_f(NUM_FAULTS);
    let (acc, _, _) = accumulator.build(&data)?;
    accumulator.check(&data, &acc)
}

#[test]
fn test_witness() -> Result<(), Error> {
    let mut data = [0 as u8; SIZE];
    fill_random_data(&mut data);
    let data = (data.to_vec(), 0);
    let mut accumulator = MTAccumulatorBuilder::new();
    accumulator
        .set_n(NUM_NODES)
        .set_f(NUM_FAULTS);
    let (acc, codes, wits) = accumulator.build(&data)?;
    for i in 0..NUM_NODES {
        accumulator.verify_witness(&acc, &wits[i], &codes[i], i)?;
    }
    Ok(())
}

fn get_size(num_nodes: Replica) -> Replica {
    let mut n: Replica = 1;
    // num_nodes.next_power_of_two(num_nodes).unwrap()
    while 1 << n < num_nodes {
        n += 1;
    }
    n + 1
}

#[test]
fn test_power_of_two() {
    for i in 1..34000 {
        assert_eq!(gs(i as usize), get_size(i as usize));
    }
    assert_eq!(gs(0), get_size(0), "zero test failed");
}

