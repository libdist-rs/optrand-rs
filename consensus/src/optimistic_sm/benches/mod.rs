mod implement;
pub use implement::*;

const _SEED: u64 = 42;
pub static TEST_POINTS: [usize; 7] = [5, 10, 20, 30, 50, 75, 100];
pub const BENCH_COUNT: usize = 10;


#[cfg(test)]
pub mod test;