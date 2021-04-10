// use rand::{rngs::StdRng, SeedableRng};

// use criterion::{
//     criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, Throughput,
// };

// const SEED: u64 = 42;
// static TEST_POINTS: [usize; 7] = [
//     3, 10, 20, 30, 50, 75, 100
// ];
// const BENCH_COUNT: usize = 10;

// pub fn mt_sh_gen(c: &mut Criterion) {
//     let rng = &mut StdRng::seed_from_u64(SEED);
//     let mut group = c.benchmark_group("mt_sh_gen");
//     BenchmarkGroup::sampling_mode(&mut group, criterion::SamplingMode::Flat);
//     for n in &TEST_POINTS {
//         let vec: Vec<F381> = (0..*n).map(|_| F381::rand(rng)).collect();
//         group.throughput(Throughput::Bytes(*n as u64));
//         group.bench_with_input(BenchmarkId::from_parameter(*n), n, |b, &_n| {
//             b.iter(|| {
//                 for cred in &vec {
//                     Biaccumulator381::create_witness(*cred, &params, &poly, rng).expect("");
//                 }
//             });
//         });
//     }
//     group.finish();
// }