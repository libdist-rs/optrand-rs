use criterion::criterion_main;

mod bls12_381 {
    use ark_bls12_381::Bls12_381;
    use crypto::bench_curve;
    const SEED: u64 = 42;
    static TEST_POINTS: [usize; 7] = [3, 10, 20, 30, 50, 75, 100];
    const BENCH_COUNT: usize = 10;

    bench_curve!(Bls12_381, "BLS-12-381");
}

mod bls12_377 {
    use ark_bls12_377::Bls12_377;
    use crypto::bench_curve;
    const SEED: u64 = 42;
    static TEST_POINTS: [usize; 7] = [3, 10, 20, 30, 50, 75, 100];
    const BENCH_COUNT: usize = 10;

    bench_curve!(Bls12_377, "BLS-12-377");
}

mod bn254 {
    use ark_bn254::Bn254;
    use crypto::bench_curve;
    const SEED: u64 = 42;
    static TEST_POINTS: [usize; 7] = [3, 10, 20, 30, 50, 75, 100];
    const BENCH_COUNT: usize = 10;

    bench_curve!(Bn254, "BN-254");
}

mod bw6_761 {
    use ark_bw6_761::BW6_761;
    use crypto::bench_curve;
    const SEED: u64 = 42;
    static TEST_POINTS: [usize; 7] = [3, 10, 20, 30, 50, 75, 100];
    const BENCH_COUNT: usize = 10;

    bench_curve!(BW6_761, "BW6-761");
}

mod cp6_782 {
    use ark_cp6_782::CP6_782;
    use crypto::bench_curve;
    const SEED: u64 = 42;
    static TEST_POINTS: [usize; 7] = [3, 10, 20, 30, 50, 75, 100];
    const BENCH_COUNT: usize = 10;

    bench_curve!(CP6_782, "CP6-782");
}

mod mnt4_298 {
    use ark_mnt4_298::MNT4_298;
    use crypto::bench_curve;
    const SEED: u64 = 42;
    static TEST_POINTS: [usize; 7] = [3, 10, 20, 30, 50, 75, 100];
    const BENCH_COUNT: usize = 10;

    bench_curve!(MNT4_298, "MNT4-298");
}

mod mnt6_298 {
    use ark_mnt6_298::MNT6_298;
    use crypto::bench_curve;
    const SEED: u64 = 42;
    static TEST_POINTS: [usize; 7] = [3, 10, 20, 30, 50, 75, 100];
    const BENCH_COUNT: usize = 10;

    bench_curve!(MNT6_298, "MNT6-298");
}

mod mnt4_753 {
    use ark_mnt4_753::MNT4_753;
    use crypto::bench_curve;
    const SEED: u64 = 42;
    static TEST_POINTS: [usize; 7] = [3, 10, 20, 30, 50, 75, 100];
    const BENCH_COUNT: usize = 10;

    bench_curve!(MNT4_753, "MNT4-753");
}

mod mnt6_753 {
    use ark_mnt6_753::MNT6_753;
    use crypto::bench_curve;
    const SEED: u64 = 42;
    static TEST_POINTS: [usize; 7] = [3, 10, 20, 30, 50, 75, 100];
    const BENCH_COUNT: usize = 10;

    bench_curve!(MNT6_753, "MNT6-753");
}

criterion_main!(
    bls12_381::benches, 
    bn254::benches,
    bls12_377::benches,
    bw6_761::benches,
    cp6_782::benches,
    mnt4_298::benches,
    mnt6_298::benches,
    mnt4_753::benches,
    mnt6_753::benches,
);
