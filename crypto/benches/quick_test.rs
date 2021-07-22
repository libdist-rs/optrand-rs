#[macro_use]
extern crate bencher;

use ark_bls12_381::Bls12_381;
use ark_ec::{PairingEngine, ProjectiveCurve};
use bencher::Bencher;
use ark_std::{UniformRand, test_rng};
use ark_ff::PrimeField;
use ark_ff::One;

type E = Bls12_381;
// type G1 = <E as PairingEngine>::G1Affine;
type G1P = <E as PairingEngine>::G1Projective;
type G1Prep = <E as PairingEngine>::G1Prepared;
// type G2 = <E as PairingEngine>::G2Affine;
type G2P = <E as PairingEngine>::G2Projective;
type G2Prep = <E as PairingEngine>::G2Prepared;
type Scalar = <E as PairingEngine>::Fr;


fn pairing_naive(bench: &mut Bencher) {
    let mut rng = test_rng();
    let (g1, g2) = (G1P::rand(&mut rng), G2P::rand(&mut rng));
    let x = Scalar::rand(&mut rng);
    let g1x = g1.mul(x.into_repr());
    let g2x = g2.mul(x.into_repr());
    bench.iter(|| {
        <E as PairingEngine>::pairing(g1, g2x) == <E as PairingEngine>::pairing(g1x, g2)
    })
}

fn pairing_optimized(bench: &mut Bencher) {
    let mut rng = test_rng();
    let (g1, g2) = (G1P::rand(&mut rng), G2P::rand(&mut rng));
    let x = Scalar::rand(&mut rng);
    let g1x = g1.mul(x.into_repr());
    let g2x = g2.mul(x.into_repr());

    let g1_prepared: G1Prep = g1.into_affine().into();
    let g2_prepared: G2Prep = g2.into_affine().into();
    let one = <E as PairingEngine>::Fqk::one();

    let g1x_prepared: G1Prep = g1x.into_affine().into();
    let g2x_prepared: G2Prep = (-g2x).into_affine().into();
    let x = <E as PairingEngine>::miller_loop(
        core::iter::once(
            &(g1_prepared.clone(), g2x_prepared.clone())));
    let y = <E as PairingEngine>::miller_loop(core::iter::once(&(g1x_prepared, g2_prepared.clone())));
    let z = x*y;
    let val = <E as PairingEngine>::final_exponentiation(&z).unwrap();
    let res = val == one;
    assert_eq!(res, true);

    bench.iter(|| {
        let g1_prepared = g1_prepared.clone();

        let g1x_prepared: G1Prep = g1x.into_affine().into();
        let g2x_prepared: G2Prep = (-g2x).into_affine().into();

        let lval = <E as PairingEngine>::miller_loop(
            core::iter::once(
                &(g1_prepared, g2x_prepared)
            )
        );
        let rval = <E as PairingEngine>::miller_loop(
            core::iter::once(
                &(g1x_prepared, g2_prepared.clone())
            )
        );
        <E as PairingEngine>::final_exponentiation(&(lval*rval)).unwrap() == one
    })
}

benchmark_group!(benches, pairing_naive, pairing_optimized);
benchmark_main!(benches);