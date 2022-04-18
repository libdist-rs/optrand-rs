use ark_bls12_381::Bls12_381;
use ark_ec::{PairingEngine, AffineCurve};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use crate::{AggregatePVSS, Beacon, DbsContext, DecompositionProof, Decryption, DleqProof, Keypair, PVSSVec, Scalar, std_rng};

// fn dummy_pvec<E>(n:usize) -> PVSSVec 
// where E: PairingEngine,
// {
//     let sk = crypto_lib::Keypair::generate_ed25519();
//     let mut rng = std_rng();
//     let dummy :Vec<_> = (0..n).map(|i| {
//        E::G1Projective::rand(&mut rng).into()
//     }).collect();
//     let dummy2 :Vec<_> = (0..n).map(|i| {
//        E::G2Projective::rand(&mut rng).into()
//     }).collect();
// } 
pub fn test_beacon() -> (Beacon<Bls12_381>, Decryption<Bls12_381>) 
{
    let mut rng = std_rng();
    let h2 = <Bls12_381 as PairingEngine>::G2Affine::prime_subgroup_generator().mul(Scalar::<Bls12_381>::rand(&mut rng).into_repr());
    let h1 = <Bls12_381 as PairingEngine>::G1Affine::prime_subgroup_generator().mul(Scalar::<Bls12_381>::rand(&mut rng).into_repr());
    let gt = Bls12_381::pairing(h1, h2);
    (
        Beacon{
            beacon: gt,
            value: h2,
        },
        Decryption{
            dec: h2,
            proof: DleqProof {
                a1: h2,
                a2: h2,
                c: Scalar::<Bls12_381>::rand(&mut rng),
                r: Scalar::<Bls12_381>::rand(&mut rng), 
                sig: vec![0; crypto_lib::ED25519_PK_SIZE*2],
            }
        }
    )
}


pub fn test_messages(n:usize) -> (PVSSVec<Bls12_381>, AggregatePVSS<Bls12_381>, DecompositionProof<Bls12_381>) 
{
    type E = Bls12_381;
    let mut rng = std_rng();
    let h2 = <Bls12_381 as PairingEngine>::G2Affine::prime_subgroup_generator().mul(Scalar::<Bls12_381>::rand(&mut rng).into_repr());
    let h1 = <Bls12_381 as PairingEngine>::G1Affine::prime_subgroup_generator().mul(Scalar::<Bls12_381>::rand(&mut rng).into_repr());
    let t = (n-1)/2;
    let keypairs:Vec<_> = (0..n).map(|_i| {
        let kpair = Keypair::<E>::generate_keypair(&mut rng);
        kpair
    }).collect();
    let public_keys = (0..n).map(|i| {
        keypairs[i].1
    }).collect();
    let ctx = DbsContext::<E>::new(&mut rng, h2, h1, n, t, 0, public_keys, keypairs[0].0);
    let sk = crypto_lib::Keypair::generate_ed25519();
    let pvec = ctx.generate_shares(&sk,&mut rng);
    let pvec2 = ctx.generate_shares(&sk,&mut rng);
    let indices = [1, 2];
    let (agg, decomp) = ctx.aggregate(&indices, [pvec.clone(),pvec2].to_vec());
    (pvec, agg, decomp)
}
