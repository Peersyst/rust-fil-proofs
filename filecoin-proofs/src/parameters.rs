use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use storage_proofs::porep::stacked::{self, LayerChallenges, StackedDrg};
use storage_proofs::post::fallback;
use storage_proofs::proof::ProofScheme;

use crate::constants::*;
use crate::types::{MerkleTreeTrait, PaddedBytesAmount, PoStConfig};

const DRG_NONCE: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 30, 30, 31,
];

type WinningPostSetupParams = fallback::SetupParams;
pub type WinningPostPublicParams = fallback::PublicParams;

type WindowPostSetupParams = fallback::SetupParams;
pub type WindowPostPublicParams = fallback::PublicParams;

pub fn public_params<Tree: 'static + MerkleTreeTrait>(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
    porep_id: [u8; 32],
) -> Result<stacked::PublicParams<Tree>> {
    StackedDrg::<Tree, DefaultPieceHasher>::setup(&setup_params(
        sector_bytes,
        partitions,
        porep_id,
    )?)
}

pub fn winning_post_public_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<WinningPostPublicParams> {
    fallback::FallbackPoSt::<Tree>::setup(&winning_post_setup_params(&post_config)?)
}

pub fn winning_post_setup_params(post_config: &PoStConfig) -> Result<WinningPostSetupParams> {
    ensure!(
        post_config.challenge_count % post_config.sector_count == 0,
        "sector count must divide challenge count"
    );

    let param_sector_count = post_config.challenge_count / post_config.sector_count;
    let param_challenge_count = post_config.challenge_count / param_sector_count;

    ensure!(
        param_sector_count * param_challenge_count == post_config.challenge_count,
        "invald parameters calculated {} * {} != {}",
        param_sector_count,
        param_challenge_count,
        post_config.challenge_count
    );

    Ok(fallback::SetupParams {
        sector_size: post_config.padded_sector_size().into(),
        challenge_count: param_challenge_count,
        sector_count: param_sector_count,
    })
}

pub fn window_post_public_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<WindowPostPublicParams> {
    fallback::FallbackPoSt::<Tree>::setup(&window_post_setup_params(&post_config))
}

pub fn window_post_setup_params(post_config: &PoStConfig) -> WindowPostSetupParams {
    fallback::SetupParams {
        sector_size: post_config.padded_sector_size().into(),
        challenge_count: post_config.challenge_count,
        sector_count: post_config.sector_count,
    }
}

fn drg_seed_from_porep_id(porep_id: [u8; 32]) -> [u8; 28] {
    let mut drg_seed = [0; 28];

    let hash = Sha256::new().chain(porep_id).chain(DRG_NONCE).result();

    drg_seed.copy_from_slice(&hash[..28]);
    drg_seed
}

pub fn setup_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
    porep_id: [u8; 32],
) -> Result<stacked::SetupParams> {
    let layer_challenges = select_challenges(
        partitions,
        *POREP_MINIMUM_CHALLENGES
            .read()
            .unwrap()
            .get(&u64::from(sector_bytes))
            .expect("unknown sector size") as usize,
        *LAYERS
            .read()
            .unwrap()
            .get(&u64::from(sector_bytes))
            .expect("unknown sector size"),
    )?;
    let sector_bytes = u64::from(sector_bytes);

    ensure!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );

    let nodes = (sector_bytes / 32) as usize;
    let degree = DRG_DEGREE;
    let expansion_degree = EXP_DEGREE;

    let drg_seed = drg_seed_from_porep_id(porep_id);

    Ok(stacked::SetupParams {
        nodes,
        degree,
        expansion_degree,
        seed: drg_seed,
        layer_challenges,
    })
}

fn select_challenges(
    partitions: usize,
    minimum_total_challenges: usize,
    layers: usize,
) -> Result<LayerChallenges> {
    let mut count = 1;
    let mut guess = LayerChallenges::new(layers, count);
    while partitions * guess.challenges_count_all() < minimum_total_challenges {
        count += 1;
        guess = LayerChallenges::new(layers, count);
    }
    Ok(guess)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::PoStType;

    #[test]
    fn partition_layer_challenges_test() {
        let f = |partitions| {
            select_challenges(partitions, 12, 11)
                .unwrap()
                .challenges_count_all()
        };
        // Update to ensure all supported PoRepProofPartitions options are represented here.
        assert_eq!(6, f(usize::from(crate::PoRepProofPartitions(2))));

        assert_eq!(12, f(1));
        assert_eq!(6, f(2));
        assert_eq!(3, f(4));
    }

    #[test]
    fn test_winning_post_params() {
        let config = PoStConfig {
            typ: PoStType::Winning,
            priority: false,
            challenge_count: 66,
            sector_count: 1,
            sector_size: 2048u64.into(),
        };

        let params = winning_post_public_params::<DefaultOctLCTree>(&config).unwrap();
        assert_eq!(params.sector_count, 66);
        assert_eq!(params.challenge_count, 1);
        assert_eq!(params.sector_size, 2048);
    }
}
