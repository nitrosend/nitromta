//! Seeded randomness. Deterministic code never asks the operating system for
//! randomness: its driver seeds an [`Rng`] for it, from the operating system
//! in production and from the run's seed in simulation, so a simulated run
//! replays exactly from its seed.
//!
//! The generator is xoshiro256++, seeded through SplitMix64 (Blackman and
//! Vigna). It is fast and statistically strong, and it is not cryptographic:
//! secrets never come from it. Its output for a given seed never changes,
//! because recorded simulation seeds depend on it.

/// A deterministic random number generator. It is deliberately not `Clone`:
/// two copies would produce the same values and correlate whatever uses
/// them. [`fork`](Self::fork) derives an independent generator instead.
#[derive(Debug)]
pub struct Rng {
    state: [u64; 4],
}

impl Rng {
    pub fn from_seed(seed: u64) -> Self {
        let mut splitmix = seed;
        Self {
            state: std::array::from_fn(|_| splitmix64(&mut splitmix)),
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let [s0, s1, s2, s3] = &mut self.state;
        let result = s0.wrapping_add(*s3).rotate_left(23).wrapping_add(*s0);
        let t = *s1 << 17;
        *s2 ^= *s0;
        *s3 ^= *s1;
        *s1 ^= *s2;
        *s0 ^= *s3;
        *s2 ^= t;
        *s3 = s3.rotate_left(45);
        result
    }

    /// A uniformly distributed value in `0..bound`, without modulo bias
    /// (Lemire's method). Panics if `bound` is zero.
    pub fn below(&mut self, bound: u64) -> u64 {
        assert!(bound > 0, "an empty range has no values");
        let mut product = u128::from(self.next_u64()) * u128::from(bound);
        if (product as u64) < bound {
            let threshold = bound.wrapping_neg() % bound;
            while (product as u64) < threshold {
                product = u128::from(self.next_u64()) * u128::from(bound);
            }
        }
        (product >> 64) as u64
    }

    /// An independent generator, for a component this one's owner creates.
    pub fn fork(&mut self) -> Self {
        Self::from_seed(self.next_u64())
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_matches_the_reference() {
        let mut state = 0;
        let outputs: [u64; 3] = std::array::from_fn(|_| splitmix64(&mut state));
        assert_eq!(
            outputs,
            [
                0xe220_a839_7b1d_cdaf,
                0x6e78_9e6a_a1b9_65f4,
                0x06c4_5d18_8009_454f
            ]
        );
    }

    #[test]
    fn xoshiro256plusplus_matches_the_reference() {
        let mut rng = Rng {
            state: [1, 2, 3, 4],
        };
        let outputs: [u64; 10] = std::array::from_fn(|_| rng.next_u64());
        assert_eq!(
            outputs,
            [
                41_943_041,
                58_720_359,
                3_588_806_011_781_223,
                3_591_011_842_654_386,
                9_228_616_714_210_784_205,
                9_973_669_472_204_895_162,
                14_011_001_112_246_962_877,
                12_406_186_145_184_390_807,
                15_849_039_046_786_891_736,
                10_450_023_813_501_588_000,
            ]
        );
    }

    /// Known answers from an independent implementation of the same
    /// algorithms. A bound just above 2^63 makes about half of all draws
    /// fall in the rejection zone, so these pin the unbiased rejection step
    /// as well as the stream.
    #[test]
    fn below_matches_the_reference() {
        let mut rng = Rng::from_seed(9);
        let cases: [(u64, [u64; 6]); 4] = [
            (6, [3, 2, 1, 5, 0, 0]),
            (
                (1 << 63) + 1,
                [
                    3_875_491_161_035_081_425,
                    1_989_015_240_936_750_000,
                    8_799_364_576_949_721_614,
                    6_224_033_820_332_044_214,
                    3_217_730_458_776_198_563,
                    2_494_495_078_851_048_842,
                ],
            ),
            (
                1_000_000_007,
                [
                    461_048_303,
                    889_511_047,
                    576_485_702,
                    889_727_129,
                    424_191_419,
                    191_925_279,
                ],
            ),
            (
                u64::MAX,
                [
                    18_208_291_585_485_029_682,
                    3_729_226_740_055_988_464,
                    9_431_531_855_792_445_431,
                    4_315_608_002_568_035_851,
                    4_900_192_251_905_415_875,
                    2_774_380_335_283_403_688,
                ],
            ),
        ];
        for (bound, expected) in cases {
            let drawn: [u64; 6] = std::array::from_fn(|_| rng.below(bound));
            assert_eq!(drawn, expected, "bound {bound}");
        }
    }

    #[test]
    fn below_stays_in_range_and_covers_it() {
        let mut rng = Rng::from_seed(7);
        let mut seen = [0_u32; 6];
        for _ in 0..60_000 {
            let value = rng.below(6);
            seen[usize::try_from(value).expect("below 6")] += 1;
        }
        // Each value is expected 10,000 times; a fair generator stays well
        // within 5% of that at this sample size.
        assert!(
            seen.iter().all(|&count| (9_500..=10_500).contains(&count)),
            "{seen:?}"
        );
        assert_eq!(rng.below(1), 0);
        assert!(rng.below(u64::MAX) < u64::MAX);
    }

    #[test]
    fn forks_are_independent_and_reproducible() {
        let mut parent = Rng::from_seed(42);
        let mut child = parent.fork();
        let parent_values: [u64; 4] = std::array::from_fn(|_| parent.next_u64());
        let child_values: [u64; 4] = std::array::from_fn(|_| child.next_u64());
        assert_ne!(parent_values, child_values);

        let mut again = Rng::from_seed(42);
        let mut child_again = again.fork();
        assert_eq!(
            child_values,
            std::array::from_fn(|_| child_again.next_u64())
        );
    }
}
