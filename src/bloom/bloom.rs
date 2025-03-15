use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Generates a random hash function using a given seed
fn hash_value(value: u64, seed: u64) -> usize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    seed.hash(&mut hasher);
    hasher.finish() as usize
}

/// Computes the optimal Bloom filter size (m) and number of hash functions (h)
/// given the database size and false positive rate.
pub fn bloom_params(prob_failure: f64, db_size: usize) -> (usize, usize) {
    let ln2 = std::f64::consts::LN_2;
    let m = (-((db_size as f64) * prob_failure.ln()) / (ln2 * ln2)).ceil() as usize;
    let h = ((m as f64 / db_size as f64) * ln2).ceil() as usize;
    (m, h)
}


/// Creates a Bloom filter of size `m`, inserting `db_size` random numbers using `h` different hash functions.
/// Returns the set of hash function seeds and the bloom filter.
pub fn bloom_create(m: usize, h: usize, db_size: usize) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    let mut bloom_filter: Vec<u64> = vec![0; m];

    // Generate `h` random hash function seeds
    let mut rng = StdRng::from_entropy();
    let hash_seeds: Vec<u64> = (0..h).map(|_| rng.gen()).collect();

    // Insert `db_size` random values into the Bloom filter
    let mut values = Vec::new();
    for _ in 0..db_size {
        let value = rng.gen::<u64>(); // Generate random value
        values.push(value);
        println!("value: {}", value);
        for &seed in &hash_seeds {
            let index = hash_value(value, seed) % m;
            bloom_filter[index] = 1;
        }
    }

    (hash_seeds, bloom_filter, values)
}

pub fn bloom_query(value: u64, seeds: &[u64], m: usize) -> Vec<usize> {
    seeds.iter().map(|&seed| hash_value(value, seed) % m).collect()
}

pub fn bloom_check(indices: Vec<usize>, bloom: Vec<u64>) -> bool {
    indices.iter().all(|&i| bloom[i] == 1)
}
