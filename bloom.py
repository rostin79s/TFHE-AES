import math

def bloom_filter_params(d, f):
    """
    Computes the optimal Bloom filter size (m) and number of hash functions (h)
    given the database size (d) and desired false positive rate (f).
    
    Parameters:
        d (int): Number of elements in the database.
        f (float): Desired false positive rate.
        
    Returns:
        m (int): Size of the Bloom filter.
        h (int): Number of hash functions.
    """
    # Compute the optimal size of the Bloom filter
    m = math.ceil(-d * math.log(f) / (math.log(2) ** 2))

    # Compute the optimal number of hash functions
    h = math.ceil((m / d) * math.log(2))

    return m, h

# Example usage
d = 2**20  # Database size (3.4M entries)
f = 1e-3     # False positive rate (10^-3)

m, h = bloom_filter_params(d, f)
print(f"Bloom filter size (m): {m}")
print(f"Number of hash functions (h): {h}")
