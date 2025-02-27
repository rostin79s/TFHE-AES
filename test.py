import numpy as np
from scipy.special import erf

def lwe_decryption_failure_probability(q, t, sigma):
    """
    Computes the decryption failure probability for an LWE/RLWE ciphertext.

    Parameters:
    q (float): Ciphertext modulus
    t (float): Plaintext modulus
    sigma (float): Standard deviation of the error

    Returns:
    float: Decryption failure probability
    """
    argument = q / (4 * t * sigma)
    return 1 - erf(argument)

# Example usage:
q = 2**64  # Example ciphertext modulus
t = 2**4     # Example plaintext modulus
sigma = 3.3747142481837397e06 # Example standard deviation of error

failure_probability = lwe_decryption_failure_probability(q, t, sigma)
print(f"Decryption Failure Probability: {failure_probability:.64f}")
