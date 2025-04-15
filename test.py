def fhe_rounding(ai, N, v, k, q):
    from math import floor

    # Constants
    twoN = 2 * N
    scale = twoN * (2 ** (k - v))

    # First rounding: round to nearest integer
    temp = (ai * scale) / q
    temp_rounded = round(temp)

    # Multiply by 2^v and round again
    temp2 = round(temp_rounded * (2 ** v))

    # Final result modulo 2N
    return temp2 % twoN

ai = 10479941893543617592
N = 2048
v = 2
k = 0
q = 2**64  # typical modulus in 64-bit cryptography

print(bin(ai))
result = fhe_rounding(ai, N, v, k, q)
print("a_i' =", result)
print("a_i' in binary =", bin(result))
