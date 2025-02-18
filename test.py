import numpy as np

def newton_schulz_inverse(A, tol=1e-5):
    """
    Compute the inverse of a matrix using Newton-Schulz iteration.
    Raises RuntimeError if convergence fails.
    """
    n, m = A.shape
    if n != m:
        raise ValueError("Matrix must be square")
    
    norm_1 = np.linalg.norm(A, 1)
    norm_inf = np.linalg.norm(A, np.inf)
    X = A.T / (norm_1 * norm_inf)
    I = np.eye(n)
    
    error = float('inf')
    iterations = 0
    
    while error > tol:
        X_prev = X
        X = X @ (2*I - A @ X)
        error = np.linalg.norm(X @ A - I, 'fro')
        iterations += 1
        
        if iterations > 50:
            raise RuntimeError("Failed to converge after 100 iterations")
            
    return X, iterations

def test_until_failure():
    """
    Test matrices with increasing scaling factors until the method fails to converge.
    """
    n = 64  # Matrix size
    scale_factor = 1.0
    scale_increment = 0.1
    test_count = 0
    
    print("Starting convergence stress test...")
    print("Scale | Status | Iterations | Error")
    print("-" * 40)
    
    while True:
        try:
            # Create random matrix
            A = np.random.uniform(-1, 1, (n, n))
            
            # Scale matrix (increasing the eigenvalues)
            A = A * scale_factor
            
            # Try to compute inverse
            A_inv, iters = newton_schulz_inverse(A, tol=1e-5)
            
            # Calculate error
            error = np.linalg.norm(A @ A_inv - np.eye(n), 'fro')
            
            print(f"{scale_factor:5.2f} | Success | {iters:10d} | {error:.2e}")
            
            # Increase scale for next iteration
            scale_factor += scale_increment
            test_count += 1
            
        except RuntimeError as e:
            print(f"\nMethod failed at scale factor {scale_factor:.2f}")
            print(f"Completed {test_count} successful tests before failure")
            
            # Calculate and display eigenvalue statistics
            eigenvals = np.linalg.eigvals(A)
            max_eigenval = np.max(np.abs(eigenvals))
            print(f"\nFinal matrix statistics:")
            print(f"Maximum absolute eigenvalue: {max_eigenval:.4f}")
            print(f"Eigenvalue range: [{np.min(eigenvals):.4f}, {np.max(eigenvals):.4f}]")
            break
            
        except np.linalg.LinAlgError as e:
            print(f"\nLinear algebra error at scale factor {scale_factor:.2f}")
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    test_until_failure()