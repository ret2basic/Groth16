"""
Groth16 Zero-Knowledge Proof System Implementation

This module implements the Groth16 zk-SNARK protocol for proving that a graph is bipartite
(can be two-colored). It demonstrates the complete workflow from constraint generation
through trusted setup to proof generation and verification.

The implementation uses the BN128 elliptic curve and includes:
- R1CS (Rank-1 Constraint System) generation
- QAP (Quadratic Arithmetic Program) conversion
- Trusted setup ceremony
- Proof generation with witness
- Pairing-based verification
"""

import numpy as np
import galois
from functools import reduce
from py_ecc.bn128 import G1, G2, multiply, add, curve_order, Z1, pairing, neg, final_exponentiate, FQ12


# ============================================================================
# SETUP PARAMETERS
# ============================================================================

# Initialize Galois Field with BN128 curve order
GF = galois.GF(curve_order)

# Trusted setup parameters (in practice, these should be randomly generated and securely destroyed)
tau = GF(123)    # Secret evaluation point for polynomials
alpha = GF(456)  # Random shift for preventing forgery
beta = GF(789)   # Random shift for preventing forgery
gamma = GF(135)  # Hiding factor for public inputs
delta = GF(246)  # Hiding factor for private inputs
r = GF(11)       # Random blinding factor for proof element A
s = GF(22)       # Random blinding factor for proof element B


# ============================================================================
# PROBLEM DEFINITION: BIPARTITE GRAPH COLORING
# ============================================================================

"""
Problem: Prove that a 4-vertex graph is bipartite (2-colorable)
Vertices: x1, x2, x3, x4
Edges: (x1,x2), (x1,x4), (x2,x3)

Arithmetic Constraints:
1. Each vertex must be colored 1 or 2:
   (xi - 1) * (xi - 2) = 0 for i in {1,2,3,4}

2. Adjacent vertices must have different colors:
   xi * xj = 2 for each edge (i,j)

R1CS Form (ensuring single multiplication per constraint):
- x1 * x1 = 3x1 - 2
- x2 * x2 = 3x2 - 2
- x3 * x3 = 3x3 - 2
- x4 * x4 = 3x4 - 2
- x1 * x2 = 2
- x1 * x4 = 2
- x2 * x3 = 2
"""


# ============================================================================
# R1CS MATRICES
# ============================================================================

# Left matrix (L)
L = np.array([
    [0, 1, 0, 0, 0],  # x1
    [0, 0, 1, 0, 0],  # x2
    [0, 0, 0, 1, 0],  # x3
    [0, 0, 0, 0, 1],  # x4
    [0, 1, 0, 0, 0],  # x1
    [0, 1, 0, 0, 0],  # x1
    [0, 0, 1, 0, 0],  # x2
])

# Right matrix (R)
R = np.array([
    [0, 1, 0, 0, 0],  # x1
    [0, 0, 1, 0, 0],  # x2
    [0, 0, 0, 1, 0],  # x3
    [0, 0, 0, 0, 1],  # x4
    [0, 0, 1, 0, 0],  # x2
    [0, 0, 0, 0, 1],  # x4
    [0, 0, 0, 1, 0],  # x3
])

# Output matrix (O)
O = np.array([
    [curve_order-2, 3, 0, 0, 0],  # -2 + 3x1
    [curve_order-2, 0, 3, 0, 0],  # -2 + 3x2
    [curve_order-2, 0, 0, 3, 0],  # -2 + 3x3
    [curve_order-2, 0, 0, 0, 3],  # -2 + 3x4
    [2, 0, 0, 0, 0],              # 2
    [2, 0, 0, 0, 0],              # 2
    [2, 0, 0, 0, 0],              # 2
])

# Convert to Galois Field
L_galois = GF(L)
R_galois = GF(R)
O_galois = GF(O)


# ============================================================================
# WITNESS (PROVER'S SECRET)
# ============================================================================

# Valid 2-coloring: x1=1 (color 1), x2=2 (color 2), x3=1 (color 1), x4=2 (color 2)
x1 = GF(1)
x2 = GF(2)
x3 = GF(1)
x4 = GF(2)

# Witness vector: [1, x1, x2, x3, x4]
a = GF(np.array([1, x1, x2, x3, x4]))

# Verify R1CS satisfaction: L·a ∘ R·a = O·a
assert all(np.equal(np.matmul(L_galois, a) * np.matmul(R_galois, a), np.matmul(O_galois, a))), "R1CS constraint violation"

# Split witness into public and private inputs
l = 0  # Index of last public input (only constant term 1 is public)
public_inputs = a[:l+1]
private_inputs = a[l+1:]


# ============================================================================
# QAP CONVERSION
# ============================================================================

def interpolate_column_galois(col):
    """
    Perform Lagrange interpolation on a column to convert it to polynomial form.
    
    Args:
        col: Column vector from R1CS matrix
    
    Returns:
        Polynomial interpolating the column values
    """
    xs = GF(np.array(range(1, len(col) + 1)))
    return galois.lagrange_poly(xs, col)


# Convert R1CS matrices to polynomial form via Lagrange interpolation
U_polys = np.apply_along_axis(interpolate_column_galois, 0, L_galois)
V_polys = np.apply_along_axis(interpolate_column_galois, 0, R_galois)
W_polys = np.apply_along_axis(interpolate_column_galois, 0, O_galois)


# ============================================================================
# QAP COMPUTATION
# ============================================================================

def inner_product_polynomials_with_witness(polys, witness):
    """
    Compute inner product of polynomials with witness coefficients.
    
    Args:
        polys: Array of polynomials
        witness: Witness vector
    
    Returns:
        Sum of polynomials weighted by witness values
    """
    mul_ = lambda x, y: x * y
    sum_ = lambda x, y: x + y
    return reduce(sum_, map(mul_, polys, witness))


# Compute QAP polynomials
sum_au = inner_product_polynomials_with_witness(U_polys, a)  # U(x)·a
sum_av = inner_product_polynomials_with_witness(V_polys, a)  # V(x)·a
sum_aw = inner_product_polynomials_with_witness(W_polys, a)  # W(x)·a

# Target polynomial: product of all constraint evaluation points
t = galois.Poly([1, curve_order - 1], field = GF)\
  * galois.Poly([1, curve_order - 2], field = GF)\
  * galois.Poly([1, curve_order - 3], field = GF)\
  * galois.Poly([1, curve_order - 4], field = GF)\
  * galois.Poly([1, curve_order - 5], field = GF)\
  * galois.Poly([1, curve_order - 6], field = GF)\
  * galois.Poly([1, curve_order - 7], field = GF)

# Evaluate target polynomial at secret point tau
t_evaluated_at_tau = t(tau)

# Compute quotient polynomial h(x) from QAP division
# QAP equation: (U·a)(V·a) = (W·a) + h·t
h = (sum_au * sum_av - sum_aw) // t
HT = h * t

# Verify QAP equation holds
assert sum_au * sum_av == sum_aw + HT, "QAP division has remainder"


# ============================================================================
# TRUSTED SETUP - POWERS OF TAU GENERATION
# ============================================================================

def generate_powers_of_tau_G1(tau):
    """Generate powers of tau on G1 for polynomial evaluation."""
    return [multiply(G1, int(tau ** i)) for i in range(t.degree)]


def generate_powers_of_tau_G2(tau):
    """Generate powers of tau on G2 for polynomial evaluation."""
    return [multiply(G2, int(tau ** i)) for i in range(t.degree)]


def generate_powers_of_tau_HT(tau):
    """Generate powers of tau for h(tau)·t(tau) computation, scaled by 1/delta."""
    delta_inverse = GF(1) / delta
    before_delta_inverse = [multiply(G1, int(tau ** i * t_evaluated_at_tau)) for i in range(t.degree - 1)]
    return [multiply(entry, int(delta_inverse)) for entry in before_delta_inverse]


def generate_beta1_and_delta1():
    """Generate beta and delta as G1 points."""
    return multiply(G1, int(beta)), multiply(G1, int(delta))


# Generate shifted polynomials for proof element C
beta_times_U_polys = [beta * U_polys[i] for i in range(len(U_polys))]
alpha_times_V_polys = [alpha * V_polys[i] for i in range(len(V_polys))]

# Compute C polynomials: β·U(x) + α·V(x) + W(x)
C_polys = [beta_times_U_polys[i] + alpha_times_V_polys[i] + W_polys[i] for i in range(len(W_polys))]
C_polys_tau = [C_polys[i](tau) for i in range(len(C_polys))]
powers_of_tau_for_C = [multiply(G1, int(C_polys_tau[i])) for i in range(len(C_polys_tau))]

# Powers of tau for public inputs (scaled by 1/gamma)
gamma_inverse = GF(1) / gamma
powers_of_tau_for_public_inputs = powers_of_tau_for_C[:l+1]
powers_of_tau_for_public_inputs = [multiply(entry, int(gamma_inverse)) for entry in powers_of_tau_for_public_inputs]

# Powers of tau for private inputs (scaled by 1/delta)
delta_inverse = GF(1) / delta
powers_of_tau_for_private_inputs = powers_of_tau_for_C[l+1:]
powers_of_tau_for_private_inputs = [multiply(entry, int(delta_inverse)) for entry in powers_of_tau_for_private_inputs]

# Generate group elements for verification
alpha_G1 = multiply(G1, int(alpha))
beta_G1 = multiply(G1, int(beta))
beta_G2 = multiply(G2, int(beta))
gamma_G2 = multiply(G2, int(gamma))
delta_G1 = multiply(G1, int(delta))
delta_G2 = multiply(G2, int(delta))


# ============================================================================
# PROOF GENERATION
# ============================================================================

def inner_product(ec_points, coeffs):
    """
    Compute inner product of elliptic curve points with scalar coefficients.
    
    Args:
        ec_points: Array of elliptic curve points
        coeffs: Array of scalar coefficients
    
    Returns:
        Sum of scaled points
    """
    return reduce(add, (multiply(point, int(coeff)) for point, coeff in zip(ec_points, coeffs)), Z1)


def encrypted_evaluation_G1(poly):
    """Evaluate polynomial at tau using G1 powers of tau."""
    powers_of_tau = generate_powers_of_tau_G1(tau)
    return inner_product(powers_of_tau, poly.coeffs[::-1])


def encrypted_evaluation_G2(poly):
    """Evaluate polynomial at tau using G2 powers of tau."""
    powers_of_tau = generate_powers_of_tau_G2(tau)
    return inner_product(powers_of_tau, poly.coeffs[::-1])


def encrypted_evaluation_HT(poly):
    """Evaluate h(x) polynomial using powers of tau for h(tau)·t(tau)."""
    powers_of_tau = generate_powers_of_tau_HT(tau)
    return inner_product(powers_of_tau, poly.coeffs[::-1])


# Compute base proof elements (before randomization)
old_A = encrypted_evaluation_G1(sum_au)
old_B2 = encrypted_evaluation_G2(sum_av)
old_B1 = encrypted_evaluation_G1(sum_av)
HT_at_tau = encrypted_evaluation_HT(h)
old_C = inner_product(powers_of_tau_for_private_inputs, private_inputs)

# Generate randomized proof elements
A1 = add(add(old_A, alpha_G1), multiply(delta_G1, int(r)))  # A + α + r·δ
B2 = add(add(old_B2, beta_G2), multiply(delta_G2, int(s)))  # B + β + s·δ (on G2)
B1 = add(add(old_B1, beta_G1), multiply(delta_G1, int(s)))  # B + β + s·δ (on G1)

# Compute final proof element C
last_term_of_C1 = neg(multiply(delta_G1, int(r * s)))  # -r·s·δ
C1 = add(add(add(add(old_C, HT_at_tau), multiply(A1, int(s))), multiply(B1, int(r))), last_term_of_C1)

# Final proof
proof = [A1, B2, C1]


# ============================================================================
# VERIFICATION
# ============================================================================

def verify_proof():
    """
    Verify the Groth16 proof using pairing equations.
    
    The verification equation is:
    e(A, B) = e(α, β) · e(Σ(ai·γ^-1·Ci(τ)), γ) · e(C, δ)
    
    Which we rearrange to:
    e(-A, B) · e(α, β) · e(public_input, γ) · e(C, δ) = 1
    
    Returns:
        bool: True if proof is valid, False otherwise
    """
    first = pairing(B2, neg(A1))
    second = pairing(beta_G2, alpha_G1)
    third = pairing(gamma_G2, inner_product(powers_of_tau_for_public_inputs, public_inputs))
    fourth = pairing(delta_G2, C1)
    
    return final_exponentiate(first * second * third * fourth) == FQ12.one()


# ============================================================================
# OUTPUT
# ============================================================================

if __name__ == "__main__":
    print("\n" + "="*60)
    print("GROTH16 ZERO-KNOWLEDGE PROOF SYSTEM")
    print("="*60)
    
    print("\n[*] Problem: Proving a 4-vertex graph is bipartite")
    print(f"    Vertices: x1={int(x1)}, x2={int(x2)}, x3={int(x3)}, x4={int(x4)}")
    print(f"    Valid 2-coloring: {[int(x1), int(x2), int(x3), int(x4)]}")
    
    print("\n[*] Proof Generation:")
    print(f"    A (G1): {A1}")
    print(f"    B (G2): {B2}")
    print(f"    C (G1): {C1}")
    
    print("\n[*] Verification:")
    verification_result = verify_proof()
    print(f"    Pairing check: {'✓ VALID' if verification_result else '✗ INVALID'}")
    
    print("\n[*] Public Parameters for Verifier Contract:")
    print(f"    Alpha (G1): {alpha_G1}")
    print(f"    Beta (G2): {beta_G2}")
    print(f"    Gamma (G2): {gamma_G2}")
    print(f"    Delta (G2): {delta_G2}")
    print(f"    Public input evaluation: {inner_product(powers_of_tau_for_public_inputs, public_inputs)}")
    
    print("\n" + "="*60)
    print("PROOF GENERATION COMPLETE")
    print("="*60 + "\n")