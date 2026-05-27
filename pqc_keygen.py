import os
import sys

# Ensure Python looks locally for your imported cryptographic modules
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Import the standardized parameter directly from your local package
from kyber_py.ml_kem.default_parameters import ML_KEM_768

def run_pqc_demo():
    print("====================================================")
    print("     POST-QUANTUM CRYPTOGRAPHY (ML-KEM/KYBER768)     ")
    print("====================================================\n")

    # Step 1: Initialize the NIST ML-KEM-768 Module
    print("[System] Initializing ML-KEM-768 parameter set (192-bit security)...")

    # Step 2: Alice Generates a Quantum-Resistant Keypair
    print("[Alice] Generating public (ek) and private (dk) keys via module lattices...")
    public_key, private_key = ML_KEM_768.keygen()
    
    print(f" -> Public Key (ek) size:  {len(public_key)} bytes")
    print(f" -> Private Key (dk) size: {len(private_key)} bytes\n")

    # Step 3: Bob Encapsulates a Shared Symmetric Secret Key using Alice's Public Key
    print("[Bob] Simulating receiving Alice's public key...")
    print("[Bob] Encapsulating a new random shared symmetric secret...")
    
    # FIXED ASSIGNMENT: Flipped the tuple order to match the library's actual return format
    bob_shared_secret, ciphertext = ML_KEM_768.encaps(public_key)
    
    print(f" -> Real Ciphertext Payload size: {len(ciphertext)} bytes")
    print(f" -> Bob's Secret Key payload size: {len(bob_shared_secret)} bytes\n")

    # Step 4: Alice Decapsulates the Ciphertext using her Private Key
    print("[Alice] Simulating receiving Bob's ciphertext payload...")
    print("[Alice] Decapsulating payload with private key...")
    
    # Passing the verified 1088-byte ciphertext object
    alice_shared_secret = ML_KEM_768.decaps(private_key, ciphertext)
    
    print(f" -> Alice's Recovered Secret Key (Hex): {alice_shared_secret.hex()}\n")

    # Step 5: Verification Check for Thesis Presentation
    print("====================================================")
    if alice_shared_secret == bob_shared_secret:
        print(" SUCCESS: Quantum-Safe Symmetric Keys Match Perfectly!")
        print(f" Shared Key (Hex): {alice_shared_secret.hex()}")
    else:
        print(" ERROR: Cryptographic key mismatch detected.")
    print("====================================================")

if __name__ == "__main__":
    run_pqc_demo()

