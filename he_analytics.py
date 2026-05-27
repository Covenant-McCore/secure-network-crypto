import tenseal as ts

def run_he_demo():
    print("====================================================")
    print("       HOMOMORPHIC ENCRYPTION (TenSEAL / BFV)       ")
    print("====================================================\n")

    # Step 1: Create the Cryptographic Context
    print("[System] Initializing BFV homomorphic encryption context...")
    context = ts.context(
        ts.SCHEME_TYPE.BFV,
        poly_modulus_degree=4096,
        plain_modulus=1032193
    )
    context.generate_galois_keys()
    print(" -> Context established with global evaluation keys.\n")

    # Step 2: Simulating Private Patient Data (Plaintext integers)
    patient_a_glucose = [95]   # Normal fasting blood sugar level
    patient_b_glucose = [145]  # Pre-diabetic/Elevated blood sugar level
    print("[Hospital Client] Preparing raw metrics before cloud uploading:")
    print(f" -> Patient A Glucose: {patient_a_glucose[0]} mg/dL")
    print(f" -> Patient B Glucose: {patient_b_glucose[0]} mg/dL\n")

    # Step 3: Encrypt the numbers locally on your secure server boundary
    print("[Hospital Client] Encrypting metrics into ciphertext vectors...")
    enc_patient_a = ts.bfv_vector(context, patient_a_glucose)
    enc_patient_b = ts.bfv_vector(context, patient_b_glucose)
    print(" -> Raw data successfully transformed into secure ciphertexts.\n")

    # Step 4: Outsource Computation to Firebase (The Untrusted Cloud Environment)
    print("[Firebase Cloud Functions] Simulating Remote Compute Engine...")
    print("[Firebase Cloud Functions] Executing additions on ciphertext objects...")
    
    # Crucial Project Demonstration: Adding ciphertexts together directly!
    enc_combined_sum = enc_patient_a + enc_patient_b
    print(" -> Firebase calculated the sum without decrypting the raw data.\n")

    # Step 5: Download and Decrypt the Result Locally on Client Interface
    print("[Doctor Dashboard] Downloading encrypted summation from cloud...")
    print("[Doctor Dashboard] Decrypting payload with local secret key...")
    
    decrypted_result = enc_combined_sum.decrypt()
    print(f" -> Decrypted Result Metric: {decrypted_result[0]} mg/dL")

    # Step 6: Verification Check for Thesis Defense Panel
    print("====================================================")
    expected_math = patient_a_glucose[0] + patient_b_glucose[0]
    if decrypted_result[0] == expected_math:
        print(f" SUCCESS: Cloud calculation matches expected math ({expected_math})!")
        print(" Privacy Preserved: Google Firebase processed data with zero visibility.")
    else:
        print(" ERROR: Homomorphic noise computation error.")
    print("====================================================")

if __name__ == "__main__":
    run_he_demo()

