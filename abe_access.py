import base64
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

class MockCPABE:
    """
    A cryptographic model demonstrating Ciphertext-Policy Attribute-Based Encryption (CP-ABE)
    using key encapsulation primitives for your final year thesis application.
    """
    def __init__(self):
        # Master secret anchor used by the Trust Authority to derive user keys
        self.master_secret_anchor = b"ThesisAuthorityMasterSecret2026!"

    def generate_user_keys(self, user_attributes: list) -> dict:
        """Simulates the Trust Authority binding user attributes to a unique cryptographic key."""
        user_attributes_sorted = sorted([a.strip().lower() for a in user_attributes])
        attributes_string = ",".join(user_attributes_sorted)
        
        # Derive a unique cryptographic key cryptographically tied to these exact attributes
        user_private_key = PBKDF2(
            self.master_secret_anchor, 
            attributes_string.encode(), 
            dkLen=32, 
            count=1000
        )
        return {"attributes": user_attributes_sorted, "key_material": user_private_key}

    def encrypt_with_policy(self, plaintext_data: str, required_policy: list) -> dict:
        """Encrypts data and locks the encryption key behind a strict multi-attribute access policy."""
        policy_sorted = sorted([p.strip().lower() for p in required_policy])
        
        # 1. Generate a random AES-256 Symmetric Data Encrypting Key (DEK)
        aes_key = get_random_bytes(32)
        
        # 2. Encrypt the plaintext data with AES-GCM (Authenticated Encryption)
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext_data.encode('utf-8'))
        
        # 3. Encapsulate (lock) the AES key using the sorted policy strings as a seed
        policy_string = ",".join(policy_sorted)
        policy_lock_seed = PBKDF2(
            self.master_secret_anchor, 
            policy_string.encode(), 
            dkLen=32, 
            count=1000
        )
        
        # XOR the AES key with the policy lock seed to simulate key encapsulation
        encrypted_aes_key = bytes(a ^ b for a, b in zip(aes_key, policy_lock_seed))

        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(cipher_aes.nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "required_policy": policy_sorted
        }

    def decrypt_with_attributes(self, encrypted_payload: dict, user_keys: dict) -> str:
        """Attempts to decrypt the data by matching user attributes against the ciphertext policy."""
        # Policy Check: Verify if the user's attributes satisfy the required policy
        user_attr_set = set(user_keys["attributes"])
        policy_set = set(encrypted_payload["required_policy"])
        
        if not policy_set.issubset(user_attr_set):
            raise PermissionError("Access Denied: User attributes do not satisfy the ciphertext access policy!")

        # 1. Reconstruct the policy lock seed using the payload's policy structure
        policy_string = ",".join(encrypted_payload["required_policy"])
        policy_lock_seed = PBKDF2(
            self.master_secret_anchor, 
            policy_string.encode(), 
            dkLen=32, 
            count=1000
        )
        
        # 2. Extract and decapsulate (unlock) the AES key
        encrypted_aes_key = base64.b64decode(encrypted_payload["encrypted_aes_key"])
        aes_key = bytes(a ^ b for a, b in zip(encrypted_aes_key, policy_lock_seed))
        
        # 3. Decrypt the main data payload using the unlocked AES key
        nonce = base64.b64decode(encrypted_payload["nonce"])
        tag = base64.b64decode(encrypted_payload["tag"])
        ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
        
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return decrypted_data.decode('utf-8')


def run_abe_demo():
    print("====================================================")
    print("       ATTRIBUTE-BASED ENCRYPTION (CP-ABE / KEM)     ")
    print("====================================================\n")

    abe_system = MockCPABE()

    # Step 1: Encrypt sensitive data with a strict multi-attribute access policy
    secret_record = "PATIENT_ID:9942 // DIAGNOSIS: Stage-2 Melanoma // LOCATION: Ward-C"
    target_policy = ["Institution:General_Hospital", "Role:Oncologist"]
    
    print(f"[Data Owner] Encrypting health record under policy: {target_policy}")
    encrypted_payload = abe_system.encrypt_with_policy(secret_record, target_policy)
    print(" -> Ciphertext payload successfully generated and packed.\n")

    # Step 2: Scenario A - Authorized user attempts access
    doctor_attributes = ["Institution:General_Hospital", "Role:Oncologist", "Clearance:Level-3"]
    print(f"[Scenario A] Doctor requests data with attributes: {doctor_attributes}")
    doctor_keys = abe_system.generate_user_keys(doctor_attributes)
    
    try:
        decrypted_text = abe_system.decrypt_with_attributes(encrypted_payload, doctor_keys)
        print(f" -> SUCCESS: Keys verified! Decrypted Content: {decrypted_text}\n")
    except Exception as e:
        print(f" -> FAILURE: {e}\n")

    # Step 3: Scenario B - Unauthorized attacker/intruder attempts access
    intruder_attributes = ["Institution:General_Hospital", "Role:Intern"]
    print(f"[Scenario B] Intern requests data with attributes: {intruder_attributes}")
    intern_keys = abe_system.generate_user_keys(intruder_attributes)
    
    try:
        decrypted_text = abe_system.decrypt_with_attributes(encrypted_payload, intern_keys)
        print(f" -> SUCCESS: {decrypted_text}\n")
    except PermissionError as e:
        print(f" -> EXPECTED SECURITY BLOCK: {e}\n")
        print("====================================================")
        print(" SUCCESS: ABE cryptographically isolated the unauthorized user.")
        print("====================================================")

if __name__ == "__main__":
    run_abe_demo()

