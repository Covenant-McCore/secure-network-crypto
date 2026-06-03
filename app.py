import os
import sys
import base64
from flask import Flask, request, jsonify, render_template

# Firebase Core Engine Imports
import firebase_admin
from firebase_admin import credentials, firestore

# Ensure local imports map correctly to your customized git-cloned folder layout
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Cryptographic Module Imports
from kyber_py.ml_kem.default_parameters import ML_KEM_768
import tenseal as ts
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

app = Flask(__name__)

# --- FIREBASE CONNECTOR CONFIGURATION ---
try:
    firebase_config = {
        "type": os.environ.get("type"),
        "project_id": os.environ.get("project_id"),
        "private_key_id": os.environ.get("private_key_id"),
        "private_key": os.environ.get("private_key").replace("\\n", "\n"),
        "client_email": os.environ.get("client_email"),
        "client_id": os.environ.get("client_id"),
        "auth_uri": os.environ.get("auth_uri"),
        "token_uri": os.environ.get("token_uri"),
        "auth_provider_x509_cert_url": os.environ.get("auth_provider_x509_cert_url"),
        "client_x509_cert_url": os.environ.get("client_x509_cert_url"),
        "universe_domain": os.environ.get("universe_domain")
    }

    cred = credentials.Certificate(firebase_config)
    firebase_admin.initialize_app(cred)

    db = firestore.client()

    print("Firebase Connected Successfully")

except Exception as e:
    print("Firebase Connection Failed:", e)
    db = None

# --- GLOBAL CRYPTOGRAPHIC ANCHORS ---
MASTER_AUTHORITY_SECRET = b"ThesisAuthorityMasterSecret2026!"
HE_CONTEXT = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=4096, plain_modulus=1032193)
HE_CONTEXT.generate_galois_keys()

# =====================================================================
# PRIMARY WEB GRAPHICAL DASHBOARD INTERFACE ROUTE
# =====================================================================
@app.route('/')
def index_dashboard():
    """Renders the HTML web interface inside the user browser layout."""
    return render_template('dashboard.html')


# =====================================================================
# MODULE 1: POST-QUANTUM CRYPTOGRAPHY (PQC / ML-KEM)
# =====================================================================
@app.route('/api/pqc/handshake', methods=['POST'])
def pqc_handshake():
    try:
        alice_public_key, alice_private_key = ML_KEM_768.keygen()
        bob_shared_secret, ciphertext = ML_KEM_768.encaps(alice_public_key)
        alice_recovered_secret = ML_KEM_768.decaps(alice_private_key, ciphertext)
        keys_match = (alice_recovered_secret == bob_shared_secret)

        return jsonify({
            "status": "Success",
            "layer": "Post-Quantum Cryptography (ML-KEM-768)",
            "channel_integrity_verified": keys_match
        }), 200
    except Exception as e:
        return jsonify({"status": "Error", "message": str(e)}), 500


# =====================================================================
# MODULE 2: FIREBASE SECURE STORAGE VIA ABE
# =====================================================================
@app.route('/api/data/upload', methods=['POST'])
def upload_secure_data():
    """
    Encrypts a patient record via ABE, and saves the ciphertext directly to Firebase Firestore.
    """
    if db is None:
        return jsonify({"status": "Firebase Error", "message": "Database connector uninitialized"}), 500

    data = request.json
    patient_id = data.get("patient_id", "UNKNOWN_ID")
    plaintext_record = data.get("record", "No Data")
    required_policy = data.get("policy", [])

    if not required_policy:
        return jsonify({"status": "Error", "message": "Policy array cannot be empty"}), 400

    # 1. Generate an AES-256 symmetric key and encrypt the record payload
    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext_record.encode('utf-8'))

    # 2. Encapsulate the key material under policy strings
    policy_sorted = sorted([p.strip().lower() for p in required_policy])
    policy_string = ",".join(policy_sorted)
    policy_lock_seed = PBKDF2(MASTER_AUTHORITY_SECRET, policy_string.encode(), dkLen=32, count=1000)
    encrypted_aes_key = bytes(a ^ b for a, b in zip(aes_key, policy_lock_seed))

    # 3. Structural Mapping to Firebase Database Columns
    payload_to_sync = {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "nonce": base64.b64encode(cipher_aes.nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
        "required_policy": policy_sorted,
        "storage_integrity_state": "Cryptographically Locked"
    }

    try:
        # Write directly to the cloud collection 'secure_patient_records'
        # Document ID corresponds directly to the Patient Identifier
        db.collection("secure_patient_records").document(patient_id).set(payload_to_sync)
        
        return jsonify({
            "status": "Synchronized Perfect",
            "firebase_target": f"secure_patient_records/{patient_id}",
            "payload_preview": {
                "ciphertext_column": payload_to_sync["ciphertext"][:20] + "...",
                "policy_column": payload_to_sync["required_policy"]
            }
        }), 200
    except Exception as e:
        return jsonify({"status": "Firebase Write Failure", "message": str(e)}), 500


# =====================================================================
# MODULE 3: HOMOMORPHIC ENCRYPTION CLOUD ANALYTICS LOGIC
# =====================================================================
@app.route('/api/analytics/compute', methods=['POST'])
def compute_homomorphic_metrics():
    """
    Demonstrates processing data and storing the encrypted outcomes in Firebase columns.
    """
    if db is None:
        return jsonify({"status": "Firebase Error", "message": "Database connector uninitialized"}), 500

    data = request.json
    batch_id = data.get("batch_id", "BATCH_01")
    metric_a = int(data.get("metric_a", 0))
    metric_b = int(data.get("metric_b", 0))

    # 1. Encrypt vectors homomorphically
    enc_vector_a = ts.bfv_vector(HE_CONTEXT, [metric_a])
    enc_vector_b = ts.bfv_vector(HE_CONTEXT, [metric_b])

    # 2. Complete computation over ciphertexts
    enc_computed_sum = enc_vector_a + enc_vector_b

    # 3. Serialize the encrypted outcome vector into byte string for cloud columns
    serialized_cloud_result = base64.b64encode(enc_computed_sum.serialize()).decode('utf-8')

    analytics_to_sync = {
        "batch_identifier": batch_id,
        "encrypted_summation_vector": serialized_cloud_result,
        "visibility_classification": "Zero-Knowledge"
    }

    try:
        # Push calculation results directly into 'cloud_computed_analytics' column space
        db.collection("cloud_computed_analytics").document(batch_id).set(analytics_to_sync)
        
        # Local confirmation verification decoding check
        decrypted_check = enc_computed_sum.decrypt()[0]

        return jsonify({
            "status": "Analytics Synced Successfully",
            "firebase_target": f"cloud_computed_analytics/{batch_id}",
            "encrypted_column_preview": serialized_cloud_result[:30] + "...",
            "local_decrypted_validation": decrypted_check
        }), 200
    except Exception as e:
        return jsonify({"status": "Firebase Write Failure", "message": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
