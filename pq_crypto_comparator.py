import oqs  # Open Quantum Safe library

# Retrieve a list of available post-quantum KEM and signature algorithms
pq_kems = oqs.get_enabled_kem_mechanisms()
pq_sigs = oqs.get_enabled_sig_mechanisms()

# # Print the lists of KEMs and signature algorithms
# print("Post-Quantum KEMs:", pq_kems)
# print("Post-Quantum SignatI'ures:", pq_sigs)

# Test a specific algorithm
def test_oqs_algorithm(alg_name, alg_type):
    """
    Function to test a specific OQS algorithm.
    :param alg_name: Name of the algorithm.
    :param alg_type: Type of the algorithm ('KEM' or 'SIG').
    """
    if alg_type == "KEM":
        return test_kem_algorithm(alg_name)
    elif alg_type == "SIG":
        return test_sig_algorithm(alg_name)
    else:
        raise ValueError("Unknown algorithm type: " + alg_type)

# Test a KEM algorithm (Kyber512) that uses the same key format as the others
def test_kem_algorithm(alg_name):
    try:
        with oqs.KeyEncapsulation(alg_name) as kem:
            keypair = kem.generate_keypair()
            # Access keys directly, no decoding needed
            public_key = keypair
            secret_key = keypair
            ciphertext, shared_secret_server = kem.encap_secret(public_key)
            shared_secret_client = kem.decap_secret(ciphertext)
            return shared_secret_client == shared_secret_server
    except Exception as e:
        print(f"Error testing KEM algorithm {alg_name}: {e}")
        return False

# Test a signature algorithm (Dilithium2) that uses a different key format
def test_sig_algorithm(alg_name):
    try:
        with oqs.Signature(alg_name) as sig:
            keypair = sig.generate_keypair()
            # Access keys using correct names, not int
            public_key = keypair
            secret_key = keypair
            message = b"This is a test message."
            # Use keys directly in operations, avoid unnecessary encoding
            signature = sig.sign(secret_key, message)
            return sig.verify(public_key, message, signature)
    except Exception as e:
        print(f"Error testing Signature algorithm {alg_name}: {e}")
        return False


result = test_oqs_algorithm("Kyber512", "KEM")
print("Kyber512 KEM Test Result:", result)

result = test_oqs_algorithm("Dilithium2", "SIG")
print("Dilithium2 SIG Test Result:", result)


# def get_org_crypto_algorithms():
#     """
#     Function to retrieve the list of cryptographic algorithms used in the organization.
#     """
#     # Implement logic to interface with the organization's systems and retrieve algorithm list
#     return org_algorithms

# org_algorithms = get_org_crypto_algorithms()

# def compare_algorithms(pq_algorithms, org_algorithms):
#     """
#     Compare post-quantum algorithms with the organization's algorithms.
#     :param pq_algorithms: List of post-quantum algorithms.
#     :param org_algorithms: List of organization's algorithms.
#     """
#     # Implement comparison logic, possibly involving testing both sets of algorithms
#     pass

# compare_algorithms(pq_kems + pq_sigs, org_algorithms)

# def report_results(comparison_results):
#     """
#     Generate a report based on the comparison results.
#     :param comparison_results: Results of the comparison.
#     """
#     # Implement reporting logic (e.g., printing to console, generating a file)
#     pass

# if __name__ == '__main__':
#     # Main script execution logic
#     comparison_results = compare_algorithms(pq_kems + pq_sigs, org_algorithms)
#     report_results(comparison_results)
