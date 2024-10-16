import sgx_wrap
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import cryptography.hazmat.backends as backends
from datetime import datetime, timedelta

import hashlib
import logging
import os

logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt = '%Y-%m-%d  %H:%M:%S %a'
                    )

# Use below command to generate ca.key and ca.crt:
#  openssl genrsa -out ca.key 2048
#  openssl req -new -key ca.key -out ca.csr
#  openssl x509 -req -days 365 -in ca.csr -signkey ca.key -out ca.crt

def test_generate_csr():
    enclave_path = "/root/Heterogeneous-TEE-Remote-Attestation/sgx/enclave.signed.so"
    enclave_id = sgx_wrap.init_enclave(enclave_path, True)

    common_name = "test"
    org_name = "test_org"
    priv_key, pub_key, csr_content = sgx_wrap.gen_then_export_key_and_csr(enclave_id, common_name, org_name)

    sgx_wrap.fini_enclave(enclave_id)
    
    m = hashlib.sha256()
    m.update(priv_key)
    logging.info("SHA256 of sealed private key is {}".format(m.hexdigest()))

    with open("private_key", "wb") as f:
        f.write(priv_key)

    with open("public_key", "wb") as f:
        f.write(pub_key);
    
    sgx_wrap.fini_enclave(enclave_id)

    return csr_content

def test_nonce():
    enclave_path = "/root/Heterogeneous-TEE-Remote-Attestation/sgx/enclave.signed.so"
    enclave_id = sgx_wrap.init_enclave(enclave_path, True)
    
    nonce = sgx_wrap.get_nonce(enclave_id)
    if (not sgx_wrap.check_nonce(enclave_id, nonce)):
        sgx_wrap.fini_enclave(enclave_id)
        raise RuntimeError("Nonce mismatch error.")
     
    sgx_wrap.fini_enclave(enclave_id)

def test_reload_key():
    with open("private_key", "rb") as f:
        private_key = f.read()

    with open("public_key", "rb") as f:
        public_key = f.read();

    m = hashlib.sha256()
    m.update(private_key)
    logging.info("SHA256 of sealed private key after load is {}".format(m.hexdigest()))

    enclave_path = "/root/Heterogeneous-TEE-Remote-Attestation/sgx/enclave.signed.so"
    enclave_id = sgx_wrap.init_enclave(enclave_path, True)
    sgx_wrap.import_key(enclave_id, private_key, public_key)
    sgx_wrap.fini_enclave(enclave_id)


def test_generate_certificate(csr_pem):
    csr = x509.load_pem_x509_csr(
        csr_pem, backends.default_backend())

    with open("ca.key", "r") as key_file:
        ca_contet = key_file.read()

    ca_private_key = load_pem_private_key(
            ca_contet.encode("utf-8"), password=None, 
            backend=backends.default_backend())
    
    one_day = timedelta(1, 0, 0)
    valid_from = datetime.today()
    valid_to = valid_from + one_day * 365 # One year validity

    certificate = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        x509.Name([
            # Replace with the issuer's details (CA's details)
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My CA Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"myca.com"),
        ])
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).sign(ca_private_key, hashes.SHA256(), padding.PKCS1v15)

    return certificate.public_bytes(Encoding.PEM)


def test_verify_certificate(cert_pem):
    with open("ca.crt", "rb") as file:
        ca_cert_pem = file.read()
    ca_cert = load_pem_x509_certificate(ca_cert_pem, default_backend())
    
    cert = load_pem_x509_certificate(cert_pem, default_backend())

    try:
        public_key = ca_cert.public_key()
    
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    
        cert_not_before = cert.not_valid_before
        cert_not_after = cert.not_valid_after
        if cert_not_before > datetime.now() or cert_not_after < datetime.now():
            raise ValueError("The certificate is expired or not yet valid.")
    
        print("Certificate is valid.")
    
    except InvalidSignature:
        print("Certificate is invalid: signature could not be verified.")
    except ValueError as e:
        print(f"Certificate is invalid: {e}")


def test_proof_gen_and_verify():
    enclave_path = "./enclave.signed.so"

    # Generate RSA key then export to outside.
    enclave_id = sgx_wrap.init_enclave(enclave_path, True)

    common_name = "test"
    org_name = "test_org"
    priv_key, pub_key, csr_content = sgx_wrap.gen_then_export_key_and_csr(enclave_id, common_name, org_name)

    sgx_wrap.fini_enclave(enclave_id)
    
    m = hashlib.sha256()
    m.update(priv_key)
    logging.info("SHA256 of sealed private key is {}".format(m.hexdigest()))

    with open("private_key", "wb") as f:
        f.write(priv_key)

    with open("public_key", "wb") as f:
        f.write(pub_key);
    
    sgx_wrap.fini_enclave(enclave_id)
    
    # Reload RSA key to enclave.
    with open("private_key", "rb") as f:
        private_key = f.read()

    with open("public_key", "rb") as f:
        public_key = f.read().decode("utf-8")

    m = hashlib.sha256()
    m.update(private_key)
    logging.info("SHA256 of sealed private key after load is {}".format(m.hexdigest()))

    enclave_id = sgx_wrap.init_enclave(enclave_path, True)
    sgx_wrap.import_key(enclave_id, private_key, public_key)

    # Generate SGX Report.
    example_enclave_path = "./example.signed.so"
    nonce = sgx_wrap.get_nonce(enclave_id)
    report = sgx_wrap.gen_example_report(example_enclave_path, nonce)

    # Generate SGX proof.
    os.environ['SGX_PRIVATE_KEY_FILE'] = "./private_key";
    os.environ['SGX_PUBLIC_KEY_FILE'] = "./public_key";
    proof, policy = sgx_wrap.gen_proof(enclave_id, report)

    # Verify SGX proof.
    verify_result = sgx_wrap.verify_proof(proof, policy, public_key)
    if not verify_result:
        logging.info("Verify success.")
    else:
        logging.error("Verify failed.")
        raise RuntimeError("Verify failed.")

    # report_data = sgx_wrap.get_report_data(proof)
    # if not sgx_wrap.check_nonce(enclave_id, report_data):
    #     logging.error("Nonce mismatch.")
    #     raise RuntimeError("Nonce mismatch.")
    
    sgx_wrap.fini_enclave(enclave_id)


def test_verify(report_json_path, policy_json_path, public_key_path):
    with open(report_json_path, "r") as f:
        proof = f.read()

    with open(policy_json_path, "r") as f:
        policy = f.read()

    with open(public_key_path, "rb") as f:
        public_key = f.read()

    verify_result = sgx_wrap.verify_proof(proof, policy, public_key)
    if not verify_result:
        logging.info("Verify success.")
    else:
        logging.error("Verify failed.")
        raise RuntimeError("Verify failed.")

if __name__ == '__main__':
    # csr_content = test_generate_csr()
    # certificate = test_generate_certificate(csr_content)
    # test_verify_certificate(certificate)
    # test_reload_key()
    # test_nonce()
    # test_proof_gen_and_verify()
    report_path = "../../test/sgx_report/report.json"
    policy_path = "../../test/sgx_report/policy.json"
    public_key_path = "../../test/sgx_report//public_key.pem"

    test_verify(report_path, policy_path, public_key_path)
