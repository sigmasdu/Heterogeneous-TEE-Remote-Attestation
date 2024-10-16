import sys
import json
import grpc
import hashlib
import argparse
import hetero_attestation_pb2_grpc
from hetero_attestation_pb2_grpc import CenterService
from hetero_attestation_pb2 import RegisterNodeRequest
from hetero_attestation_pb2 import RegisterNodeResponse
from hetero_attestation_pb2 import TeeAttestationResponse
from hetero_attestation_pb2 import TeeAttestationRequest
from hetero_attestation_pb2 import InnerVerifyRequest
from hetero_attestation_pb2 import InnerVerifyResponse
from hetero_attestation_pb2 import RunStatus

from concurrent.futures import ThreadPoolExecutor

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import cryptography.hazmat.backends as backends
from datetime import datetime, timedelta

import logging

logging.basicConfig(level=logging.DEBUG,
                   format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                   datefmt='%Y-%m-%d  %H:%M:%S %a')


class CenterServiceImpl(CenterService):
    def __init__(self, ca_key, ca_cert,
                 sgx_service_addr, phytium_service_addr, csv_service_addr):
        self.ca_key = ca_key
        self.ca_cert = ca_cert
        self.sgx_verify_service = sgx_service_addr
        self.phytium_verify_service = phytium_service_addr
        self.csv_verify_service = csv_service_addr

    def set_cert_field(self, country_name, state_or_province_name,
                       locality_name, organization_name, common_name):
        self.country_name = country_name
        self.state_or_province_name = state_or_province_name
        self.locality_name = locality_name
        self.organization_name = organization_name
        self.common_name = common_name

    def RegisterNode(self, request, response):
        csr_content = request.csr_content
        node_id = request.node_id

        csr = x509.load_pem_x509_csr(
            csr_content, backends.default_backend())

        ca_private_key = load_pem_private_key(
            self.ca_key, password=None,
            backend=backends.default_backend())

        one_day = timedelta(1, 0, 0)
        valid_from = datetime.today()
        valid_to = valid_from + one_day * 365  # One year validity

        certificate = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            x509.Name([
                x509.NameAttribute(
                    NameOID.COUNTRY_NAME, self.country_name),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, self.state_or_province_name),
                x509.NameAttribute(
                    NameOID.LOCALITY_NAME, self.locality_name),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, self.organization_name),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, self.common_name),
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

        pem_bytes = certificate.public_bytes(Encoding.PEM)

        logging.info(f"Generate certificate for {node_id} finish.")

        return RegisterNodeResponse(node_id=node_id,
                                    node_cert=pem_bytes,
                                    ca_cert=self.ca_cert)

    def VerifySignature(self, pub_key_bytes, msg, signature):
        try:
            public_key = serialization.load_pem_public_key(
                pub_key_bytes, backend=default_backend())

            public_key.verify(
               signature, msg,
               padding.PKCS1v15(),
               hashes.SHA256()
            )
            logging.info("Signature verification successful!")
            return True
        except InvalidSignature as e:
            logging.error("Signature verify failed, invalid signature.")
            return False
        except Exception as e:
            logging.error(f"Signature verify failed, {e}.")
            return False

    def VerifyCertificate(self, node_cert):
        ca_cert = load_pem_x509_certificate(self.ca_cert, default_backend())
        # Verify certificate.
        valid_cert = True
        try:
            public_key = ca_cert.public_key()

            public_key.verify(
                node_cert.signature,
                node_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                node_cert.signature_hash_algorithm
            )

            cert_not_before = node_cert.not_valid_before
            cert_not_after = node_cert.not_valid_after
            if cert_not_before > datetime.now() or cert_not_after < datetime.now():
                raise ValueError(
                    "The certificate is expired or not yet valid.")
        except InvalidSignature:
            valid_cert = False
            logging.error(
                "Certificate is invalid: signature could not be verified.")
        except ValueError as e:
            valid_cert = False
            logging.error(f"Certificate is invalid: {e}")
        return valid_cert

    def VerifyTeeProof(self, request, response):
        # Verify certificate.
        node_cert_bytes = request.tee_node_cert
        node_cert = load_pem_x509_certificate(node_cert_bytes,
                                              default_backend())
        valid_cert = self.VerifyCertificate(node_cert)
        if not valid_cert:
            response = TeeAttestationResponse(
                status=RunStatus(
                    error=True, msg="Invalid node cerificate."))
            return response

        # Verify signature and proof.
        public_key_bytes = node_cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        proof = request.tee_proof
        policy = request.policy
        # verify_result = sgx_wrap.verify_proof(proof, policy, public_key)

        proof_obj = json.loads(proof)
        tee_platform = proof_obj["report"]["str_tee_platform"]
        if tee_platform == "HETERO_TEE_SGX":
            logging.info("Redirect verify step to inner SGX verify service.")
            channel = grpc.insecure_channel(self.sgx_verify_service)
            stub = hetero_attestation_pb2_grpc.VerifyServiceStub(channel)
            inner_request = InnerVerifyRequest(
                proof=proof, policy=policy, public_key=public_key_bytes)
            inner_response = stub.Verify(inner_request)
            logging.info(
                f"Verify result from inner SGX verify service: {inner_response}")
        elif tee_platform == "CSV":
            # check validataion fo report by signature
            msg = proof_obj["report"]["json_report"].encode("utf-8")
            logging.info("begin to verfiy report sig")
            sig = bytes.fromhex(proof_obj["report"]["json_report_sig"])

            valid_sig = False
            valid_sig = self.VerifySignature(public_key_bytes, msg, sig)
            logging.info(f"end of verfiy report sig {valid_sig}")
            if valid_sig is True:
                logging.info(
                    "Redirect verify step to inner Hygon CSV verify service.")
                channel = grpc.insecure_channel(self.csv_verify_service)
                stub = hetero_attestation_pb2_grpc.VerifyServiceStub(channel)
                inner_request = InnerVerifyRequest(
                    proof=proof, policy=policy, public_key=public_key_bytes)
                inner_response = stub.Verify(inner_request)
                logging.info(
                    f"Verify result from inner Hygon CSV verify service: "
                    f"{inner_response.verify_result}")
            else:
                inner_response = InnerVerifyResponse(verify_result=False)
        else:
            msg = proof_obj["report"]["json_report"].encode("utf-8")
            sig = bytes.fromhex(proof_obj["report"]["json_report_sig"])

            valid_sig = False
            valid_sig = self.VerifySignature(public_key_bytes, msg, sig)
            if valid_sig is True:
                logging.info(
                    "Redirect verify step to inner Phytium verify service.")
                channel = grpc.insecure_channel(self.phytium_verify_service)
                stub = hetero_attestation_pb2_grpc.VerifyServiceStub(channel)
                inner_request = InnerVerifyRequest(
                    proof=proof, policy=policy, public_key=public_key_bytes)
                inner_response = stub.Verify(inner_request)
                logging.info(
                    f"Verify result from inner Phytium verify service: "
                    f"{inner_response.verify_result}")
            else:
                inner_response = InnerVerifyResponse(verify_result=False)

        verify_result = inner_response.verify_result

        if len(request.attachment) != 0:
            valid_sig = self.VerifySignature(public_key_bytes,
                                             request.attachment,
                                             bytes.fromhex(
                                                 request.hex_attach_sig))
            if not valid_sig:
                logging.error("Verify signature of attachment failed.")
                verify_result = False
            else:
                logging.info("Verify signature of attachment finish.")

        ca_private_key = load_pem_private_key(
            self.ca_key, password=None,
            backend=backends.default_backend())

        if verify_result:
            message = proof + "pass"
        else:
            message = proof + "failed"

        if len(request.attachment):
            message = message + hashlib.sha256(request.attachment).hexdigest()

        message = message + request.nonce.hex()
        sha256_result = hashlib.sha256(message.encode()).hexdigest()
        logging.info(f"SHA256 of message to sign is {sha256_result}")

        signature = ca_private_key.sign(
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        proof_obj = json.loads(proof)
        del proof_obj['report']['json_report']
        del proof_obj['pem_public_key']
        proof_obj["signature"] = signature.hex()

        verify_result_msg = "pass" if verify_result else "failed"
        response = TeeAttestationResponse(verify_result = verify_result_msg,
                                          platform = tee_platform,
                                          service_digest = json.dumps(proof_obj),
                                          ca_cert = self.ca_cert)
        return response


def server(ca_key, ca_cert, config):
    port = config["listen_port"]
    sgx_verify_service = config["inner_sgx_verify_service"]
    phytium_verify_service = config["inner_phytium_verify_service"]
    csv_verify_service = config["inner_csv_verify_service"]
    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    service_impl = CenterServiceImpl(ca_key, ca_cert,
                                     sgx_verify_service,
                                     phytium_verify_service,
                                     csv_verify_service)
    cert_field = config["cert_field"]
    service_impl.set_cert_field(cert_field["country_name"],
                                cert_field["state_or_province_name"],
                                cert_field["locality_name"],
                                cert_field["organization_name"],
                                cert_field["common_name"])

    hetero_attestation_pb2_grpc.add_CenterServiceServicer_to_server(
        service_impl, server)
    server.add_insecure_port("[::]:" + port)
    server.start()

    logging.info(f"The Center Attestation service is running. listen port: {port}")
    server.wait_for_termination()


def setup_cmdline_args():
    parser = argparse.ArgumentParser(description='Route server.')
    parser.add_argument("--config", required=True, help="Path of config file.")
    return parser


if __name__ == '__main__':
    parser = setup_cmdline_args()
    args = parser.parse_args()
    conf_file = args.config

    with open(conf_file, "r") as f:
        conf_obj = json.load(f)

    logging.info(conf_obj)

    dir = conf_obj["cert_and_key_file_path"]
    with open(dir + "/ca.key", "rb") as ca_key_file:
        ca_key_bytes = ca_key_file.read()

    with open(dir + "/ca.crt", "rb") as ca_cert_file:
        ca_cert_bytes = ca_cert_file.read()

    server(ca_key_bytes, ca_cert_bytes, conf_obj)
