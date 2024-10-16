import json
import hashlib
from datetime import datetime, timedelta
import cryptography.hazmat.backends as backends
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
import hetero_attestation_pb2_grpc
from hetero_attestation_pb2_grpc import TeeNodeService
from hetero_attestation_pb2 import RunStatus
from hetero_attestation_pb2 import TeeAttestationResponse
from hetero_attestation_pb2 import TeeAttestationRequest
from hetero_attestation_pb2 import HeteroAttestationResponse
from hetero_attestation_pb2 import HeteroAttestationRequest
from hetero_attestation_pb2 import RegisterNodeResponse
from hetero_attestation_pb2 import RegisterNodeRequest
from concurrent.futures import ThreadPoolExecutor
import argparse
import grpc
import logging

# autopep8: off
import sys
sys.path.append("../wrapper/phytium/host")
import phytium_wrap
# autopep8: on


logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')


class RegisterResult:
    def __init__(self, node_cert, ca_cert, pub_key, priv_key, mac):
        self.node_cert = node_cert
        self.ca_cert = ca_cert
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.mac = mac


def register_phytium_node(node_id, common_name, org_name, center_service_addr):
    handle = phytium_wrap.tee_init_session()
    content = phytium_wrap.tee_gen_key_and_csr(handle)
    phytium_wrap.tee_destroy_session(handle)

    priv_key = content[1]
    mac = content[3]
    pub_key = content[2]
    csr_content = content[0]

    # Reqeust to generate certificate.
    channel = grpc.insecure_channel(center_service_addr)
    stub = hetero_attestation_pb2_grpc.CenterServiceStub(channel)

    request = RegisterNodeRequest(node_id=node_id, csr_content=csr_content)
    response = stub.RegisterNode(request)

    logging.info(
        f"Register node to center attestation service {center_service_addr} finish.")

    return RegisterResult(response.node_cert, response.ca_cert, pub_key, priv_key, mac)


class TeeNodeServiceForPhytium(TeeNodeService):
    def __init__(self, node_id, priv_key_path, pub_key_path, node_cert_path,
                 ca_cert_path, center_service_addr):
        self.priv_key_path = priv_key_path
        self.pub_key_path = pub_key_path
        self.ca_cert_path = ca_cert_path
        self.node_id = node_id
        self.node_cert_path = node_cert_path
        self.center_addr = center_service_addr

    def CheckSignature(self, message, signature):
        with open(self.ca_cert_path, "rb") as f:
            ca_cert_bytes = f.read()

        ca_cert = load_pem_x509_certificate(ca_cert_bytes, default_backend())
        public_key = ca_cert.public_key()

        try:
            public_key.verify(signature, message,
                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                          salt_length=padding.PSS.MAX_LENGTH),
                              hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    def IssueRemoteAttestation(self, request, response):
        with open(self.node_cert_path, "rb") as f:
            node_cert = f.read()

        proof, policy = phytium_wrap.gen_phytium_proof()

        proof_obj = json.loads(proof)
        report = proof_obj["report"]["json_report"]

        with open(self.priv_key_path, "rb") as f:
            mac_and_priv_key = f.read()

        view = memoryview(mac_and_priv_key)
        mac = view[0:32].tobytes()
        priv_key = view[32:].tobytes()

        handle = phytium_wrap.tee_init_session()
        digest = phytium_wrap.tee_gen_sig(
            handle, report.encode("utf-8"), priv_key, mac)

        proof_obj["report"]["json_report_sig"] = digest.decode("utf-8")
        proof = json.dumps(proof_obj)

        logging.info("Generate Phytium proof finish.")
        logging.info("Request center attestation service to verify proof.")

        # Send to center attestation service.
        verify_request = TeeAttestationRequest(
            tee_proof=proof,
            nonce=request.nonce,
            platform="hetero_phytium",
            policy=policy,
            tee_node_id=self.node_id,
            attest_id=request.attest_id,
            challenger_node_id=request.node_id,
            tee_node_cert=node_cert)

        if len(request.attachment) != 0:
            verify_request.attachment = request.attachment
            verify_request.hex_attach_sig = phytium_wrap.tee_gen_sig(
                handle, request.attachment, priv_key, mac)
            logging.info("Generate signature of attachment finish.")

        channel = grpc.insecure_channel(self.center_addr)
        stub = hetero_attestation_pb2_grpc.CenterServiceStub(channel)

        verify_response = stub.VerifyTeeProof(verify_request)
        if verify_response.status.error:
            response = HeteroAttestationResponse(
                status=RunStatus(error=True, msg=verify_response.status.msg))
            logging.error(
                f"Center attestion service verify failed, {verify_response.status.msg}")
            return response

        logging.info("Center attestation service return verify result.")

        digest_obj = json.loads(verify_response.service_digest)
        signature = bytes.fromhex(digest_obj["signature"])

        if len(request.attachment) != 0:
            message = verify_request.tee_proof + \
                verify_response.verify_result + \
                hashlib.sha256(verify_request.attachment).hexdigest() + \
                verify_request.nonce.hex()
        else:
            message = verify_request.tee_proof + \
                verify_response.verify_result + \
                verify_request.nonce.hex()
        message = message.encode("utf-8")

        sha256_result = hashlib.sha256(message).hexdigest()
        logging.info(f"SHA256 of message is {sha256_result}")

        if not self.CheckSignature(message, signature):
            response = HeteroAttestationResponse(
                status=RunStatus(error=True,
                                 msg="Verify signature from center service failed."))
            logging.error("Verify signature failed.")
            return response

        logging.info("Signature verify finish.")

        response = HeteroAttestationResponse(
            verify_result=verify_response.verify_result,
            tee_proof=proof.encode("utf-8"), signature=digest_obj["signature"],
            nonce=request.nonce,
            status=RunStatus(error=False))

        return response


def setup_cmdline_args():
    parser = argparse.ArgumentParser(description='Phytium node service.')
    parser.add_argument("--config", required=True, help="Path of config file.")
    return parser


if __name__ == '__main__':
    parser = setup_cmdline_args()
    args = parser.parse_args()
    with open(args.config, "r") as f:
        conf_obj = json.load(f)

    logging.info(conf_obj)

    result = register_phytium_node(conf_obj["node_id"],
                                   conf_obj["csr_field"]["common_name"],
                                   conf_obj["csr_field"]["organization_name"],
                                   conf_obj["center_attestation_service"])

    priv_key_path = conf_obj["cert_and_key_file_path"] + "/priv_key"
    pub_key_path = conf_obj["cert_and_key_file_path"] + "/pub_key"
    node_cert_path = conf_obj["cert_and_key_file_path"] + "/node_cert"
    ca_cert_path = conf_obj["cert_and_key_file_path"] + "/ca_cert"

    with open(node_cert_path, "wb") as f:
        f.write(result.node_cert)

    with open(ca_cert_path, "wb") as f:
        f.write(result.ca_cert)

    with open(priv_key_path, "wb") as f:
        f.write(result.mac)
        f.write(result.priv_key)

    with open(pub_key_path, "wb") as f:
        f.write(result.pub_key)

    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    service_impl = TeeNodeServiceForPhytium(conf_obj["node_id"], priv_key_path,
                                            pub_key_path,
                                            node_cert_path,
                                            ca_cert_path,
                                            conf_obj["center_attestation_service"])

    hetero_attestation_pb2_grpc.add_TeeNodeServiceServicer_to_server(
        service_impl, server)
    server.add_insecure_port("[::]:" + conf_obj["listen_port"])
    server.start()

    logging.info("The Node service is running.")
    server.wait_for_termination()
