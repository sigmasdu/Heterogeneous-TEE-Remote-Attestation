import sys
import os
sys.path.append("../wrapper/sgx")

import sgx_wrap
from sgx import register_node
from sgx import TeeNodeService
from sgx import HeteroAttestationIssuer  
import hetero_attestation_pb2_grpc

from concurrent.futures import ThreadPoolExecutor
import grpc
import argparse

import logging
logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt = '%Y-%m-%d  %H:%M:%S %a'
                    )

def setup_argument():
    parser = argparse.ArgumentParser(description='Test scripts for Hetero-TEE-Attestation.')
    parser.add_argument("role", choices = ["challenger", "sgx_node"], help = "Role of this party.")
    parser.add_argument("node_id", help = "Id of this node.")

    return parser

def register_sgx_node(node_id, priv_key_path, pub_key_path, node_cert_path, ca_cert_path):
    result = register_node(node_id, "test", "test", "172.21.1.58:40060")

    with open(priv_key_path, "wb") as f:
        f.write(result.priv_key)

    with open(pub_key_path, "wb") as f:
        f.write(result.pub_key)

    with open(node_cert_path, "wb") as f:
        f.write(result.node_cert)

    with open(ca_cert_path, "wb") as f:
        f.write(result.ca_cert)


def run_attest_server(node_id, priv_key_path, pub_key_path, node_cert_path, ca_cert_path):
    port = "40070"
    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    service_impl = TeeNodeService(node_id, priv_key_path, pub_key_path, 
                                  node_cert_path, ca_cert_path, "127.0.0.1:40060") 
    hetero_attestation_pb2_grpc.add_TeeNodeServiceServicer_to_server(service_impl, server)
    server.add_insecure_port("[::]:" + port)
    server.start()

    logging.info("The Node service is running.")
    server.wait_for_termination()


def run_hetero_attest(ca_cert_path, tee_node_addr, node_id):
    enclave_path = "../wrapper/sgx/enclave.signed.so"
    enclave_id = sgx_wrap.init_enclave(enclave_path, False)
    nonce = sgx_wrap.get_nonce(enclave_id)
    
    issuer = HeteroAttestationIssuer(ca_cert_path, "test_attest", node_id, 
                                     tee_node_addr, nonce)
    if not issuer.IssueHeteroAttestation():
        logging.error(f"The tee env in {tee_node_addr} is not trusted.")
    else:
        logging.info(f"The tee env in {tee_node_addr} is trusted.")

if __name__ == "__main__":
    priv_key_path = "/tmp/priv_key"
    pub_key_path = "/tmp/pub_key"
    node_cert_path = "/tmp/node_cert"
    ca_cert_path = "/tmp/ca_cert"

    parser = setup_argument()
    args = parser.parse_args()

    register_sgx_node(args.node_id, priv_key_path, pub_key_path, 
                      node_cert_path, ca_cert_path)
    
    if args.role == "challenger":
        run_hetero_attest(ca_cert_path, "127.0.0.1:40070", args.node_id)
    else:
        run_attest_server("sgx_node", priv_key_path, pub_key_path, 
                          node_cert_path, ca_cert_path)
