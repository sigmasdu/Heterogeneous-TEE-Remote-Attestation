from hetero_attestation_pb2 import InnerVerifyRequest
from hetero_attestation_pb2 import InnerVerifyResponse
from hetero_attestation_pb2_grpc import VerifyService
import hetero_attestation_pb2_grpc
from concurrent.futures import ThreadPoolExecutor

import grpc
import json
import argparse
import logging
logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a'
                    )


class VerifyServiceSgxImpl(VerifyService):
    def Verify(self, request, response):
        import sys
        sys.path.append("../wrapper/sgx/")
        import sgx_wrap

        if not sgx_wrap.verify_proof(request.proof,
                                     request.policy,
                                     request.public_key):
            logging.info("Verify SGX proof finish.")
            response = InnerVerifyResponse(verify_result=True)
            return response
        else:
            logging.error("Verify SGX proof failed.")
            response = InnerVerifyResponse(verify_result=False)
            return response


class VerifyServicePhytiumImpl(VerifyService):
    def Verify(self, request, response):
        import sys
        sys.path.append("../wrapper/phytium/host/")
        import phytium_wrap

        if not phytium_wrap.verify_phytium_proof(request.proof,
                                                 request.policy):
            logging.info("Verify Phytium proof finish.")
            response = InnerVerifyResponse(verify_result=True)
            return response
        else:
            logging.error("Verify Phytium proof failed.")
            response = InnerVerifyResponse(verify_result=False)
            return response

class VerifyServiceCSVImpl(VerifyService):
    def Verify(self, request, response):
        import sys
        sys.path.append("../wrapper/csv")
        import csv_wrap

        if not csv_wrap.verify_csv_proof(request.proof,
                                                 request.policy):
            logging.info("Verify Hygon CSV proof finish.")
            response = InnerVerifyResponse(verify_result=True)
            return response
        else:
            logging.error("Verify Hygon CSV proof failed.")
            response = InnerVerifyResponse(verify_result=False)
            return response

def run_sgx_verify_server(port):
    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    service_impl = VerifyServiceSgxImpl()
    hetero_attestation_pb2_grpc.add_VerifyServiceServicer_to_server(
        service_impl, server)
    server.add_insecure_port("[::]:" + port)
    server.start()

    logging.info("The SGX verify service is running.")
    server.wait_for_termination()


def run_phytium_verify_server(port):
    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    service_impl = VerifyServicePhytiumImpl()
    hetero_attestation_pb2_grpc.add_VerifyServiceServicer_to_server(
        service_impl, server)
    server.add_insecure_port("[::]:" + port)
    server.start()

    logging.info("The Phytium verify service is running.")
    server.wait_for_termination()

def run_csv_verify_server(port):
    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    service_impl = VerifyServiceCSVImpl()
    hetero_attestation_pb2_grpc.add_VerifyServiceServicer_to_server(
        service_impl, server)
    server.add_insecure_port("[::]:" + port)
    server.start()

    logging.info(f"The HYGON CSV verify service is running. listen port: {port}")
    server.wait_for_termination()


def parser_args():
    parser = argparse.ArgumentParser(
        description="Parse command line argument.")
    parser.add_argument("tee", help="Tee type.")
    parser.add_argument("port", help="Port the service listen on.")
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parser_args()
    if args.tee == "sgx":
        run_sgx_verify_server(args.port)
    elif args.tee == "csv":
        run_csv_verify_server(args.port)
    else:
        run_phytium_verify_server(args.port)
