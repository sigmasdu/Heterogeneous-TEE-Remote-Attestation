#!/usr/bin/python3
import os 
import sys
import logging
logging.basicConfig(level=logging.DEBUG,
                format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                datefmt = '%Y-%m-%d  %H:%M:%S %a')

if __name__ == '__main__':
    logging.info("Run SGX verify.")
    
    env_val = os.environ.get("LD_LIBRARY_PATH")
    if env_val is None:
        os.environ['LD_LIBRARY_PATH'] = "./sgx/"
        try:
            logging.info("Restart python process.")
            os.execv(sys.argv[0], sys.argv)
        except Exception as e:
            logging.error(f"Re-run sgx.py failed, {e}.")


    if "./sgx/" not in os.environ['LD_LIBRARY_PATH']:
        os.environ['LD_LIBRARY_PATH'] += "./sgx/"
        try:
            logging.info("Restart python process.")
            os.execv(sys.argv[0], sys.argv)
        except Exception as e:
            logging.error("Re-run sgx.py failed.")
 
    report_json_path = "../test/sgx_report/report.json"
    policy_json_path = "../test/sgx_report/policy.json"
    public_key_path = "../test/sgx_report/public_key.pem"
    
    with open(report_json_path, "r") as f:
        proof = f.read()
    
    with open(policy_json_path, "r") as f:
        policy = f.read()
    
    with open(public_key_path, "rb") as f:
        public_key = f.read()
    
    import sys
    sys.path.append("./sgx/")
    import sgx_wrap
    verify_result = sgx_wrap.verify_proof(proof, policy, public_key)
    if not verify_result:
        logging.info("Verify success.")
    else:
        logging.error("Verify failed.")
        raise RuntimeError("Verify failed.")
