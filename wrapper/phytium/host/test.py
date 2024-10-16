from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

import phytium_wrap
import logging
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt = '%Y-%m-%d  %H:%M:%S %a')


def gen_then_check_sig(msg):
    handle = phytium_wrap.tee_init_session()
    content = phytium_wrap.tee_gen_key_and_csr(handle)

    priv_key = content[1]
    mac = content[3]
    
    sig_result = phytium_wrap.tee_gen_sig(handle, msg, priv_key, mac)
    sig_result = sig_result.decode("utf-8")
    sig_bytes = bytes.fromhex(sig_result)
    
    pub_key_bytes = content[2]

    try:
        public_key = serialization.load_pem_public_key(pub_key_bytes, backend=default_backend())

        public_key.verify(
            sig_bytes,
            msg,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        logging.info("Signature verification successful!")
    except InvalidSignature as e:
        logging.error("Signature verify failed, invalid signature.")

    except Exception as e:
        logging.error(f"Signature verify failed, {e}.")
    finally:
        phytium_wrap.tee_destroy_session(handle)

def gen_then_check_proof():
    proof, policy = phytium_wrap.gen_phytium_proof()
    phytium_wrap.verify_phytium_proof(proof, policy)

if __name__ == '__main__':
    msg = "Test string for phytium tee.".encode("utf-8")
    gen_then_check_sig(msg)
    gen_then_check_proof()
