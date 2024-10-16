#include <glog/logging.h>
#include <pybind11/pybind11.h>
#include <sgx_urts.h>

#include <tuple>

#ifndef SGX_VERIFY_ONLY
#include "attestation_u.h"
#include "example_u.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_error.h"
#include "sgx_pce.h"
#include "sgx_quote_3.h"
#endif

#include "attestation/common/bytes.h"
#include "attestation/common/protobuf.h"
#include "attestation/generation/ua_generation.h"
#include "unified_attestation/ua_untrusted.h"

namespace py = pybind11;

#ifndef SGX_VERIFY_ONLY
static const uint32_t errmsg_max_len = 1024;

static void get_enclave_errmsg(sgx_enclave_id_t eid, std::string ecall_name,
                               char *errmsg, uint32_t size) {
  std::stringstream ss;
  sgx_status_t status;
  status = ecall_get_error_message(eid, errmsg, errmsg_max_len);
  if (status == SGX_SUCCESS)
    ss << "Error during " << ecall_name << ": " << errmsg << ".";
  else
    ss << "Error during " << ecall_name << ": Unknown error.";
}

static uint64_t init_enclave(std::string &enclave_path, bool allow_debug) {
  sgx_enclave_id_t eid = 0;
  sgx_status_t status = sgx_create_enclave(enclave_path.c_str(), allow_debug,
                                           nullptr, nullptr, &eid, nullptr);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Create enclave failed, path " << enclave_path << ", sgx error "
       << status;
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (allow_debug)
    LOG(INFO) << "Create SGX enclave, enable debug, enclave path "
              << enclave_path << ", enclave id 0x" << std::hex << eid << ".";
  else
    LOG(INFO) << "Create SGX enclave, disable debug, enclave path "
              << enclave_path << ", enclave id 0x" << std::hex << eid << ".";

  return eid;
}

static void fini_enclave(uint64_t eid) {
  sgx_destroy_enclave(eid);
  LOG(INFO) << "Destroy enclave, enclave id 0x" << std::hex << eid << ".";
}

static std::tuple<py::bytes, py::bytes, py::bytes> gen_then_export_key_and_csr(
    uint64_t u64_eid, std::string common_name, std::string organization_name) {
  sgx_enclave_id_t eid = static_cast<sgx_enclave_id_t>(u64_eid);
  int enclave_ret = 0;

  // Generate rsa key.
  sgx_status_t status = ecall_generate_rsa_key(
      eid, &enclave_ret,
      reinterpret_cast<const unsigned char *>(common_name.c_str()),
      reinterpret_cast<const unsigned char *>(organization_name.c_str()));
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_generate_rsa_key failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != 0) {
    char errmsg[errmsg_max_len];
    std::string ecall_name = "ecall_generate_rsa_key";
    get_enclave_errmsg(eid, ecall_name, errmsg, errmsg_max_len);
    LOG(ERROR) << errmsg;
    throw std::runtime_error(errmsg);
  }

  // Get key size.
  uint32_t private_key_size = 0;
  uint32_t public_key_size = 0;
  status = ecall_get_rsa_key_size(eid, &enclave_ret, &private_key_size,
                                  &public_key_size);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_get_rsa_key_size failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != 0) {
    char errmsg[errmsg_max_len];
    std::string ecall_name = "ecall_get_rsa_key_size";
    get_enclave_errmsg(eid, ecall_name, errmsg, errmsg_max_len);
    LOG(ERROR) << errmsg;
    throw std::runtime_error(errmsg);
  }

  LOG(INFO) << "Size of RSA public key " << public_key_size
            << ", size of sealed RSA private key " << private_key_size << ".";

  // Get RSA key.
  std::string priv_key;
  std::string pub_key;

  priv_key.resize(private_key_size);
  pub_key.resize(public_key_size);

  uint8_t *priv_key_ptr =
      reinterpret_cast<uint8_t *>(const_cast<char *>(priv_key.data()));
  uint8_t *pub_key_ptr =
      reinterpret_cast<uint8_t *>(const_cast<char *>(pub_key.data()));

  status = ecall_export_rsa_key(eid, &enclave_ret, priv_key_ptr, pub_key_ptr,
                                static_cast<uint32_t>(priv_key.size()),
                                static_cast<uint32_t>(pub_key.size()));
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_export_rsa_key failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != 0) {
    char errmsg[errmsg_max_len];
    std::string ecall_name = "ecall_export_rsa_key";
    get_enclave_errmsg(eid, ecall_name, errmsg, errmsg_max_len);
    LOG(ERROR) << errmsg;
    throw std::runtime_error(errmsg);
  }

  LOG(INFO) << "Get RSA public key and sealed private key finish.";

  // Get size of CSR content.
  uint32_t csr_size = 0;
  status = ecall_get_csr_size(eid, &enclave_ret, &csr_size);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_get_csr_size failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != 0) {
    char errmsg[errmsg_max_len];
    std::string ecall_name = "ecall_get_csr_size";
    get_enclave_errmsg(eid, ecall_name, errmsg, errmsg_max_len);
    LOG(ERROR) << errmsg;
    throw std::runtime_error(errmsg);
  }

  LOG(INFO) << "Size of CSR content " << csr_size << ".";

  // Get CSR content.
  std::string csr_content;
  csr_content.resize(csr_size);

  char *csr_ptr = const_cast<char *>(csr_content.c_str());
  status = ecall_get_csr_content(eid, &enclave_ret, csr_ptr, csr_size);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_get_csr_content failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != 0) {
    char errmsg[errmsg_max_len];
    std::string ecall_name = "ecall_get_csr_content";
    get_enclave_errmsg(eid, ecall_name, errmsg, errmsg_max_len);
    LOG(ERROR) << errmsg;
    throw std::runtime_error(errmsg);
  }

  LOG(INFO) << "Get CSR content finish.";

  // Return to python.
  py::bytes priv_key_obj(priv_key);
  py::bytes pub_key_obj(pub_key);
  py::bytes csr_obj(csr_content);

  return std::make_tuple(priv_key_obj, pub_key_obj, csr_obj);
}

static void import_key(uint64_t u64_eid, std::string priv_key,
                       std::string pub_key) {
  uint8_t *priv_key_ptr =
      reinterpret_cast<uint8_t *>(const_cast<char *>(priv_key.data()));
  uint8_t *pub_key_ptr =
      reinterpret_cast<uint8_t *>(const_cast<char *>(pub_key.data()));

  uint32_t priv_key_size = priv_key.size();
  uint32_t pub_key_size = pub_key.size();

  sgx_enclave_id_t eid = static_cast<sgx_enclave_id_t>(u64_eid);

  int enclave_ret = 0;
  sgx_status_t status =
      ecall_import_rsa_key(eid, &enclave_ret, priv_key_ptr, priv_key_size,
                           pub_key_ptr, pub_key_size);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_import_rsa_key failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != 0) {
    char errmsg[errmsg_max_len];
    std::string ecall_name = "ecall_import_rsa_key";
    get_enclave_errmsg(eid, ecall_name, errmsg, errmsg_max_len);
    LOG(ERROR) << errmsg;
    throw std::runtime_error(errmsg);
  }

  return;
}

static py::bytes get_nonce(uint64_t u64_eid) {
  sgx_enclave_id_t eid = static_cast<sgx_enclave_id_t>(u64_eid);
  std::string nonce;
  nonce.resize(SGX_REPORT_DATA_SIZE);

  unsigned char *nonce_ptr =
      reinterpret_cast<unsigned char *>(const_cast<char *>(nonce.data()));

  int enclave_ret = 0;
  sgx_status_t status =
      ecall_generate_nonce(eid, &enclave_ret, nonce_ptr, SGX_REPORT_DATA_SIZE);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_generate_nonce failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != 0) {
    char errmsg[errmsg_max_len];
    std::string ecall_name = "ecall_import_rsa_key";
    get_enclave_errmsg(eid, ecall_name, errmsg, errmsg_max_len);
    LOG(ERROR) << errmsg;
    throw std::runtime_error(errmsg);
  }

  return nonce;
}

static int check_nonce(uint64_t u64_eid, std::string nonce) {
  sgx_enclave_id_t eid = static_cast<sgx_enclave_id_t>(u64_eid);
  unsigned char *nonce_ptr =
      reinterpret_cast<unsigned char *>(const_cast<char *>(nonce.data()));

  int enclave_ret = 0;
  sgx_status_t status =
      ecall_check_nonce(eid, &enclave_ret, nonce_ptr, nonce.size());
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_check_nonce failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != 0) {
    char errmsg[errmsg_max_len];
    std::string ecall_name = "ecall_check_nonce";
    get_enclave_errmsg(eid, ecall_name, errmsg, errmsg_max_len);
    LOG(ERROR) << errmsg;
    throw std::runtime_error(errmsg);
  }

  return 1;
}

static py::bytes gen_sig(uint64_t u64_eid, std::string msg) {
  sgx_enclave_id_t eid = static_cast<sgx_enclave_id_t>(u64_eid);

  unsigned char *msg_ptr =
      reinterpret_cast<unsigned char *>(const_cast<char *>(msg.data()));
  uint32_t msg_size = msg.size();

  int enclave_ret = 0;
  sgx_status_t status =
      ecall_gen_signature(eid, &enclave_ret, msg_ptr, msg_size);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_gen_signature failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != 0) {
    char errmsg[errmsg_max_len];
    std::string ecall_name = "ecall_gen_signature";
    get_enclave_errmsg(eid, ecall_name, errmsg, errmsg_max_len);
    LOG(ERROR) << errmsg;
    throw std::runtime_error(errmsg);
  }

  uint32_t sig_size = 0;
  status = ecall_get_signature_size(eid, &enclave_ret, &sig_size);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_get_signature_size failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != 0) {
    char errmsg[errmsg_max_len];
    std::string ecall_name = "ecall_get_signature_size";
    get_enclave_errmsg(eid, ecall_name, errmsg, errmsg_max_len);
    LOG(ERROR) << errmsg;
    throw std::runtime_error(errmsg);
  }

  std::string sig;
  sig.resize(sig_size);

  unsigned char *sig_ptr =
      reinterpret_cast<unsigned char *>(const_cast<char *>(sig.data()));

  status = ecall_get_signature(eid, &enclave_ret, sig_ptr, sig_size);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_get_signature failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != 0) {
    char errmsg[errmsg_max_len];
    std::string ecall_name = "ecall_get_signature";
    get_enclave_errmsg(eid, ecall_name, errmsg, errmsg_max_len);
    LOG(ERROR) << errmsg;
    throw std::runtime_error(errmsg);
  }

  return py::bytes(sig);
}

static int gen_policy_from_proof(const std::string &auth_json,
                                 std::string &policy_json) {
  kubetee::UnifiedAttestationAuthReport auth_report;
  kubetee::UnifiedAttestationAttributes attr;
  JSON2PB(auth_json, &auth_report);
  TEE_CHECK_RETURN(UaGetAuthReportAttr(auth_report, &attr));

  kubetee::UnifiedAttestationPolicy policy;
  policy.set_pem_public_key(auth_report.pem_public_key());
  policy.add_main_attributes()->CopyFrom(attr);

  PB2JSON(policy, &policy_json);
  return 0;
}

static std::tuple<py::bytes, py::bytes> gen_proof(uint64_t u64_eid,
                                                  std::string sgx_report) {
  uint8_t *report_ptr =
      reinterpret_cast<uint8_t *>(const_cast<char *>(sgx_report.data()));
  DataBytes report_bytes(report_ptr, sgx_report.size());
  std::string report_hex_str = report_bytes.ToHexStr().GetStr();

  std::string tee_identity = std::to_string(u64_eid);
  std::string report_type = "Passport";

  std::string auth_json;
  TeeErrorCode ret = TEE_ERROR_GENERIC;
  do {
    UaReportGenerationParameters report_param;
    report_param.tee_identity = tee_identity;
    report_param.report_type = report_type;
    report_param.sgx_report_hex = report_hex_str;

    ret = UaGenerateAuthReportJson(&report_param, &auth_json);
    if (ret != 0) {
      TEE_LOG_ERROR("Fail to generate proof: 0x%X\n", ret);
      break;
    }
  } while (0);

  if (ret != TEE_SUCCESS) {
    char errmsg[errmsg_max_len];
    snprintf(errmsg, errmsg_max_len,
             "Generate sgx proof failed, error code 0x%x.", ret);
    throw std::runtime_error(errmsg);
  }

  std::string policy_json;
  int error = gen_policy_from_proof(auth_json, policy_json);
  if (error != 0) {
    throw std::runtime_error("Generate policy for sgx failed.");
  }

  py::bytes proof_bytes(auth_json);
  py::bytes policy_bytes(policy_json);

  return std::make_tuple(proof_bytes, policy_json);
}

#endif

static int verify_proof(std::string sgx_proof_json, std::string policy_json,
                        std::string pub_key) {
  kubetee::UnifiedAttestationAuthReport auth_report;
  JSON2PB(sgx_proof_json, &auth_report);
  std::string report_type = auth_report.report().str_report_type();

  if (report_type != "Passport") {
    LOG(ERROR) << "Don't support report type " << report_type << ".";
    return -1;
  }

  kubetee::UnifiedAttestationPolicy policy;
  JSON2PB(policy_json, &policy);
  policy.set_pem_public_key(pub_key);

  std::string new_policy_json;
  PB2JSON(policy, &new_policy_json);

  if (UaVerifyAuthReportJson(sgx_proof_json, new_policy_json) != TEE_SUCCESS) {
    LOG(ERROR) << "Verify SGX proof failed.";
    return -1;
  }

  return 0;
}

#ifndef SGX_VERIFY_ONLY

static TeeErrorCode decode_proof_json(const std::string &proof_json,
                                      kubetee::DcapReport &dcap_report) {
  kubetee::UnifiedAttestationAuthReport auth;
  JSON2PB(proof_json, &auth);

  const auto &report = auth.report();
  JSON2PB(report.json_report(), &dcap_report);

  return 0;
}

static py::bytes get_report_data(std::string sgx_proof_json) {
  kubetee::DcapReport dcap_report;
  if (decode_proof_json(sgx_proof_json, dcap_report) != TEE_SUCCESS) {
    LOG(ERROR) << "Decode proof json of sgx platform failed.";
    throw std::runtime_error("Decode proof json of sgx platform failed.");
  }

  std::string b64_quote_body = dcap_report.b64_quote();
  kubetee::common::DataBytes quote;
  quote.SetValue(b64_quote_body);

  sgx_quote3_t *quote_ptr = RCAST(sgx_quote3_t *, quote.data());
  uint8_t *data_ptr = quote_ptr->report_body.report_data.d;

  return std::string(reinterpret_cast<char *>(data_ptr), SGX_REPORT_DATA_SIZE);
}

static int load_qe(void) {
  constexpr char kRhelLikeLibDir[] = "/usr/lib64/";
  constexpr char kUbuntuLikeLibDir[] = "/usr/lib/x86_64-linux-gnu/";
  constexpr char kPceLib[] = "libsgx_pce.signed.so";
  constexpr char kQe3Lib[] = "libsgx_qe3.signed.so";
  constexpr char kQplLib[] = "libdcap_quoteprov.so.1";

  LOG(INFO) << "Set the enclave load policy as persistent";
  quote3_error_t ret = sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT);
  if (SGX_QL_SUCCESS != ret) {
    LOG(ERROR) << "Error in set enclave load policy, error code " << ret << ".";
    return -1;
  }

  // Set the PCE/QE3/QPL library path
  std::string default_lib_dir;
  if (!access("/usr/bin/apt", R_OK))
    default_lib_dir.assign(kUbuntuLikeLibDir);
  else
    default_lib_dir.assign(kRhelLikeLibDir);

  LOG(INFO) << "DCAP library path: " << default_lib_dir.c_str() << ".";

  std::string pce_lib = default_lib_dir + kPceLib;
  std::string qe3_lib = default_lib_dir + kQe3Lib;
  std::string qpl_lib = default_lib_dir + kQplLib;
  ret = sgx_ql_set_path(SGX_QL_PCE_PATH, pce_lib.c_str());
  if (SGX_QL_SUCCESS != ret) {
    LOG(ERROR) << "Fail to set PCE path, error code " << ret << ".";
    return -1;
  }

  ret = sgx_ql_set_path(SGX_QL_QE3_PATH, qe3_lib.c_str());
  if (SGX_QL_SUCCESS != ret) {
    LOG(ERROR) << "Fail to set QE3 path, error code " << ret << ".";
    return -1;
  }

  ret = sgx_ql_set_path(SGX_QL_QPL_PATH, qpl_lib.c_str());
  if (SGX_QL_SUCCESS != ret) {
    // Ignore the error, because user may want to get cert type=3 quote
    LOG(WARNING) << "Cannot to set QPL path, error code " << ret << ".";
    LOG(WARNING) << "You may get ECDSA quote with `Encrypted PPID` cert type.";
  }

  return 0;
}

static py::bytes get_qe_target_info(std::string name) {
  LOG(INFO) << "Generate QE target info for " << name << ".";

  int ret = load_qe();
  if (ret != 0) {
    LOG(ERROR) << "Load SGX DCAP library failed.";
    throw std::runtime_error("Load SGX DCAP library failed.");
  }

  sgx_target_info_t qe_target_info;
  quote3_error_t qe_ret = sgx_qe_get_target_info(&qe_target_info);
  if (qe_ret != SGX_QL_SUCCESS) {
    std::stringstream ss;
    ss << "Fail to get target info, error code " << qe_ret << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  char *ptr = reinterpret_cast<char *>(&qe_target_info);
  return std::string(ptr, sizeof(qe_target_info));
}

static py::bytes gen_example_report(std::string enclave_path,
                                    std::string custom_data) {
  if (load_qe()) {
    LOG(ERROR) << "Load QE, PCE, QPL failed.";
    throw std::runtime_error("Load QE, PCE, QPL failed.");
  }

  sgx_enclave_id_t local_eid = 0;
  sgx_status_t status =
      sgx_create_enclave(enclave_path.c_str(), 0, NULL, NULL, &local_eid, NULL);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Create example enclave failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  sgx_target_info_t qe_target_info;
  quote3_error_t qe_ret = sgx_qe_get_target_info(&qe_target_info);
  if (qe_ret != SGX_QL_SUCCESS) {
    std::stringstream ss;
    ss << "Fail to get target info, error code " << qe_ret << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  uint8_t *data_ptr =
      reinterpret_cast<uint8_t *>(const_cast<char *>(custom_data.data()));

  sgx_report_t example_report;
  sgx_status_t enclave_ret;
  status = ecall_gen_report(local_eid, &enclave_ret, &qe_target_info, data_ptr,
                            custom_data.size(), &example_report);
  sgx_destroy_enclave(local_eid);

  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run ecall_gen_report failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (enclave_ret != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "" << status << "Failed to generate sgx report, sgx error "
       << enclave_ret << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  return std::string(reinterpret_cast<char *>(&example_report),
                     sizeof(example_report));
}
#endif

PYBIND11_MODULE(sgx_wrap, m) {
  m.doc() = "SGX wrapper.";
#ifndef SGX_VERIFY_ONLY
  m.def("init_enclave", &init_enclave, "Create SGX enclave.");
  m.def("fini_enclave", &fini_enclave, "Destroy SGX enclave.");
  m.def("import_key", &import_key, "Restore private key and public key.");
  m.def("gen_then_export_key_and_csr", &gen_then_export_key_and_csr,
        "Generate RSA key and CSR, then export public key, sealed "
        "private key, CSR.");
  m.def("get_nonce", &get_nonce, "Get nonce.");
  m.def("check_nonce", &check_nonce, "Check nonce.");
  m.def("gen_sig", &gen_sig, "Digital signature of message.");
      m.def("gen_proof", &gen_proof, "Generate proof of SGX.");
  m.def("get_report_data", &get_report_data, "Get report data from proof.");
  m.def("get_qe_target_info", &get_qe_target_info,
        "Get target info of quote enclave.");
  m.def("gen_example_report", &gen_example_report,
        "Generate a example SGX report");
#endif
  m.def("verify_proof", &verify_proof, "Verify proof of SGX.");
}
