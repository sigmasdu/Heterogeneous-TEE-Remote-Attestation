#include <err.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <glog/logging.h>
#include <pybind11/pybind11.h>

#include "unified_attestation/ua_untrusted.h"

#ifndef PHYTIUM_VERIFY_ONLY 
// clang-format off
#include "attestation_helper.h"
#include "helper_core.h"

#include <tee_client_api.h>
#include <teec_trace.h>
// clang-format on
#endif

namespace py = pybind11;
using kubetee::attestation::ReeInstance;
using kubetee::attestation::UaTeeInitParameters;

// static void bin_to_hex(const unsigned char *s, size_t l, char *d) {
//   static const char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7',
//                                    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
//   while (l--) {
//     *(d + 2 * l + 1) = hex_table[(*(s + l)) & 0x0f];
//     *(d + 2 * l) = hex_table[(*(s + l)) >> 4];
//   }
// }

#ifndef PHYTIUM_VERIFY_ONLY
static std::tuple<uint64_t, uint64_t> tee_init_session(void) {
  TEEC_Result res;
  TEEC_Context *ctx;
  TEEC_Session *sess;
  TEEC_UUID uuid = TA_HELPER_CORE_UUID;
  uint32_t err_origin;

  ctx = (TEEC_Context *)malloc(sizeof(TEEC_Context));
  sess = (TEEC_Session *)malloc(sizeof(TEEC_Session));

  res = TEEC_InitializeContext(NULL, ctx);
  if (res != TEEC_SUCCESS) {
    std::stringstream ss;
    ss << "TEEC_InitializeContext failed with code " << res << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  res = TEEC_OpenSession(ctx, sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
                         &err_origin);
  if (res != TEEC_SUCCESS) {
    std::stringstream ss;
    ss << "TEEC_Opensession failed with code " << res << ", origin "
       << err_origin << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  return std::make_tuple((uint64_t)ctx, (uint64_t)sess);
}

static void tee_destroy_session(std::tuple<uint64_t, uint64_t> ctx_and_sess) {
  TEEC_Context *ctx = (TEEC_Context *)(std::get<0>(ctx_and_sess));
  TEEC_Session *sess = (TEEC_Session *)(std::get<1>(ctx_and_sess));

  TEEC_CloseSession(sess);
  TEEC_FinalizeContext(ctx);

  free(ctx);
  free(sess);
}

static std::tuple<py::bytes, py::bytes, py::bytes, py::bytes>
tee_gen_key_and_csr(std::tuple<uint64_t, uint64_t> ctx_and_sess) {
  TEEC_Operation op;
  uint32_t err_origin;
  TEEC_Result res;

  TEEC_Session *sess = (TEEC_Session *)(std::get<1>(ctx_and_sess));

  // Init helper.
  memset(&op, 0, sizeof(op));
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
  res = TEEC_InvokeCommand(sess, HELPER_INIT, &op, &err_origin);
  if (res != TEEC_SUCCESS) {
    std::stringstream ss;
    ss << "TEEC_InvokeCommand HELPER_INIT failed with code " << res
       << ", origin " << err_origin << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  // Generate RSA key and CSR.
  memset(&op, 0, sizeof(op));
  op.paramTypes =
      TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
                       TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);

  std::string csr_content;
  csr_content.resize(1024);

  std::string pub_key;
  pub_key.resize(2048);

  std::string priv_key;
  priv_key.resize(2048);

  std::string mac;
  mac.resize(32);

  op.params[0].tmpref.buffer = (char *)csr_content.data();
  op.params[0].tmpref.size = 1024;
  op.params[1].tmpref.buffer = (char *)pub_key.data();
  op.params[1].tmpref.size = 2048;
  op.params[2].tmpref.buffer = (char *)priv_key.data();
  op.params[2].tmpref.size = 2048;
  op.params[3].tmpref.buffer = (char *)mac.data();
  op.params[3].tmpref.size = 32;

  res = TEEC_InvokeCommand(sess, HELPER_GEN_KEY_AND_CSR, &op, &err_origin);
  if (res != TEEC_SUCCESS) {
    std::stringstream ss;
    ss << "TEEC_InvokeCommand HELPER_GEN_KEY_AND_CSR failed with code " << res
       << ", origin " << err_origin << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  LOG(INFO) << "Length of certificate signing request is " << csr_content.size()
            << ".";
  LOG(INFO) << "Length of public key is " << pub_key.size() << ".";
  LOG(INFO) << "Length of sealed private key is " << priv_key.size() << ".";
  LOG(INFO) << "Length of mac is " << mac.size() << ".";

  return std::make_tuple(py::bytes(csr_content), py::bytes(priv_key),
                         py::bytes(pub_key), py::bytes(mac));
}

static py::bytes tee_gen_sig(std::tuple<uint64_t, uint64_t> handle,
                             std::string msg, std::string seal_key,
                             std::string mac) {
  TEEC_Operation op;
  uint32_t err_origin;
  TEEC_Result res;

  if (seal_key.size() != 2048) {
    std::stringstream ss;
    ss << "Length of sealed private key must 2048, but give sealed key with "
       << seal_key.size() << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  if (mac.size() != 32) {
    std::stringstream ss;
    ss << "Length of mac must be 32, but give mac with " << mac.size() << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  TEEC_Session *sess = (TEEC_Session *)(std::get<1>(handle));
  memset(&op, 0, sizeof(op));
  op.paramTypes =
      TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                       TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);

  op.params[0].tmpref.buffer = (char *)seal_key.data();
  op.params[0].tmpref.size = 2048;
  op.params[1].tmpref.buffer = (char *)mac.data();
  op.params[1].tmpref.size = 32;

  op.params[2].tmpref.buffer = (char *)msg.data();
  op.params[2].tmpref.size = msg.size();

  std::string sig_result;
  sig_result.resize(2048);

  op.params[3].tmpref.buffer = (char *)sig_result.data();
  op.params[3].tmpref.size = 2048;

  res = TEEC_InvokeCommand(sess, HELPER_DIGITAL_SIGNATURE, &op, &err_origin);
  if (res != TEEC_SUCCESS) {
    std::stringstream ss;
    ss << "TEEC_InvokeCommand HELPER_DIGITAL_SIGNATURE failed with code " << res
       << ", origin " << err_origin << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  LOG(INFO) << "Length of signature result in hex format is "
            << strlen(sig_result.data()) << ".";

  return py::bytes(sig_result.substr(0, strlen(sig_result.data())));
}

static TeeErrorCode GenerateAuthReportJson(std::string *report_json,
                                           std::string *policy_json) {
  std::string report_type = kUaReportTypePassport;
  std::string auth_json;
  std::string tee_identity;
  UaTeeInitParameters param;

  int ret = TEE_ERROR_GENERIC;
  do {
    // Generate the unified attestation report
    UaReportGenerationParameters report_param;
    report_param.tee_identity = "None";
    report_param.report_type = report_type;
    report_param.report_hex_nonce = "31323334";
    ret = UaGenerateAuthReportJson(&report_param, &auth_json);
    if (ret != 0) {
      TEE_LOG_ERROR("Fail to generate authentication report: 0x%X\n", ret);
      return TEE_ERROR_GENERIC;
    }

    kubetee::UnifiedAttestationAuthReport auth_report;
    kubetee::UnifiedAttestationAttributes attr;
    JSON2PB(auth_json, &auth_report);
    TEE_CHECK_RETURN(UaGetAuthReportAttr(auth_report, &attr));
    kubetee::UnifiedAttestationPolicy policy;
    policy.set_pem_public_key(auth_report.pem_public_key());
    policy.add_main_attributes()->CopyFrom(attr);
    PB2JSON(policy, policy_json);
  } while (0);

  *report_json = std::move(auth_json);
  return TEE_SUCCESS;
}

static std::tuple<py::bytes, py::bytes> gen_phytium_proof(void) {
  std::string json_report;
  std::string json_policy;
  auto ret = GenerateAuthReportJson(&json_report, &json_policy);
  if (ret != TEE_SUCCESS) {
    throw py::value_error("GenerateAuthReportJson failed");
  }

  py::bytes result(json_report);
  py::bytes policy(json_policy);

  return std::make_tuple(result, policy);
}
#else
static int verify_phytium_proof(const std::string &report_json,
                                const std::string &policy_json) {
  kubetee::UnifiedAttestationAuthReport auth_report;
  JSON2PB(report_json, &auth_report);
  std::string report_type = auth_report.report().str_report_type();
  TEE_CHECK_RETURN(UaVerifyAuthReportJson(report_json, policy_json));

  TEE_LOG_INFO("Verify %s type report successfully!", report_type.c_str());
  return 0;
}
#endif

PYBIND11_MODULE(phytium_wrap, m) {
  m.doc() = "Python wrapper for the operation in phytium tee.";
#ifndef PHYTIUM_VERIFY_ONLY
  m.def("tee_init_session", &tee_init_session, "Init tee session.");
  m.def("tee_gen_key_and_csr", &tee_gen_key_and_csr,
        "Generate RSA key and certificate signing request.");
  m.def("tee_gen_sig", &tee_gen_sig, "Generate digital signature.");
  m.def("tee_destroy_session", &tee_destroy_session, "Destroy tee session.");
  m.def("gen_phytium_proof", &gen_phytium_proof,
        "Generate device proof of phyitum tee.");
#else
  m.def("verify_phytium_proof", &verify_phytium_proof,
        "Verify device proof of phytium tee.");
#endif
}
