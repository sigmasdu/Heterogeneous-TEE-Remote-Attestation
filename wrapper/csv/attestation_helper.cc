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

namespace py = pybind11;

// static void bin_to_hex(const unsigned char *s, size_t l, char *d) {
//   static const char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7',
//                                    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
//   while (l--) {
//     *(d + 2 * l + 1) = hex_table[(*(s + l)) & 0x0f];
//     *(d + 2 * l) = hex_table[(*(s + l)) >> 4];
//   }
// }

#ifndef CSV_VERIFY_ONLY
static TeeErrorCode GenerateAuthReportJson(std::string *report_json,
                                           std::string *policy_json) {
  std::string report_type = kUaReportTypePassport;
  std::string auth_json;
  std::string tee_identity;

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

static std::tuple<py::bytes, py::bytes> gen_csv_proof(void) {
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
static int verify_csv_proof(const std::string &report_json,
                                const std::string &policy_json) {
  kubetee::UnifiedAttestationAuthReport auth_report;
  JSON2PB(report_json, &auth_report);
  std::string report_type = auth_report.report().str_report_type();
  TEE_CHECK_RETURN(UaVerifyAuthReportJson(report_json, policy_json));

  TEE_LOG_INFO("Verify %s type report successfully!", report_type.c_str());
  return 0;
}
#endif

PYBIND11_MODULE(csv_wrap, m) {
  m.doc() = "Python wrapper for the operation in csv tee.";
#ifndef CSV_VERIFY_ONLY
  m.def("gen_csv_proof", &gen_csv_proof,
        "Generate device proof of csv tee.");
#else
  m.def("verify_csv_proof", &verify_csv_proof,
        "Verify device proof of csv tee.");
#endif
}

