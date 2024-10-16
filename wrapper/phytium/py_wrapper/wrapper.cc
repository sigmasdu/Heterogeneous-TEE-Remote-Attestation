#include "wrapper.h"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <dlfcn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <pybind11/pybind11.h>
#include "unified_attestation/ua_untrusted.h"
#define PUB_KEY_FILE "/root/key/public.pem"
#define PRV_KEY_FILE "/root/key/private.pem"
namespace py = pybind11;
using kubetee::attestation::ReeInstance;
using kubetee::attestation::UaTeeInitParameters;
TeeErrorCode GetKeyPair(std::string* pub_key, std::string* prv_key) {
  std::string pub_key_file = PUB_KEY_FILE;
  std::string private_key_file = PRV_KEY_FILE;
  if (!kubetee::utils::FsFileExists(private_key_file)) {
    kubetee::common::RsaCrypto crypto(2048, true);
    auto ret = crypto.GenerateKeyPair(pub_key, prv_key);
    if (ret != TEE_SUCCESS) {
      printf("generate key pair failed\n");
      return TEE_ERROR_GENERIC;
    }
    kubetee::utils::FsWriteString(pub_key_file, *pub_key);
    kubetee::utils::FsWriteString(private_key_file, *prv_key);
    return TEE_SUCCESS;
  }
  if (kubetee::utils::FsReadString(pub_key_file, pub_key) != TEE_SUCCESS) {
    printf("Fail to load public key\n");
    return TEE_ERROR_GENERIC;
  }
  if (kubetee::utils::FsReadString(private_key_file, prv_key) != TEE_SUCCESS) {
    printf("Fail to load public key\n");
    return TEE_ERROR_GENERIC;
  }
  return TEE_SUCCESS;
}

// generate csr
static TeeErrorCode GenerateCsr(const std::string& common, const std::string& org, std::string* csr_content) {
  X509_REQ *x509_req = nullptr;
  X509_NAME *x509_name = nullptr;
  EVP_PKEY *pKey = nullptr;
  RSA *r = nullptr;
  std::string pub_key;
  std::string prv_key;
  GetKeyPair(&pub_key, &prv_key);
  const char *szCountry = "CN";
  const char *szProvince = "BJ";
  const char *szCity = "BJ";

  BIO *bio = nullptr;
  char *buf = nullptr;

  do {
    // 2. set version of x509 req
    x509_req = X509_REQ_new();
    int ret = X509_REQ_set_version(x509_req, 0);
    x509_name = X509_REQ_get_subject_name(x509_req);

    ret = X509_NAME_add_entry_by_txt(
        x509_name, "C", MBSTRING_ASC,
        reinterpret_cast<const unsigned char *>(szCountry), -1, -1, 0);

    ret = X509_NAME_add_entry_by_txt(
        x509_name, "ST", MBSTRING_ASC,
        reinterpret_cast<const unsigned char *>(szProvince), -1, -1, 0);
    ret = X509_NAME_add_entry_by_txt(
        x509_name, "L", MBSTRING_ASC,
        reinterpret_cast<const unsigned char *>(szCity), -1, -1, 0);
    ret = X509_NAME_add_entry_by_txt(
        x509_name, "O", MBSTRING_ASC,
        reinterpret_cast<const unsigned char *>(org.c_str()), -1, -1, 0);
    ret = X509_NAME_add_entry_by_txt(
        x509_name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char *>(common.c_str()), -1, -1, 0);

    bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, pub_key.c_str());
    pKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if(!pKey) {
      ret = 0;
      printf("PEM_read_bio_PrivateKey error\n");
      BIO_free(bio);
      break;
    }

    ret = X509_REQ_set_pubkey(x509_req, pKey);
    if (ret != 1) {
      printf("X509 REQ set pubkey error\n");
      BIO_free(bio);
      break;
    }

    BIO_puts(bio, prv_key.c_str());
    r = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    if(!r) {
      printf("X509 REQ set private key error\n");
      BIO_free(bio);
      break;
    }
    BIO_free(bio);

    // 5. set sign key of x509 req
    EVP_PKEY_set1_RSA(pKey, r);
    ret = X509_REQ_sign(x509_req, pKey, EVP_sha256());
    if (ret <= 0) {
      printf("X509 REQ sign error\n");
      break;
    }

    bio = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_X509_REQ(bio, x509_req);
    auto data_size = BIO_get_mem_data(bio, &buf);
    *csr_content = std::string(buf, data_size);
    BIO_free(bio);
  } while (0);

  X509_REQ_free(x509_req);
  EVP_PKEY_free(pKey);
  return TEE_SUCCESS;
}

static py::bytes GenerateCsrWrapper(const std::string& common, const std::string& org) {
  std::string csr_content;
  auto ret = GenerateCsr(common, org, &csr_content);
  if (ret != TEE_SUCCESS) {
    throw py::value_error("GenerateCsr failed"); 
  }
  py::bytes csr_content_bytes(csr_content);
  return csr_content_bytes; 
}

// generate report
static TeeErrorCode GenerateAuthReportJson(std::string* report_json, std::string* policy_json) {
  std::string report_type = kUaReportTypePassport;
  std::string auth_json;
  std::string tee_identity;
  UaTeeInitParameters param;
  param.trust_application = ENCLAVE;
  // uint8_t pub_key[512];
  // size_t pub_key_size = sizeof(pub_key);
  TEE_CHECK_RETURN(ReeInstance::Initialize(param, &tee_identity));

  int ret = TEE_ERROR_GENERIC;
  do {
    // Generate the unified attestation report
    UaReportGenerationParameters report_param;
    report_param.tee_identity = tee_identity;
    report_param.report_type = report_type;
    // Both report nonce and user data use hex string
    // and will be decoded before saved in report.
    // In SGX liked TEE, they are saved into the same place,
    // So we cannot set them at the same tiime
    report_param.report_hex_nonce = "31323334";
    // report_param.others.set_hex_user_data("31323334");
    std::string pub_key;
    std::string prv_key;
    GetKeyPair(&pub_key, &prv_key);
    report_param.others.set_pem_public_key(pub_key);

    // ret = get_phytium_public_key(pub_key, &pub_key_size);
    // if (ret == TEE_SUCCESS) {
    //     report_param.others.set_pem_public_key(std::string((char *)pub_key, pub_key_size));
    // }
    ret = UaGenerateAuthReportJson(&report_param, &auth_json);
    if (ret != 0) {
      TEE_LOG_ERROR("Fail to generate authentication report: 0x%X\n", ret);
      return TEE_ERROR_GENERIC;
    }

    // // Save unified attestation report to local file
    // std::string report_filename = "unified_attestation_auth_report_";
    // report_filename.append(report_type + ".json");
    // ret = kubetee::utils::FsWriteString(report_filename, auth_json);

    // Save unified attestation policy to local file
    kubetee::UnifiedAttestationAuthReport auth_report;
    kubetee::UnifiedAttestationAttributes attr;
    JSON2PB(auth_json, &auth_report);
    TEE_CHECK_RETURN(UaGetAuthReportAttr(auth_report, &attr));
    kubetee::UnifiedAttestationPolicy policy;
    policy.set_pem_public_key(auth_report.pem_public_key());
    policy.add_main_attributes()->CopyFrom(attr);
    // std::string policy_json;
    PB2JSON(policy, policy_json);
    // std::string policy_filename = "unified_attestation_auth_policy_";
    // policy_filename.append(report_type + ".json");
    // ret = kubetee::utils::FsWriteString(policy_filename, policy_json);
  } while (0);

  TEE_CHECK_RETURN(ReeInstance::Finalize(tee_identity));
  *report_json = std::move(auth_json);
  return TEE_SUCCESS;;
}

static std::tuple<py::bytes, py::bytes> GenerateAuthReportJsonWrapper() {
  std::string json_report;
  std::string json_policy;
  auto ret = GenerateAuthReportJson(&json_report, &json_policy);
  if (ret != TEE_SUCCESS) {
    throw py::value_error("GenerateAuthReportJson failed");
  }
  py::bytes result(json_report);
  py::bytes policy(json_policy);
  return std::make_tuple(result, policy);; 
}

// verify report
int UntrustAuthReportVerify(const std::string& report_json,
                            const std::string& policy_json) {
  // Cannot verify BackgroundCheck type report directly,
  // convert it to Passport type report firstly.
  kubetee::UnifiedAttestationAuthReport auth_report;
  JSON2PB(report_json, &auth_report);
  std::string report_type = auth_report.report().str_report_type();
#ifndef SGX_MODE_SIM
  if (report_type == kUaReportTypeBgcheck) {
    std::string auth_json = report_json;
    kubetee::attestation::ReportConvert covert;
    TEE_CHECK_RETURN(covert.BgcheckToPassportAuthJson(report_json, &auth_json));
    TEE_CHECK_RETURN(UaVerifyAuthReportJson(auth_json, policy_json));
  } else
#endif
  {
    TEE_CHECK_RETURN(UaVerifyAuthReportJson(report_json, policy_json));
  }

  TEE_LOG_INFO("Verify %s type report successfully!", report_type.c_str());
  return 0;
}

PYBIND11_MODULE(phytium_attestation, m) {
  m.doc() = "PHYTIUM wrapper.";
  m.def("generate_report", &GenerateAuthReportJsonWrapper, "Generate phytimum report.");
  m.def("verify_report", &UntrustAuthReportVerify, "Verify phytimum report.");
  m.def("gen_csr", &GenerateCsrWrapper, "generate csr.");
}

