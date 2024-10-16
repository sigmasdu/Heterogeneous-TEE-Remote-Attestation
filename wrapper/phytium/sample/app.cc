#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <dlfcn.h>

#include "unified_attestation/ua_untrusted.h"

#include "sample/app.h"

using kubetee::attestation::ReeInstance;
using kubetee::attestation::UaTeeInitParameters;

typedef int (*func_get_public_key)(uint8_t* public_key, size_t* public_key_size);

static TeeErrorCode get_phytium_public_key(uint8_t* public_key, size_t* public_key_size) {
  TeeErrorCode res = TEE_ERROR_GENERIC;
  void *handle = NULL;
  func_get_public_key fun_get_public_key = NULL;

  handle = dlopen("/lib/libuniattest.so", RTLD_LAZY);
  if (handle == NULL) {
    printf("load libuniattest.so failed, %s\n", dlerror());
    return TEE_ERROR_GENERIC;
  }

  fun_get_public_key = (func_get_public_key) dlsym(handle, "get_public_key");
  if (fun_get_public_key == NULL) {
    printf("find get_public_key failed, %s\n", dlerror());
    return TEE_ERROR_GENERIC;
  }

  res = fun_get_public_key(public_key, public_key_size);
  if (res != TEE_SUCCESS) {
    printf("call get_public_key failed, 0x%08x\n", res);
    return res;
  }

  if (handle != NULL) {
    dlclose(handle);
  }

  return TEE_SUCCESS;
}

int GenerateAuthReportJson(const std::string& report_type) {
  std::string tee_identity;
  UaTeeInitParameters param;
  param.trust_application = ENCLAVE;
  uint8_t pub_key[512];
  // size_t pub_key_size = sizeof(pub_key);
  TEE_CHECK_RETURN(ReeInstance::Initialize(param, &tee_identity));

  TeeErrorCode ret = TEE_ERROR_GENERIC;
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
    std::string pub_key_file = "/root/key/public.pem";
    std::string private_key_file = "/root/key/private.pem";
    if (!kubetee::utils::FsFileExists(private_key_file)) {
      kubetee::common::RsaCrypto crypto(2048);
      auto ret = crypto.GenerateKeyPair(&pub_key, &prv_key);
      if (ret != TEE_SUCCESS) {
        printf("generate key pair failed\n");
        return -1;
      }
      kubetee::utils::FsWriteString(pub_key_file, pub_key);
      kubetee::utils::FsWriteString(private_key_file, prv_key);
    }
    if (kubetee::utils::FsReadString(pub_key_file, &pub_key) != TEE_SUCCESS) {
      printf("Fail to load public key\n");
      return -1;
    }
    if (kubetee::utils::FsReadString(private_key_file, &prv_key) != TEE_SUCCESS) {
      printf("Fail to load public key\n");
      return -1;
    }
    report_param.others.set_pem_public_key(pub_key);
    
    // ret = get_phytium_public_key(pub_key, &pub_key_size);
    // if (ret == TEE_SUCCESS) {
    //     report_param.others.set_pem_public_key(std::string((char *)pub_key, pub_key_size));
    // }
    std::string auth_json;
    ret = UaGenerateAuthReportJson(&report_param, &auth_json);
    if (ret != 0) {
      TEE_LOG_ERROR("Fail to generate authentication report: 0x%X\n", ret);
      break;
    }

    // Save unified attestation report to local file
    std::string report_filename = "unified_attestation_auth_report_";
    report_filename.append(report_type + ".json");
    ret = kubetee::utils::FsWriteString(report_filename, auth_json);

    // Save unified attestation policy to local file
    kubetee::UnifiedAttestationAuthReport auth_report;
    kubetee::UnifiedAttestationAttributes attr;
    JSON2PB(auth_json, &auth_report);
    TEE_CHECK_RETURN(UaGetAuthReportAttr(auth_report, &attr));
    kubetee::UnifiedAttestationPolicy policy;
    policy.set_pem_public_key(auth_report.pem_public_key());
    policy.add_main_attributes()->CopyFrom(attr);
    std::string policy_json;
    PB2JSON(policy, &policy_json);
    std::string policy_filename = "unified_attestation_auth_policy_";
    policy_filename.append(report_type + ".json");
    ret = kubetee::utils::FsWriteString(policy_filename, policy_json);
  } while (0);

  TEE_CHECK_RETURN(ReeInstance::Finalize(tee_identity));
  return ret;
}

int main(int argc, char** argv) {
  // Decide the report types
  std::vector<const char*> types;
  if (argc >= 2) {
    for (int i = 1; i < argc; i++) {
      TEE_LOG_INFO("Add report type[%d] = %s\n", i, argv[i]);
      types.push_back(argv[i]);
    }
  } else {
    // types.push_back(kUaReportTypeBgcheck);
#ifndef SGX_MODE_SIM
    // Because Passport type need to connnect third party service
    // So, it's not working for simulation mode
    types.push_back(kUaReportTypePassport);
#endif
  }

  // Generate the reports
  for (auto iter = types.begin(); iter != types.end(); iter++) {
    TeeErrorCode ret = TEE_ERROR_GENERIC;
    if ((ret = GenerateAuthReportJson(*iter))) {
      TEE_LOG_ERROR("GenerateAuthReportJson(%s) failed\n", *iter);
      return ret;
    } else {
      TEE_LOG_INFO("GenerateAuthReportJson(%s) successfully!\n", *iter);
    }
  }
  return 0;
}
