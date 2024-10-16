#include <sgx_report.h>
#include <sgx_trts.h>
#include <sgx_urts.h>
#include <sgx_utils.h>

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_gen_report(sgx_target_info_t *qe_target_info,
                              uint8_t *custom_data, uint32_t custom_size,
                              sgx_report_t *report) {
  sgx_status_t status;
  sgx_report_data_t report_data;

  if (custom_size > SGX_REPORT_DATA_SIZE)
    custom_size = SGX_REPORT_DATA_SIZE;

  uint8_t *src = custom_data;
  uint8_t *dest = (uint8_t *)(&(report_data.d));
  memcpy(dest, src, custom_size);

  status = sgx_create_report(qe_target_info, &report_data, report);
  return status;
};

#ifdef __cplusplus
}
#endif
