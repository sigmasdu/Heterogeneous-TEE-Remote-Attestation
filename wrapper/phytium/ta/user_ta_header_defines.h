#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include "helper_core.h"

#define TA_UUID TA_HELPER_CORE_UUID
 
#define TA_FLAGS                    (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE               (1024 * 1024)
#define TA_DATA_SIZE                (1024 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
        { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
                "Attestation helper" }, \
        { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }


#endif /*USER_TA_HEADER_DEFINES_H*/
