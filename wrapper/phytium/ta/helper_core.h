#ifndef HELPER_CORE_H_
#define HELPER_CORE_H_

#define TA_HELPER_CORE_UUID                          \
  {                                                  \
    0x30097836, 0xa15b, 0x40d8, {                    \
      0xbd, 0x87, 0x92, 0x96, 0x39, 0x3d, 0x0a, 0xa7 \
    }                                                \
  }

enum {
  HELPER_INIT,
  HELPER_GEN_KEY_AND_CSR,
  HELPER_DIGITAL_SIGNATURE,
};

#endif
