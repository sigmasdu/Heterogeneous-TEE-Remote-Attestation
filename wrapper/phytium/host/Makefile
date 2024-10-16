CC      = $(CROSS_COMPILE)gcc
CXX     = $(CROSS_COMPILE)g++
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

TEEC_EXPORT = /data/link/export/usr

# For pybind11.
PYBIND11_INCLUDE_PATH := $(shell python3 -m pybind11 --includes)
PYTHON_LIBRARY_SUFFIX := $(shell python3-config --extension-suffix)
PYTHON_INCLUDE_PATH := $(shell python3-config --includes)

# For jinzhao-attest.
JINZHAO_LIB_DIR := /root/jinzhao_lib_phytium/lib/
JINZHAO_INCLUDE_DIR := /root/jinzhao_lib_phytium/include/ 


CFLAGS += -Wall -I../ta/ -I$(TEEC_EXPORT)/include -I./ \
          $(PYBIND11_INCLUDE_PATH) $(PYTHON_INCLUDE_PATH) \
          -I $(JINZHAO_INCLUDE_DIR)

LDADD += -lteec -L$(TEEC_EXPORT)/lib -L$(JINZHAO_LIB_DIR) -lual -lpthread -lcrypto -lglog

CFLAGS_FOR_VERIFY = -DPHYTIUM_VERIFY_ONLY $(PYBIND11_INCLUDE_PATH) $(PYTHON_INCLUDE_PATH) -I $(JINZHAO_INCLUDE_DIR)
LDFLAGS_FOR_VERIFY = -L$(JINZHAO_LIB_DIR) -lual -lpthread -lcrypto -lglog

.PHONY: all
all: python_module 

python_module:attestation_helper.cc
	$(CXX) -O3 -Wall -shared -std=c++11 -fPIC attestation_helper.cc ${CFLAGS} -o phytium_wrap$(PYTHON_LIBRARY_SUFFIX) $(LDADD)

verify: attestation_helper.cc
	$(CXX) -O3 -Wall -shared -std=c++11 -fPIC attestation_helper.cc $(CFLAGS_FOR_VERIFY) $(LDFLAGS_FOR_VERIFY) -o phytium_wrap$(PYTHON_LIBRARY_SUFFIX) 

.PHONY: clean
clean:
	rm -rf $(OBJS) bin
