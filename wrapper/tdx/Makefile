ENCLAVE_KEY := ${SGX_ENCLAVE_KEY}
ENCLAVE_LDS := ${SGX_ENCLAVE_LDS}
ENCLAVE_CONFIG := ${SGX_ENCLAVE_CONFIG}

# For pybind11.
PYBIND11_INCLUDE_PATH := $(shell python3 -m pybind11 --includes)
PYTHON_LIBRARY_SUFFIX := $(shell python3-config --extension-suffix)

# File and CFLAG from jinzhao-attest.
EDL_FILE := /root/jinzhao_lib_sgx/edl/attestation.edl
UAL_T_LIB := /root/jinzhao_lib_sgx/lib/libual_t.a
UAL_U_LIB := /root/jinzhao_lib_sgx/lib/libual_u.so
UAL_LIB_DIR := /root/jinzhao_lib_sgx/lib/
JINZHAO_INC := -I /root/jinzhao_lib_sgx/include/

# For SGX.
SGX_SDK := /opt/intel/sgxsdk
SGX_COMMON_CFLAGS := -I/opt/intel/sgxsdk/include/ 
SGX_COMMON_CFLAGS += -m64 -Wall
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SDK_INC := $(SGX_SDK)/include
LIBCXX_INC := $(SGX_SDK)/include/libcxx
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign

PACKAGE_INC := /opt/intel/sgxssl/include/
Enclave_Include_Paths := -I./Enclave -I$(SGX_SDK_INC) -I$(SGX_SDK_INC)/tlibc
Enclave_Include_Paths += -I$(LIBCXX_INC) -I$(PACKAGE_INC)

Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc 
Common_C_Cpp_Flags += -fvisibility=hidden -fpic -fpie -fstack-protector 
Common_C_Cpp_Flags += -fno-builtin-printf -Wformat -Wformat-security 
Common_C_Cpp_Flags += $(Enclave_Include_Paths) -include "tsgxsslio.h"

Enclave_C_Flags := $(Common_C_Cpp_Flags) -Wno-implicit-function-declaration -std=c11
Enclave_Cpp_Flags := $(Common_C_Cpp_Flags) -std=c++11 -nostdinc++

Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie
SGXSSL_Library_Name := sgx_tsgxssl
OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice

OPENSSL_LIBRARY_PATH := /opt/intel/sgxssl/lib64/
SgxSSL_Link_Libraries := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive 
SgxSSL_Link_Libraries += -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive
SgxSSL_Link_Libraries += -l$(OpenSSL_Crypto_Library_Name) 

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined \
				-nostdlib -nodefaultlibs -nostartfiles $(Security_Link_Flags) \
        $(SgxSSL_Link_Libraries) -L$(SGX_LIBRARY_PATH) \
        -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tstdc -lsgx_pthread -lsgx_tcxx -lsgx_tcrypto -l$(Service_Library_Name) -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
        -Wl,--defsym,__ImageBase=0 \
        -Wl,--version-script=$(ENCLAVE_LDS)

all: enclave.signed.so sgx_wrap_module example.signed.so

verify: sgx_wrap_verify_module 


clean:
	@rm -rf *.o
	@rm -rf attestation*
	@rm -rf enclave.o enclave.so enclave.signed.so
	@rm -rf sgx_wrap*.so
	@rm -rf example_t.*
	@rm -rf example_u.*

######## Enclave Objects ########
attestation_t.c:$(SGX_EDGER8R)
	$(SGX_EDGER8R) --trusted $(EDL_FILE) --search-path $(SGX_SDK_INC)
	@echo "Gen => $@"

attestation_t.o: attestation_t.c
	$(CC) $(Enclave_C_Flags) $(JINZHAO_INC) -c $< -o $@	
	@echo "CC <= $<" 

enclave.o: enclave/enclave.cc
	$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@		
	@echo "CXX <= $<" 

enclave.so: enclave.o attestation_t.o $(UAL_T_LIB)
	$(CXX) $^ -o $@ $(UAL_T_LIB) $(Enclave_Link_Flags)

enclave.signed.so: enclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_KEY) -enclave enclave.so -out $@ -config $(ENCLAVE_CONFIG) 
	@echo "SIGN =>  $@"


######## Python C Extension For SGX Proof Generation And Verify ########
attestation_u.c: $(SGX_EDGER8R)
	@$(SGX_EDGER8R) --untrusted $(EDL_FILE) --search-path $(SGX_SDK_INC)
	@echo "Gen => $@"

attestation_u.o: attestation_u.c
	@$(CC) -fPIC -shared $(JINZHAO_INC) -I $(SGX_SDK)/include -c $< -o $@
	@echo "CC <= $@"

example_u.c: $(SGX_EDGER8R)
	@$(SGX_EDGER8R) --untrusted ./enclave/example.edl --search-path $(SGX_SDK_INC)
	@echo "Gen => $@"

example_u.o: example_u.c
	@$(CC) -fPIC -shared $(JINZHAO_INC) -I $(SGX_SDK)/include -c $< -o $@
	@echo "CC <= $@"

sgx_wrap.o: sgx_wrap.cc example_u.o attestation_u.o
	c++ -fPIC -shared -O3 -Wall -I $(SGX_SDK_INC) $(JINZHAO_INC) $(PYBIND11_INCLUDE_PATH) sgx_wrap.cc -c -o sgx_wrap.o
	@echo "CXX <= $@"

sgx_wrap_module: sgx_wrap.o $(UAL_U_LIB) attestation_u.o example_u.o
	c++ -O3 -Wall -shared -std=c++11 -fPIC sgx_wrap.o attestation_u.o example_u.o $(UAL_U_LIB) -o sgx_wrap$(PYTHON_LIBRARY_SUFFIX) -lglog
	@echo "Generate python module."

######## Python C Extension For SGX Proof Verify ########
sgx_wrap_verify_module: sgx_wrap.cc $(UAL_U_LIB)
	c++ -O3 -Wall -shared -DSGX_VERIFY_ONLY \
		-std=c++11 $(PYBIND11_INCLUDE_PATH) \
		$(JINZHAO_INC) -fPIC sgx_wrap.cc \
		-o sgx_wrap$(PYTHON_LIBRARY_SUFFIX) \
		-L $(UAL_LIB_DIR) -lglog -lual_u 

	@echo "Generate python module (only for verify)."

######## Example Enclave ########
example_t.c: $(SGX_EDGER8R)
	@$(SGX_EDGER8R) --trusted ./enclave/example.edl --search-path $(SGX_SDK_INC)
	@echo "Gen => $@"

example_t.o: example_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC <= $@"

example.o: enclave/example.cc
	$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@		
	@echo "CXX <= $<"

example.so: example_t.o example.o
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)

example.signed.so: example.so
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_KEY) -enclave example.so -out $@ -config $(ENCLAVE_CONFIG) 
	@echo "SIGN =>  $@"
