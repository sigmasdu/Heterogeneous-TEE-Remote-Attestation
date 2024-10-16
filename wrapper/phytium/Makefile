# target = //sample:verfify \
#       //sample:generator \
#       //py_wrapper:phytium_attestation
# 
# release:
# 	bazel build ${target} 
# 
# verify:
# 	bazel build //py_wrapper:phytium_attestation //sample:verfify 

export V?=0

.PHONY: all

all: attestation_helper

attestation_helper:
	make -C host CROSS_COMPILE=$(HOST_CROSS_COMPILE)
	make -C ta CROSS_COMPILE=$(TA_CROSS_COMPILE)

verify:
	make -C host verify

.PHONY: clean
clean:
	make -C host clean
	make -C ta clean
