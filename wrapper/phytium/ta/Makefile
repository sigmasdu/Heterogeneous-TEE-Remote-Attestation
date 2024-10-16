CFG_TEE_TA_LOG_LEVEL ?= 2
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

BINARY=30097836-a15b-40d8-bd87-9296393d0aa7

TA_DEV_KIT_DIR=/data/link/export-ta_arm64/
include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

all: install

install:
	cp 30097836-a15b-40d8-bd87-9296393d0aa7.ta /data/optee_armtz/ 

clean: clean_ta_file
.PHONY: clean_ta_file
clean_ta_file:
	rm -f $(BINARY).ta
