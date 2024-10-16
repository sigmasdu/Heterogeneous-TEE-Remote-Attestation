#!/bin/bash
set -x
set -e

# "available build type: \
#    verify_sgx \
#    verify_phytium \
#    verify_csv \
#    verify_tdx \
#    verify \
#    sgx \
#    phytium \
#    csv \
#    tdx \
#  "

BUILD_TYPE=$1
ROOT_PATH=$(pwd)
SGX_PATH="${ROOT_PATH}/wrapper/sgx"
PHYTIUM_PATH="${ROOT_PATH}/wrapper/phytium"
CSV_PATH="${ROOT_PATH}/wrapper/csv"
TDX_PATH="${ROOT_PATH}/wrapper/tdx"
# ***********************compile verify only****************************
function compile_sgx_verify() {
  pushd ${SGX_PATH}
  make clean
  make verify
  popd
}

function compile_phytium_verify() {
  pushd ${PHYTIUM_PATH}
  make verify
  popd
}

function compile_csv_verify() {
  pushd ${CSV_PATH}
  make verify
  popd
}

function compile_tdx_verify() {
  echo "compile_tdx_verify skip ...."
  return
  pushd ${TDX_PATH}
  make verify
  popd
}

function compile_verify() {
  compile_sgx_verify
  compile_phytium_verify
  compile_csv_verify
  compile_tdx_verify
}

function compile_verify_by_tee_type() {
  if [ "${BUILD_TYPE}" ==  "verify_sgx" ]; then
    compile_sgx_verify
  fi

  if [ "${BUILD_TYPE}" ==  "verify_phytium" ]; then
    compile_phytium_verify
  fi

  if [ "${BUILD_TYPE}" ==  "verify_csv" ]; then
    compile_csv_verify
  fi

  if [ "${BUILD_TYPE}" ==  "verify_tdx" ]; then
    compile_tdx_verify
  fi

  # no tee type compile all
  if [ "${BUILD_TYPE}" ==  "verify" ]; then
    compile_verify
  fi
}


# ******************compile all generator and verfiy**********************
function compile_sgx() {
  if [ "${BUILD_TYPE}" ==  "sgx" ]; then
    pushd ${SGX_PATH}
    make clean
    make
    popd
  fi
}

function compile_phytium() {
  if [ "${BUILD_TYPE}" ==  "phytium" ]; then
    pushd ${PHYTIUM_PATH}
    make
    popd
  fi
}
function compile_csv() {
  if [ "${BUILD_TYPE}" == "csv" ]; then
    pushd ${CSV_PATH}
    make
    popd
  fi
}

function compile_tdx() {
  echo "compile_tdx, skip...."
  return
  if [ "${BUILD_TYPE}" == "tdx" ]; then
    pushd ${TDX_PATH_PATH}
    make
    popd
  fi
}

function compile_by_tee_type() {
  compile_sgx
  compile_phytium
  compile_csv
  compile_tdx
}

# ******************compile proto**********************
function compile_proto() {
  echo "Compile proto file for attestation center."
  pushd ${ROOT_PATH}/attestation_center
  python3 -m grpc_tools.protoc \
      --proto_path=../proto/ \
      ../proto/hetero_attestation.proto \
      --python_out=./ --grpc_python_out=./
  popd

  echo "Compile proto file for tee node."
  pushd ${ROOT_PATH}/tee_node
  python3 -m grpc_tools.protoc \
      --proto_path=../proto/ \
      ../proto/hetero_attestation.proto \
      --python_out=./ --grpc_python_out=./
  popd
}

# ******************compile proto**********************
function main() {
  compile_verify_by_tee_type
  compile_by_tee_type
  compile_proto
}

main
