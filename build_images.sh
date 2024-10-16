#!/bin/bash
#set -e
set -x
function build_image() {
  dockerfile_name=$1
  image=$2
  docker build -f ${DOCKER_FILE_NAME} -t ${IMAGE} .
}

#attestation center
function attestation_center_router() {
    #build image for attestation center router
    IMAGE=primihub:attestation_center_router
    docker rmi ${IMAGE}
    DOCKER_FILE_NAME=Dockerfile_router
    build_image ${DOCKER_FILE_NAME} ${IMAGE}
}

# build image for attestation center verify sgx
function attestation_center_verify_sgx () {
    IMAGE=primihub:attestation_center_sgx
    DOCKER_FILE_NAME=Dockerfile_sgx
    build_image ${DOCKER_FILE_NAME} ${IMAGE}
}
#build image for attestation center verify phytium
function attestation_center_phytium() {
    IMAGE=primihub:attestation_center_phytium
    docker rmi ${IMAGE}
    DOCKER_FILE_NAME=Dockerfile_phytium
    build_image ${DOCKER_FILE_NAME} ${IMAGE}
}
##build image for attestation center verify hygon csv
function attestation_center_hygon_csv() {
    IMAGE=primihub:attestation_center_hygon_csv
    docker rmi ${IMAGE}
    DOCKER_FILE_NAME=Dockerfile_csv
    build_image ${DOCKER_FILE_NAME} ${IMAGE}
}

# # sgx proof gen
function generate_sgx_proof() {
    IMAGE=primihub:generate_sgx_proof
    DOCKER_FILE_NAME=Dockerfile_gen_sgx_proof
    build_image ${DOCKER_FILE_NAME} ${IMAGE}
}

# # phytium proof gen
function generate_phytium_proof() {
    IMAGE=primihub:generate_phytium_proof
    DOCKER_FILE_NAME=Dockerfile_gen_phytium_proof
    build_image ${DOCKER_FILE_NAME} ${IMAGE}
}
# hygon csvproof gen
function generate_csv_proof() {
    IMAGE=primihub:generate_csv_proof
    docker rmi ${IMAGE}
    DOCKER_FILE_NAME=Dockerfile_gen_csv_proof
    build_image ${DOCKER_FILE_NAME} ${IMAGE}
}

function main() {
# attestion route
#attestation_center_router
## sgx
#attestation_center_verify_sgx
#generate_sgx_proof
#
## phytium
#attestation_center_phytium
#generate_phytium_proof

# hygon csv
attestation_center_hygon_csv
generate_csv_proof
}


main
