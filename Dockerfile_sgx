FROM antkubetee/kubetee-dev-sgx:2.0-ubuntu20.04-sgx2.17.1-py as builder

ENV LANG C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

ARG ROOT_PATH=/Heterogeneous-TEE-Remote-Attestation
WORKDIR $ROOT_PATH
ADD . $ROOT_PATH
ARG JINZHAO_ATTEST_PATH=$ROOT_PATH/external/jinzhao-attest
#build jinzhao-attest
WORKDIR $JINZHAO_ATTEST_PATH
ARG HETERO_TEE_TYPE=SGX
RUN bash ./build.sh --with-samples
RUN bash ./build.sh --install

RUN mkdir -p /root/jinzhao_lib_sgx
RUN cp -rf $JINZHAO_ATTEST_PATH/build/install/* /root/jinzhao_lib_sgx/
RUN cp $JINZHAO_ATTEST_PATH/build/*pb.h /root/jinzhao_lib_sgx/include/

# build sgx verify
WORKDIR $ROOT_PATH
RUN bash build.sh verify_sgx

ENV http_proxy=
ENV https_proxy=
ENV HTTP_PROXY=
ENV HTTPS_PROXY=
