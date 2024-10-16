#!/bin/bash
set -x
if [[ -d cert ]]; then
 rm -fr cert
fi
mkdir cert
cd cert
openssl genrsa -out ca.key 2048
openssl req -new -key ca.key -out ca.csr -subj "/C=CN/ST=GD/L=SZ/O=test/OU=dev/CN=test/emailAddress=test@gmail.com"
openssl x509 -req -days 365 -in ca.csr -signkey ca.key -out ca.crt
cd -
