#!/bin/bash

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -sha256 -days 365 -nodes \
  -keyout key.pem -out cert.pem \
  -subj "/CN=localhost" \
  -addext "basicConstraints = critical, CA:FALSE" \
  -addext "keyUsage = critical, digitalSignature" \
  -addext "extendedKeyUsage = serverAuth" \
  -addext "subjectAltName = DNS:localhost, IP:127.0.0.1"

