#!/usr/bin/env bash
#   Step 3 — dev cert generator for the rustls
# dual-ingress kernel ( Addendum 2a §2).
#
# Produces a self-signed dev CA and three leaf certs in./secrets/:
#   - dev_ca.crt / dev_ca.key
#   - kernel_server.crt / kernel_server.key   (SAN: DNS:safety-kernel-rust.internal)
#   - client_worker.crt / client_worker.key   (SAN: URI:spiffe://qorch/role/worker)
#
# Output dir is gitignored by../../../.gitignore (*.pem, *.key etc).
# For prod, use Google Secret Manager — never check these in.
#
# Requirements: openssl >= 1.1.1. Re-running overwrites prior artifacts.
set -euo pipefail

OUT="${1:-secrets}"
SNI="${QORCH_KERNEL_SNI:-safety-kernel-rust.internal}"
ROLE="${ROLE:-worker}"

mkdir -p "$OUT"
cd "$OUT"

# 1. Dev CA (self-signed, 10y).
openssl genrsa -out dev_ca.key 4096 2>/dev/null
openssl req -x509 -new -key dev_ca.key -days 3650 -sha256 \
    -subj "/CN=qorch dev CA" -out dev_ca.crt 2>/dev/null

# 2. Server cert signed by dev CA, SAN = $SNI.
openssl genrsa -out kernel_server.key 4096 2>/dev/null
openssl req -new -key kernel_server.key -subj "/CN=$SNI" -out kernel_server.csr 2>/dev/null
cat > kernel_server.ext <<EOF
subjectAltName=DNS:$SNI,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in kernel_server.csr -CA dev_ca.crt -CAkey dev_ca.key -CAcreateserial \
    -days 365 -sha256 -extfile kernel_server.ext -out kernel_server.crt 2>/dev/null

# 3. Client cert signed by dev CA, SAN = spiffe URI for $ROLE.
openssl genrsa -out "client_${ROLE}.key" 4096 2>/dev/null
openssl req -new -key "client_${ROLE}.key" -subj "/CN=qorch-client-${ROLE}" \
    -out "client_${ROLE}.csr" 2>/dev/null
cat > "client_${ROLE}.ext" <<EOF
subjectAltName=URI:spiffe://qorch/role/${ROLE}
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in "client_${ROLE}.csr" -CA dev_ca.crt -CAkey dev_ca.key -CAcreateserial \
    -days 365 -sha256 -extfile "client_${ROLE}.ext" -out "client_${ROLE}.crt" 2>/dev/null

# Tidy intermediates.
rm -f kernel_server.csr kernel_server.ext "client_${ROLE}.csr" "client_${ROLE}.ext" dev_ca.srl

echo "wrote dev certs to $(pwd):"
ls -la dev_ca.* kernel_server.* "client_${ROLE}".* 2>/dev/null

cat <<EOF

To run the kernel against these certs:
  export QORCH_KERNEL_TLS_CERT=$(pwd)/kernel_server.crt
  export QORCH_KERNEL_TLS_KEY=$(pwd)/kernel_server.key
  export QORCH_KERNEL_CLIENT_CA_PEM=$(pwd)/dev_ca.crt   # optional: enables mTLS
  export QORCH_KERNEL_SNI=$SNI
EOF
