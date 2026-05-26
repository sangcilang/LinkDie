#!/bin/sh
# generate-ssl.sh — Generate a self-signed TLS certificate for local development.
# This script runs inside the nginx container on first start if cert.pem is missing.

set -e

CERT_DIR="/etc/nginx/ssl"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "SSL certificates already exist, skipping generation."
    exit 0
fi

echo "Generating self-signed SSL certificate for localhost..."
mkdir -p "$CERT_DIR"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/C=VN/ST=HCM/L=HoChiMinh/O=EphemeralShare/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Certificate generated:"
echo "  Cert: $CERT_FILE"
echo "  Key:  $KEY_FILE"
openssl x509 -in "$CERT_FILE" -noout -subject -dates
