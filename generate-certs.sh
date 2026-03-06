#!/bin/bash

mkdir -p nginx/certs

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout nginx/certs/key.pem \
    -out nginx/certs/cert.pem \
    -subj "/C=US/ST=State/L=City/O=SSL Checker Pro/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

echo "✅ Self-signed certificates generated in nginx/certs/"
echo "   cert.pem - Certificate"
echo "   key.pem  - Private key"
