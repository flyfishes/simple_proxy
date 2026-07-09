#!/bin/bash
# 生成自签名证书
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3365 -nodes \
    -subj "/CN=localhost"
echo "证书已生成: cert.pem, key.pem"