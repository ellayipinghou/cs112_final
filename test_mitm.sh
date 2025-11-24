#!/bin/bash
# HTTPS MITM Proxy Test Suite

PROXY="http://localhost:9395"
CA_CERT="proxy_ca.crt"

echo "========================================"
echo "HTTPS MITM Proxy Test Suite"
echo "========================================"
echo ""

echo "Test 1: Basic HTTPS connection with header injection"
echo "--------------------------------------"
curl -I -x "$PROXY" --cacert "$CA_CERT" https://example.com 2>&1 | grep -E "(HTTP|X-Proxy|Server)" | head -5
echo ""

echo "Test 2: Verify certificate is signed by our CA"
echo "--------------------------------------"
curl -v -x "$PROXY" --cacert "$CA_CERT" https://example.com 2>&1 | grep -E "(issuer|subject|subjectAltName)" | head -3
echo ""

echo "Test 3: GET request to httpbin.org"
echo "--------------------------------------"
curl -s -x "$PROXY" --cacert "$CA_CERT" https://httpbin.org/get 2>&1 | grep -E '"url"'
echo ""

echo "Test 4: POST request with data"
echo "--------------------------------------"
curl -s -X POST -x "$PROXY" --cacert "$CA_CERT" https://httpbin.org/post -d "name=CS112&test=mitm" 2>&1 | grep -A 4 '"form"'
echo ""

echo "Test 5: Multiple domains (Google)"
echo "--------------------------------------"
curl -I -x "$PROXY" --cacert "$CA_CERT" https://www.google.com 2>&1 | grep -E "(HTTP|X-Proxy|Server)" | head -4
echo ""

echo "========================================"
echo "All tests completed!"
echo "========================================"

