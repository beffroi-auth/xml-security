#!/bin/sh
# Verifies with xmlsec1 both signatures of every document SignerOracleTest wrote into the directory given
# (spec/dsig.md section 9.3 row 10). Run from the root of the repository, where xmlsec1 is installed:
#   sh tests/Dsig/Fixture/oracle/verify-every-scheme.sh .ci-tools/oracle
set -eu

directory=$1
certificate=tests/Dsig/Fixture/keys/test-signing-certificate.pem
count=0
for file in "$directory"/*.xml; do
    [ -f "$file" ] || continue
    for signature in '/*/*[local-name()="Signature"]' '/*/*[local-name()="Assertion"]/*[local-name()="Signature"]'; do
        xmlsec1 --verify --lax-key-search --pubkey-cert-pem "$certificate" \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response \
            --node-xpath "$signature" "$file"
    done
    count=$((count + 1))
done
if [ "$count" -eq 0 ]; then
    echo "No signed document in $directory." >&2
    exit 1
fi
echo "$count documents, both signatures of each verified by xmlsec1."
