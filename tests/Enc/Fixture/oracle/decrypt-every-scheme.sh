#!/bin/sh
# Decrypts with xmlsec1 every document EncryptorOracleTest wrote into the directory given, and compares what xmlsec1
# gives back, in its exclusive canonical form with comments, with the document before encryption (spec/enc.md
# section 9.3 row 10). Run from the root of the repository, where xmlsec1 and xmllint are installed:
#   sh tests/Enc/Fixture/oracle/decrypt-every-scheme.sh .ci-tools/oracle/enc
set -eu

directory=$1
key=tests/Enc/Fixture/keys/test-signing-key.pem
decrypted=$(mktemp)
count=0
for file in "$directory"/*.xml; do
    [ -f "$file" ] || continue
    xmlsec1 --decrypt --lax-key-search --privkey-pem "$key" --output "$decrypted" "$file"
    if ! xmllint --exc-c14n "$decrypted" | cmp -s - "${file%.xml}.expected"; then
        echo "$file: xmlsec1 gives back another document than the one encrypted." >&2
        exit 1
    fi
    count=$((count + 1))
done
rm -f "$decrypted"
if [ "$count" -eq 0 ]; then
    echo "No encrypted document in $directory." >&2
    exit 1
fi
echo "$count documents decrypted by xmlsec1 to the document before encryption."
