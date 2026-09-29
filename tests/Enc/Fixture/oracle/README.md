# The xmlsec1 oracle of the encryptor

`tests/Enc/Unit/EncryptorOracleTest.php` builds a response whose assertion holds a comment and a QName value
naming a prefix the response declares, puts the assertion inside the `saml:EncryptedAssertion` a consumer builds,
writes the exclusive canonical form with comments of that document, then encrypts the assertion under each content
method and each hash the build offers and writes the encrypted document, into the directory `XMLSEC_ORACLE` names
(`enc/`). `decrypt-every-scheme.sh` then has xmlsec1, the implementation that is not this one, decrypt each, and
compares what it gives back, through `xmllint --exc-c14n`, with the document before encryption (spec/enc.md section
9.3 row 10).

The session key and the IV are random, so nothing here is pinned: the documents are written again on every run. The
job Oracle of the CI encrypts in the phpqa image of PHP 8.5, where the four hashes are available, and decrypts in
Alpine 3.22 (xmlsec1 1.3.7); on the developer's machine, `PHP_VERSION=8.5 castor xmlsec-oracle` does the same into
`.ci-tools/oracle`, which git ignores.
