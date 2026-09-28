# The xmlsec1 oracle of the signer

`tests/Dsig/Unit/SignerOracleTest.php` signs the assertion of a built response, then the response, with every
scheme the build offers, exclusive and exclusive with comments, and one PKCS#1 v1.5 scheme over a digest of another
size, and writes each document into the directory `XMLSEC_ORACLE` names. `verify-every-scheme.sh` then has xmlsec1,
the implementation that is not this one, verify both signatures of each (spec/dsig.md section 9.3 row 10).

A PSS signature is random, so nothing here is pinned: the documents are written again on every run. The job Oracle
of the CI signs in the phpqa image of PHP 8.5 and verifies in Alpine 3.22 (xmlsec1 1.3.7); on the developer's
machine, `PHP_VERSION=8.5 castor xmlsec-oracle` does the same into `.ci-tools/oracle`, which git ignores.
