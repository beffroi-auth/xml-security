# Test keys

Copies of the files of `../../Dsig/Fixture/keys/`, byte for byte, so that the commands recorded in this tree run
from `tests/Enc/Fixture/` and the tests of the `Enc` namespace read nothing outside their own tree. That README
says how each file was made and what it is: an RSA-2048 pair and its self-signed certificate that are public by
construction and protect no real document, a stranger's certificate, a weak RSA-1024 pair, an EC pair, a DSA key and
a passphrase-protected key (passphrase `test-passphrase`).

In this namespace, `test-signing-certificate.pem` is the peer's encryption certificate every vector of `../vectors/`
was encrypted to, and `test-signing-key.pem` the decryption key that reads them; the stranger's certificate encrypts
`../hostile/encrypted-under-the-stranger-certificate-refused.xml`, which that key cannot unwrap; the weak, EC and DSA
files serve the refusal of a key that is not RSA of at least 2048 bits (E-11).

One file of this directory has no copy in Dsig's: `test-signing-public-key.pem`, the public key of the test certificate, made
in Alpine 3.22 with OpenSSL 3.5.8 on 27 September 2026 with `openssl x509 -in test-signing-certificate.pem -pubkey -noout`,
for `PeerKey::fromPublicKeyPem()`.
