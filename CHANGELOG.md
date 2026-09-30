# Changelog

Every notable change of `beffroi-php/xml-security` is recorded here, in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html): until 1.0.0, a minor version may change the API.

## 0.1.0 - 2026-09-30

The first version: XML security for PHP 8.4 and later, in one package and three namespaces, each under its own
specification, which is the law of its code: [`spec/core.md`](spec/core.md), [`spec/dsig.md`](spec/dsig.md) and
[`spec/enc.md`](spec/enc.md). It is the XML foundation of the SAML 2.0 spike of Heidi: `saml2-model` and
`saml2-bindings` are built on it. It requires `ext-dom`, `ext-libxml` and `ext-openssl`, and no other package.

### Added

#### Core, a safe DOM (16 invariants, I-1 to I-16)

- `Loader`: parses bytes, never a path, with the `Dom\XMLDocument` API and no entity loader; refuses a DOCTYPE
  wherever it stands, an entity reference, bytes that are not UTF-8, a UTF-16 or UTF-32 byte order mark, a declared
  encoding other than UTF-8, XML 1.1, any libxml diagnostic, an unbound prefix, a relative namespace URI, a
  duplicate ID; holds the document to six bounds (`Limits`: bytes, depth, elements, attributes per element,
  namespace declarations, ID length), each with a ceiling.
- `IdAttributes` and `Document`: one ID space per document, the attributes the consumer registers and nothing else,
  `elementById()` refusing an unknown ID; a node of a document the brick did not produce is refused (`ForeignNode`).
- `Children`, `Attributes` and `Text`: direct children only, counted, never searched; text read whole, a comment
  splitting it skipped and an element inside it refused, the value that Canonical XML without comments signs.
- `Canonicalizer` and `CanonicalXml`: exclusive and inclusive canonicalization, with or without comments, with an
  `InclusiveNamespaces` prefix list and excluded nodes; `false` and the empty string are refusals, never bytes to
  hash.
- `DocumentFactory` and `Serializer`: documents built with a prefix or a declared default namespace on every element,
  and serialized only when a parser would read them back the same (a carriage return, a prefix bound to the default
  namespace, a CDATA section holding `]]>`, an ampersand in a namespace name are refused).

#### Dsig, XML Signature (17 invariants, D-1 to D-17)

- `Verifier::verify()`: the `ds:Signature` a direct child of the claimed element, one, or a refusal; the reading
  model strict, its algorithms by name from closed lists; `SignedInfo` verified against the consumer's keys before
  the element's digest is computed, so that only a trusted signer makes the verifier canonicalize the element; the
  reference resolved by identity to the claimed element; the digest compared in constant time. `Verified::$document`
  is the reload of the very bytes the digest covered, the only thing the consumer reads.
- `Verifier::verifyDetached()`: the same rules for a signature that is not XML, the query string of the HTTP-Redirect
  binding.
- `Signer::sign()`: signs the loaded form of what was built, so that what is hashed is what the peer parses; an
  optional certificate hint, exactly one certificate or a refusal; an element that already holds a signature is
  refused.
- `VerificationKey`, `VerificationKeys`, `PrivateKey` and `SigningKeyInterface`: keys read from exactly one PEM block
  in memory, never from a path, RSA of at least 2048 bits, one to sixteen trusted keys; the signing port lets a key
  management service sign without handing its key over.
- Schemes `rsa-sha256`, `rsa-sha384`, `rsa-sha512` and their RSASSA-PSS counterparts; digests SHA-256, SHA-384 and
  SHA-512; exclusive canonicalization, with or without comments, and the enveloped signature transform.

#### Enc, XML Encryption (14 invariants, E-1 to E-14)

- `Decryptor::decrypt()`: the `xenc:EncryptedData` of an element, its one `EncryptedKey` inside its `KeyInfo`, read
  strictly; every length checked before the primitive (session key, IV, GCM tag); one failure that says nothing,
  whatever step failed, OpenSSL's error queue emptied; the plaintext loaded by the consumer's `Loader`, the document
  it returns being all the consumer reads.
- `Encryptor::encrypt()`: the element's exclusive canonical form with comments, every prefix in scope rendered, a
  fresh session key and IV for every call, AES-GCM with a 16-byte tag, the session key under RSA-OAEP to the peer; the
  plaintext loaded once by the consumer's `Loader` before it is encrypted; an optional certificate hint, exactly one
  certificate or a refusal.
- `PrivateDecryptionKey`, `DecryptionKeyInterface` and `PeerKey`: keys read from exactly one PEM block in memory,
  RSA of at least 2048 bits; the decryption port answers `null` rather than a reason, so that it cannot become an
  oracle.
- Content methods `aes128-gcm` and `aes256-gcm`; key transports `rsa-oaep-mgf1p` and `rsa-oaep` with SHA-1, SHA-256,
  SHA-384 or SHA-512.

#### Quality

- A hostile corpus per namespace, an adversarial pass on each, and a traceability test that checks that every
  invariant and every row of the corpus is cited by a test.
- PHPUnit on PHP 8.4 and 8.5, PHPStan at level max with rules that confine each OpenSSL call to one file, Deptrac
  between the namespaces, Mago, Rector, and Infection with no escaped mutant on the files of the specifications.
- xmlsec1 1.3.7, the implementation that is not this one, verifies every scheme the signer produces and decrypts
  every scheme the encryptor produces, on every run of the CI; the vectors of both namespaces were produced by it.
  SimpleSAMLphp's library verifies and decrypts what this package produces, and the reverse.

### Security

Refused by name, whatever else the document holds: signature wrapping in its known forms, a reference that is not
`#` and an ID, XPath, XSLT and base64 transforms, inclusive canonicalization in a signature, SHA-1, MD5, HMAC, DSA and
ECDSA; AES-CBC and 3DES, RSA PKCS#1 v1.5 key transport, key wrapping and key agreement, a truncated GCM tag,
`CipherReference`; keys shorter than 2048 bits or not RSA. Refusals name the rule they apply and never carry the
input, a key or a plaintext. The package was reviewed for vulnerabilities pull request by pull request and then as a
whole against the SAML spike, and every finding was fixed before this version: no vulnerability is known in it.
Report one privately, as [`SECURITY.md`](SECURITY.md) says.

### Known limitations

- On PHP 8.4, RSASSA-PSS and `rsa-oaep` with a hash other than SHA-1 are refused with `AlgorithmUnavailable`: they
  need PHP 8.5, and RSASSA-PSS needs OpenSSL 3.1 as well.
- The encrypted assertions of Entra ID, ADFS and SimpleSAMLphp identity providers are refused, since they use
  AES-CBC (#63); so is the plaintext xmlsec1 writes for an element nested in its document, as pysaml2 drives it
  (#64). They can send their assertions signed and not encrypted.
- The default bounds of `Limits` are provisional until the metadata of ADFS and SimpleSAMLphp are measured (#13, #16).
- `LIBXML_NO_XXE` is set where it is defined, libxml 2.13 and later; no build of the CI exercises it yet (#17).
- The serializer does not refuse yet the characters no parser accepts in built content (#29).
- No preset of the SAML ID attributes is shipped: the consumer registers them on its `Loader`.
