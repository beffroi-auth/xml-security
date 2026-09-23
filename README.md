# beffroi-php/saml-xml-core

The `xml-core` brick of a SAML 2.0 stack: a safe DOM for XML that is about to be signed, verified, encrypted or
decrypted. It parses without being attacked, finds an element by its ID without ambiguity, canonicalizes without
ever hashing nothing, reads text as the signer meant it, and serializes what was built. It knows no signature, no
cipher, no SAML and no HTTP: `xml-dsig`, `xml-enc` and `saml2-model` are built on it, and so can any XML Signature or
XML Encryption profile.

[`SPECIFICATION.md`](SPECIFICATION.md) is the law of this repository: the code conforms to it, or the document
changes first. This file is the short version.

Requires PHP 8.4 or later with `ext-dom` (the `Dom\` API) and `ext-libxml`. Nothing else, ever.

```bash
composer require beffroi-php/saml-xml-core
```

## Loading

```php
use Beffroi\Xml\Core\{IdAttribute, IdAttributes, Limits, Loader, Name};

$ids = new IdAttributes([
    new IdAttribute(new Name(null, 'ID'), 'urn:oasis:names:tc:SAML:2.0:assertion'),
    new IdAttribute(new Name(null, 'ID'), 'urn:oasis:names:tc:SAML:2.0:protocol'),
    new IdAttribute(new Name(null, 'Id'), 'http://www.w3.org/2000/09/xmldsig#'),
]);
$loader = new Loader($ids, new Limits());   // the defaults of section 7, each raisable up to its ceiling

$document = $loader->load($bytes);           // throws a RefusedXml naming the rule, never quoting the input
$assertion = $document->elementById('_a1b2'); // the index built at load; UnknownId when absent
```

`load()` takes bytes, never a path or a stream. It refuses, in this order: an input over `maxBytes`; a UTF-16 or
UTF-32 byte order mark or bytes that are not UTF-8; a `<!DOCTYPE` anywhere in the bytes; an empty input; whatever
libxml throws on or merely reports, at any level; a declared encoding other than UTF-8 or a version other than 1.0;
then, in one pass over the tree, a depth, an element count, an attribute count, a namespace declaration count or an
ID length over its bound, a namespace name that is not an absolute URI, an ID that is not an NCName, and an ID seen
twice, under one registered attribute or two.

Hold the `Document` for as long as you use its nodes: the brick recognises a node through the `Document` that owns
it, and a `Document` you drop is forgotten, its nodes foreign again.

## Reading

```php
use Beffroi\Xml\Core\{Attributes, Children, Name, Text};

$saml = 'urn:oasis:names:tc:SAML:2.0:assertion';
$subject = Children::one($assertion, new Name($saml, 'Subject'));      // MissingChild, AmbiguousChild
$nameId  = Children::optional($subject, new Name($saml, 'NameID'));    // null, or AmbiguousChild
$value   = Text::of($nameId);          // every text and CDATA child, comments skipped; MixedContent on an element
$format  = Attributes::optional($nameId, new Name(null, 'Format'));    // null when absent, never ''
```

Names compare a namespace URI and a local name, never a prefix. `Children` looks at direct children only: nothing in
the brick searches descendants, and an assertion wrapped inside `samlp:Extensions` is never found from the root.
`Text::of()` reads `user@example.com<!---->.evil.com` as `user@example.com.evil.com`, the value the signature covers.

## Canonicalizing

```php
use Beffroi\Xml\Core\{CanonicalizationMethod, Canonicalizer, InclusiveNamespaces};

$method = CanonicalizationMethod::fromUri('http://www.w3.org/2001/10/xml-exc-c14n#');
$canonical = new Canonicalizer()->canonicalize(
    $assertion,
    $method,
    InclusiveNamespaces::fromPrefixList('ds saml'),
    excluding: [$signature],   // the enveloped signature transform: detached, canonicalized, reinserted in a finally
);
hash('sha256', $canonical->bytes, true);
```

The four methods of Canonical XML 1.0 and Exclusive XML Canonicalization 1.0, with and without comments, are the
only ones; Canonical XML 1.1 is refused as unknown. A canonicalization libxml cannot do is `CanonicalizationFailed`,
and a `CanonicalXml` never holds the empty string. The document is identical before and after the call, whether it
succeeds or fails. No XPath expression exists in the brick.

What a verifier hands to its consumer is the re-parse of the canonical bytes it hashed: `$loader->load($canonical->bytes)`
gives one root, the signed element with every namespace and inherited `xml:*` attribute the form rendered, and no
wrapper, no sibling, no second assertion.

## Writing

```php
use Beffroi\Xml\Core\{DocumentFactory, Name, Serializer};

$document = new DocumentFactory()->create(new Name('urn:oasis:names:tc:SAML:2.0:protocol', 'AuthnRequest'), 'samlp');
$root = $document->root();
$root->setAttributeNS(null, 'ID', '_' . bin2hex(random_bytes(16)));   // build with the Dom API, the brick wraps nothing
$bytes = new Serializer()->serialize($document);   // <?xml version="1.0" encoding="UTF-8"?>, a line feed, the root
```

Nothing pretty-prints. Build what you sign with one prefix per namespace, no carriage return in a text node, no
adjacent CDATA sections and no ampersand in a namespace name, and forward a document you loaded as you received it
instead of re-serializing it: PHP's `saveXml()` drops a prefix bound to the in-scope default namespace, merges
adjacent CDATA sections and escapes an ampersand of a namespace name twice, and a parser normalises a carriage
return away (specification, section 6.5).

## The invariants

Each is code, never an option, and has its tests.

| | |
|---|---|
| I-1 | No DOCTYPE, no entity: refused before parsing and after. |
| I-2 | Fixed parse flags: `LIBXML_NONET`, plus `LIBXML_NO_XXE` when defined; never `NOENT`, `DTDLOAD`, `DTDATTR`, `DTDVALID`, `XINCLUDE`, `PARSEHUGE`, `NOBLANKS`, `NOCDATA`; no entity loader. |
| I-3 | A libxml diagnostic of any level is a refusal; libxml's state is saved and restored around every call. |
| I-4 | One parser: the brick canonicalizes and serializes only what it loaded or created. |
| I-5 | UTF-8 and XML 1.0 only; a UTF-8 byte order mark is accepted. |
| I-6 | Every namespace name is an absolute URI, or the empty undeclaration of the default namespace. |
| I-7 | Six bounds: 1 MiB, depth 64, 10 000 elements, 32 attributes per element, 512 namespace declarations, IDs of 128 bytes. |
| I-8 | One ID space per document, no duplicate, every ID an NCName. |
| I-9 | Lookup by index, never `getElementById()`, never XPath. |
| I-10 | Names are a namespace URI and a local name. |
| I-11 | Children only, nothing searches descendants. |
| I-12 | Text is the concatenation of the text and CDATA children. |
| I-13 | Nothing canonicalizes to nothing. |
| I-14 | Subtree exclusion is structural: detached, reinserted in a `finally`. |
| I-15 | Faithful serialization, `formatOutput` false, whitespace kept. |
| I-16 | Refusals name the rule, never the input. |

## What consumers never call

The brick's own PHPStan configuration bans them, and every consumer is asked to copy the rules of
`.ci-tools/phpstan.neon` and `tests/PhpStan/`: `DOMDocument`, `DOMXPath`, `Dom\XPath`, `SimpleXMLElement`,
`XMLReader`, `XMLWriter`, `libxml_set_external_entity_loader()`, the flags above, `getElementById()`,
`setIdAttribute*()`, `getElementsByTagName*()`, `querySelector*()`, `importNode()`, `adoptNode()`, `xinclude()`,
the validation methods; `createFromString()` and `createEmpty()` outside `Loader` and `DocumentFactory`, `C14N()`
outside `Canonicalizer`, `saveXml()` outside `Serializer`. `textContent`, `nodeValue` and `innerHTML` are not
read: `Text::of()` is the way.

## Development

```bash
composer install
castor phpunit        # PHPUnit 13 with coverage
castor prepare-pr     # Mago lint and format, Rector, PHPStan at level max with no baseline, syntax, composer
castor infect         # Infection on the files of section 9, no escaped mutant allowed
castor infect --diff  # the lines changed since origin/main, the shape of every CI run on the rest
castor libxml         # the PHP and libxml versions, and whether LIBXML_NO_XXE is defined on this build
```

Every task runs inside the `ghcr.io/spomky-labs/phpqa` image when Docker is available, on PHP 8.5 by default and
on 8.4 with `PHP_VERSION=8.4`. The CI runs the same tasks on both.

## Security

See [SECURITY.md](SECURITY.md): private reporting, an advisory and a CVE for every fix.

## License

MIT, see [LICENSE](LICENSE).
