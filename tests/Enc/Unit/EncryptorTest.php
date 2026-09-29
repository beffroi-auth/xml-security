<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\Signer;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Enc\ContentAlgorithm;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\EncryptedData;
use Beffroi\Xml\Enc\Encryptor;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use Beffroi\Xml\Enc\KeyTransport;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Enc\PeerKey;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\Built;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use Dom\Element;
use function explode;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function str_ends_with;
use function strlen;
use function substr;

/**
 * Section 6.2: encryption in order, the element canonicalized with comments (E-9), fresh randomness (E-8), a
 * prefixed xenc:EncryptedData returned unattached in the element's document, decrypted by the decryptor of this
 * namespace and by xmlsec1 (tests/Enc/Fixture/behaviour/README.md).
 */
final class EncryptorTest extends TestCase
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    private Encryptor $encryptor;

    private Decryptor $decryptor;

    private Canonicalizer $canonicalizer;

    private PeerKey $peer;

    private PrivateDecryptionKey $key;

    protected function setUp(): void
    {
        $this->encryptor = new Encryptor();
        $this->decryptor = new Decryptor(new Loader(Stack::idAttributes()));
        $this->canonicalizer = new Canonicalizer();
        $this->peer = PeerKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'));
        $this->key = PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
    }

    /**
     * §9.3 row 3, E-9: encrypt() then decrypt() on a built assertion, under each content algorithm and SHA-1: the
     * root's exclusive canonical form with comments is the plaintext that was encrypted.
     */
    #[Test]
    #[DataProvider('provideContentAlgorithms')]
    public function itEncryptsWhatTheDecryptorDecrypts(ContentAlgorithm $algorithm): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $expected = $this->canonical($assertion);

        // When
        $encrypted = $this->encryptor->encrypt($assertion, $this->peer, $algorithm);

        // Then
        $data = EncryptedData::of($encrypted);
        static::assertSame($algorithm, $data->algorithm);
        static::assertSame(OaepHash::Sha1, $data->key->transport->hash);
        static::assertSame(256, strlen($data->key->cipherValue));
        static::assertSame(
            strlen($expected) + ContentAlgorithm::IV_BYTES + ContentAlgorithm::TAG_BYTES,
            strlen($data->cipherValue),
        );
        $decrypted = $this->decryptor->decrypt($encrypted, $this->key);
        static::assertSame($expected, $this->canonical($decrypted->root()));
        static::assertSame($decrypted->root(), $decrypted->elementById(Built::ASSERTION_ID));
    }

    /**
     * @return iterable<string, array{ContentAlgorithm}>
     */
    public static function provideContentAlgorithms(): iterable
    {
        yield 'aes256-gcm' => [ContentAlgorithm::Aes256Gcm];
        yield 'aes128-gcm' => [ContentAlgorithm::Aes128Gcm];
    }

    /**
     * §9.3 row 4, section 13: under rsa-oaep with a SHA-2 hash, the EncryptionMethod names the hash twice and the
     * decryptor decrypts, on PHP 8.5; AlgorithmUnavailable on 8.4, before anything is encrypted.
     */
    #[Test]
    #[TestWith([OaepHash::Sha256], 'SHA-256')]
    #[TestWith([OaepHash::Sha384], 'SHA-384')]
    #[TestWith([OaepHash::Sha512], 'SHA-512')]
    public function itEncryptsUnderRsaOaepWhereTheBuildTakesADigest(OaepHash $hash): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $expected = $this->canonical($assertion);
        if (! $hash->isAvailable()) {
            $this->expectException(AlgorithmUnavailable::class);
            $this->expectExceptionMessageIs('This build cannot wrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }

        // When
        $encrypted = $this->encryptor->encrypt($assertion, $this->peer, transport: new KeyTransport($hash));

        // Then
        $data = EncryptedData::of($encrypted);
        static::assertSame($hash, $data->key->transport->hash);
        static::assertSame(KeyTransport::RSA_OAEP, Attributes::optional(
            Children::one($data->key->element, new Name(Stack::XMLENC, 'EncryptionMethod')),
            new Name(null, 'Algorithm'),
        ));
        $decrypted = $this->decryptor->decrypt($encrypted, $this->key);
        static::assertSame($expected, $this->canonical($decrypted->root()));
    }

    /**
     * §9.3 row 5, E-8: two calls on the same element draw two session keys and two IVs.
     */
    #[Test]
    public function itDrawsFreshRandomnessForEveryCall(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);

        // When
        $first = EncryptedData::of($this->encryptor->encrypt($assertion, $this->peer));
        $second = EncryptedData::of($this->encryptor->encrypt($assertion, $this->peer));

        // Then
        static::assertNotSame($first->key->cipherValue, $second->key->cipherValue);
        static::assertNotSame($first->cipherValue, $second->cipherValue);
        static::assertNotSame(
            substr($first->cipherValue, 0, ContentAlgorithm::IV_BYTES),
            substr($second->cipherValue, 0, ContentAlgorithm::IV_BYTES),
        );
    }

    /**
     * §9.3 row 6: the element comes back in the document of the assertion, unattached; put under an
     * EncryptedAssertion in place of the assertion, the response serializes with Core, loads again and decrypts.
     */
    #[Test]
    public function itReturnsAnUnattachedElementOfTheGivenDocument(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $expected = $this->canonical($assertion);

        // When
        $encrypted = $this->encryptor->encrypt($assertion, $this->peer);

        // Then
        static::assertSame($assertion->ownerDocument, $encrypted->ownerDocument);
        static::assertNull($encrypted->parentNode);
        static::assertSame($document, Document::owning($encrypted));
        $bytes = new Serializer()->serialize($this->wrapped($document, $encrypted));
        static::assertStringContainsString(
            '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>',
            $bytes,
        );
        static::assertStringContainsString(
            '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>',
            $bytes,
        );
        static::assertStringContainsString('<xenc:CipherData><xenc:CipherValue>', $bytes);
        static::assertStringNotContainsString('<saml:Assertion', $bytes);
        $loaded = Loaded::document($bytes);
        $decrypted = $this->decryptor->decrypt(Encrypted::dataOf($loaded), $this->key);
        static::assertSame($expected, $this->canonical($decrypted->root()));
    }

    /**
     * §9.3 row 7: with a certificate, the key's KeyInfo/X509Data/X509Certificate holds its base64; without, the
     * key has no KeyInfo.
     */
    #[Test]
    public function itCarriesTheCertificateWhenGiven(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $pem = Fixtures::bytes('keys/test-signing-certificate.pem');
        $keyInfo = new Name(Stack::XMLDSIG, 'KeyInfo');

        // When
        $with = EncryptedData::of($this->encryptor->encrypt($assertion, $this->peer, certificatePem: $pem));
        $without = EncryptedData::of($this->encryptor->encrypt($assertion, $this->peer));

        // Then
        $certificate = Children::one(
            Children::one(Children::one($with->key->element, $keyInfo), new Name(Stack::XMLDSIG, 'X509Data')),
            new Name(Stack::XMLDSIG, 'X509Certificate'),
        );
        static::assertSame(preg_replace('~-----[A-Z ]+-----|\s~', '', $pem), Text::of($certificate));
        static::assertNull(Children::optional($without->key->element, $keyInfo));
        $decrypted = $this->decryptor->decrypt($with->element, $this->key);
        static::assertSame($this->canonical($assertion), $this->canonical($decrypted->root()));
    }

    /**
     * §9.3 row 8, E-9: an element with a comment and inherited declarations: the plaintext is its exclusive
     * canonical form with comments, the comment kept and the declaration of saml rendered on the assertion, so that
     * it parses on its own.
     */
    #[Test]
    public function itEncryptsTheCanonicalFormWithComments(): void
    {
        // Given
        $document = Built::responseWithCommentedAssertion();
        $assertion = Built::assertionOf($document);
        static::assertNull(Attributes::optional($assertion, new Name(self::XMLNS, 'saml')));

        // When
        $decrypted = $this->decryptor->decrypt($this->encryptor->encrypt($assertion, $this->peer), $this->key);

        // Then
        $root = $decrypted->root();
        static::assertSame($this->canonical($assertion), $this->canonical($root));
        static::assertSame(Stack::SAML_ASSERTION, Attributes::optional($root, new Name(self::XMLNS, 'saml')));
        $nameId = Children::one(
            Children::one($root, new Name(Stack::SAML_ASSERTION, 'Subject')),
            new Name(Stack::SAML_ASSERTION, 'NameID'),
        );
        static::assertSame('user-0001', Text::of($nameId));
        static::assertStringContainsString('<!--' . Built::COMMENT . '-->', $this->canonical($nameId));
    }

    /**
     * §9.3 row 9: a signed assertion (the signer of Dsig) encrypted, decrypted, verified by Dsig: the round trip of
     * the stack.
     */
    #[Test]
    public function itEncryptsASignedAssertionTheStackVerifiesAfterDecryption(): void
    {
        // Given
        $loader = new Loader(Stack::idAttributes());
        $signed = new Signer($loader)->sign(
            Built::responseWithAssertion(),
            Built::ASSERTION_ID,
            PrivateKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem')),
            after: new Name(Stack::SAML_ASSERTION, 'Issuer'),
        );
        $trusted = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);

        // When
        $encrypted = $this->encryptor->encrypt(Built::assertionOf($signed), $this->peer);
        $decrypted = $this->decryptor->decrypt($encrypted, $this->key);

        // Then
        $verified = new Verifier($loader)->verify($decrypted->root(), $trusted);
        static::assertSame(SignatureAlgorithm::RsaSha256, $verified->algorithm);
        static::assertSame(Built::ASSERTION_ID, Attributes::optional(
            $verified->document->root(),
            new Name(null, 'ID'),
        ));
    }

    /**
     * §9.3 row 10: what the encryptor produced once, decrypted by xmlsec1 (tests/Enc/Fixture/behaviour/README.md),
     * decrypts here too to the built assertion.
     */
    #[Test]
    #[TestWith(['encrypted-by-the-encryptor-aes256-gcm.xml'], 'aes256-gcm')]
    #[TestWith(['encrypted-by-the-encryptor-aes128-gcm.xml'], 'aes128-gcm')]
    public function itsOutputIsWhatXmlsec1Decrypted(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('behaviour/' . $fixture);
        $built = Built::responseWithAssertion();
        $expected = $this->canonical(Built::assertionOf($built));

        // When
        $decrypted = $this->decryptor->decrypt(Encrypted::dataOf($document), $this->key);

        // Then
        static::assertSame($expected, $this->canonical($decrypted->root()));
    }

    /**
     * §9.3 row 11: a built element whose default namespace is undeclared is refused by Core's canonicalizer (core.md
     * section 6.3, whose message this asserts), before anything is encrypted.
     */
    #[Test]
    public function itRefusesABuiltElementWhoseDefaultNamespaceIsUndeclared(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS('urn:b', 'b'));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An element without a prefix has no xmlns attribute in scope that declares its namespace (section 6.3).');

        // When
        $this->encryptor->encrypt($root, $this->peer);
    }

    /**
     * Section 6.3: an element detached from its document.
     */
    #[Test]
    public function itRefusesADetachedElement(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $assertion = Built::assertionOf($document);
        $document->root()->removeChild($assertion);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The apex is not connected to its document (section 6.3).');

        // When
        $this->encryptor->encrypt($assertion, $this->peer);
    }

    /**
     * Core I-4: an element of a document parsed outside the loader.
     */
    #[Test]
    public function itRefusesAForeignElement(): void
    {
        // Given
        $foreign = Foreign::parse(Fixtures::bytes('vectors/response-assertion.data.xml'));
        $element = $foreign->documentElement;
        static::assertInstanceOf(Element::class, $element);

        // Then
        $this->expectException(ForeignNode::class);

        // When
        $this->encryptor->encrypt($element, $this->peer);
    }

    /**
     * Section 6.2 step 6: both cipher values are base64 in lines of 76 characters, the last one shorter, no line
     * break at the end, as the interoperability targets write it.
     */
    #[Test]
    public function itWritesBase64InLinesOfSeventySixCharacters(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $cipherValue = new Name(Stack::XMLENC, 'CipherValue');
        $cipherData = new Name(Stack::XMLENC, 'CipherData');

        // When
        $data = EncryptedData::of($this->encryptor->encrypt(Built::assertionOf($document), $this->peer));

        // Then
        foreach ([$data->element, $data->key->element] as $element) {
            $text = Text::of(Children::one(Children::one($element, $cipherData), $cipherValue));
            static::assertFalse(str_ends_with($text, "\n"));
            $lines = explode("\n", $text);
            static::assertGreaterThan(1, count($lines));
            $last = array_pop($lines);
            foreach ($lines as $line) {
                static::assertSame(76, strlen($line));
            }
            static::assertGreaterThan(0, strlen($last));
            static::assertLessThanOrEqual(76, strlen($last));
        }
    }

    /**
     * §9.2 row 40, E-14: a certificate hint that is not exactly one certificate is refused before anything is
     * canonicalized, a private key first, the one thing that must never reach the peer.
     */
    #[Test]
    #[DataProvider('provideHintsThatAreNotOneCertificate')]
    public function itRefusesACertificateHintThatIsNotOneCertificate(string $certificatePem): void
    {
        // Given
        $document = Built::responseWithAssertion();

        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('The certificate is one PEM block of type CERTIFICATE and nothing else (E-14).');

        // When
        $this->encryptor->encrypt(Built::assertionOf($document), $this->peer, certificatePem: $certificatePem);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHintsThatAreNotOneCertificate(): iterable
    {
        $key = Fixtures::bytes('keys/test-signing-key.pem');
        $certificate = Fixtures::bytes('keys/test-signing-certificate.pem');

        yield 'a private key' => [$key];
        yield 'a key then a certificate' => [$key . $certificate];
        yield 'a certificate then a key' => [$certificate . $key];
        yield 'two certificates' => [$certificate . Fixtures::bytes('keys/stranger-certificate.pem')];
        yield 'text after the certificate' => [$certificate . 'x'];
        yield 'no content' => ["-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n"];
        yield 'content that is not base64' => ["-----BEGIN CERTIFICATE-----\nA===\n-----END CERTIFICATE-----\n"];
    }

    /**
     * The exclusive canonical form with comments, the content a decryption gives back (E-9).
     */
    private function canonical(Element $element): string
    {
        return $this->canonicalizer->canonicalize($element, CanonicalizationMethod::ExclusiveWithComments)->bytes;
    }


    /**
     * The response with its assertion replaced by an EncryptedAssertion holding $encrypted, what the consumer does.
     */
    private function wrapped(Document $document, Element $encrypted): Document
    {
        $assertion = Built::assertionOf($document);
        $xml = $assertion->ownerDocument;
        static::assertNotNull($xml);
        $wrapper = $xml->createElementNS(Stack::SAML_ASSERTION, 'saml:EncryptedAssertion');
        $wrapper->appendChild($encrypted);
        $document->root()->replaceChild($wrapper, $assertion);

        return $document;
    }
}
