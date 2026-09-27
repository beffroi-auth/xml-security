<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Enc\ContentAlgorithm;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\EncryptedData;
use Beffroi\Xml\Enc\Exception\UnknownContentAlgorithm;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.4: the real documents, what SimpleSAMLphp's library encrypted, decrypted here with the test key
 * (tests/Enc/Fixture/real/README.md); the interoperability is proven, the trust is the metadata layer's business.
 */
final class RealDocumentsTest extends TestCase
{
    /**
     * §9.4, section 13: what xmlseclibs 3.1.5, the library under simplesamlphp/saml2, encrypted for this namespace
     * on 27 September 2026 over the assertion of the data file, under aes256-gcm then aes128-gcm, the session key
     * under rsa-oaep-mgf1p, the EncryptedKey inside a dsig:KeyInfo with no hint.
     */
    #[Test]
    #[TestWith(
        ['simplesamlphp-xmlseclibs-3.1.5-response-encrypted-aes256-gcm-2026-09-27.xml', ContentAlgorithm::Aes256Gcm],
        'aes256-gcm',
    )]
    #[TestWith(
        ['simplesamlphp-xmlseclibs-3.1.5-response-encrypted-aes128-gcm-2026-09-27.xml', ContentAlgorithm::Aes128Gcm],
        'aes128-gcm',
    )]
    public function itDecryptsWhatSimpleSamlPhpsLibraryEncrypted(string $fixture, ContentAlgorithm $algorithm): void
    {
        // Given
        $document = Loaded::fixture('real/' . $fixture);
        $element = Encrypted::dataOf($document);
        $data = EncryptedData::of($element);
        static::assertSame($algorithm, $data->algorithm);
        static::assertSame(OaepHash::Sha1, $data->key->transport->hash);

        // When
        $decrypted = new Decryptor(new Loader(Stack::idAttributes()))->decrypt($element, $this->key());

        // Then
        $root = $decrypted->root();
        static::assertSame($root, $decrypted->elementById('_assertion-d4e5f6'));
        static::assertSame(
            'https://idp.example.org',
            Text::of(Children::one($root, new Name(Stack::SAML_ASSERTION, 'Issuer'))),
        );
        $nameId = Children::one(
            Children::one($root, new Name(Stack::SAML_ASSERTION, 'Subject')),
            new Name(Stack::SAML_ASSERTION, 'NameID'),
        );
        static::assertSame('user-0001', Text::of($nameId));
    }

    /**
     * §9.4, E-1, section 12: what simplesamlphp/saml2 4.20.3's EncryptedAssertion::setAssertion() produces under
     * the peer's RSA key, aes128-cbc with rsa-oaep-mgf1p, which is what a SimpleSAMLphp identity provider sends:
     * refused by name, the trade-off decision 0013 made.
     */
    #[Test]
    public function itRefusesWhatSimpleSamlPhpsSetAssertionEncryptsByDefault(): void
    {
        // Given
        $document = Loaded::fixture('real/simplesamlphp-saml2-4.20.3-response-encrypted-assertion-default-2026-09-27.xml');
        $element = Encrypted::dataOf($document);

        // Then
        $this->expectException(UnknownContentAlgorithm::class);
        $this->expectExceptionMessageIs('The content algorithm is not AES-128-GCM or AES-256-GCM (E-1).');

        // When
        new Decryptor(new Loader(Stack::idAttributes()))->decrypt($element, $this->key());
    }

    private function key(): PrivateDecryptionKey
    {
        return PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
    }
}
