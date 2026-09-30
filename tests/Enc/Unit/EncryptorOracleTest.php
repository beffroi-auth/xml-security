<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Enc\ContentAlgorithm;
use Beffroi\Xml\Enc\Encryptor;
use Beffroi\Xml\Enc\KeyTransport;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Enc\PeerKey;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\Built;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Dom\XMLDocument;
use function file_put_contents;
use function getenv;
use function is_dir;
use function mkdir;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresEnvironmentVariable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * §9.3 row 10: the assertion of a built response, a comment in it and a QName value naming a prefix of the response,
 * encrypted under each content method and each hash this build offers, written into the directory XMLSEC_ORACLE
 * names with the document xmlsec1 must give back, in its exclusive canonical form with comments
 * (tests/Enc/Fixture/oracle/README.md, the job Oracle of the CI). The files are the input of the oracle, not
 * fixtures: the test is skipped when the variable is not set.
 */
#[RequiresEnvironmentVariable('XMLSEC_ORACLE')]
final class EncryptorOracleTest extends TestCase
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    private const string XS = 'http://www.w3.org/2001/XMLSchema';

    private const string XSI = 'http://www.w3.org/2001/XMLSchema-instance';

    #[Test]
    #[DataProvider('provideSchemes')]
    public function itWritesAnEncryptedResponseAndWhatItDecryptsTo(ContentAlgorithm $algorithm, OaepHash $hash): void
    {
        // Given
        $directory = getenv('XMLSEC_ORACLE');
        static::assertIsString($directory);
        $directory .= '/enc';
        static::assertTrue(is_dir($directory) || mkdir($directory, 0o777, true));
        $document = Built::responseWithCommentedAssertion();
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertInstanceOf(XMLDocument::class, $xml);
        $root->setAttributeNS(self::XMLNS, 'xmlns:xs', self::XS);
        $root->setAttributeNS(self::XMLNS, 'xmlns:xsi', self::XSI);
        $assertion = Built::assertionOf($document);
        Children::one(
            Children::one(
                Children::one($assertion, new Name(Stack::SAML_ASSERTION, 'AttributeStatement')),
                new Name(Stack::SAML_ASSERTION, 'Attribute'),
            ),
            new Name(Stack::SAML_ASSERTION, 'AttributeValue'),
        )->setAttributeNS(self::XSI, 'xsi:type', 'xs:string');
        // the assertion inside the EncryptedAssertion the consumer builds, where the EncryptedData will stand
        $wrapper = $xml->createElementNS(Stack::SAML_ASSERTION, 'saml:EncryptedAssertion');
        $root->replaceChild($wrapper, $assertion);
        $wrapper->appendChild($assertion);
        $expected = new Canonicalizer()->canonicalize($root, CanonicalizationMethod::ExclusiveWithComments)->bytes;

        // When
        $encrypted = new Encryptor(new Loader(Stack::idAttributes()))->encrypt(
            $assertion,
            PeerKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
            $algorithm,
            new KeyTransport($hash),
        );
        $wrapper->replaceChild($encrypted, $assertion);
        $name = sprintf('%s/%s-%s', $directory, $algorithm->name, $hash->name);
        $written = file_put_contents($name . '.xml', new Serializer()->serialize($document));

        // Then
        static::assertNotFalse($written);
        static::assertNotFalse(file_put_contents($name . '.expected', $expected));
    }

    /**
     * @return iterable<string, array{ContentAlgorithm, OaepHash}>
     */
    public static function provideSchemes(): iterable
    {
        foreach (ContentAlgorithm::cases() as $algorithm) {
            foreach (OaepHash::cases() as $hash) {
                if (! $hash->isAvailable()) {
                    continue;
                }

                yield sprintf('%s, %s', $algorithm->name, $hash->name) => [$algorithm, $hash];
            }
        }
    }
}
