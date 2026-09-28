<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\DigestAlgorithm;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\Signer;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Built;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
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
 * §9.3 row 10: the assertion of a built response, then the response, signed with every scheme this build offers,
 * exclusive and exclusive with comments, written into the directory XMLSEC_ORACLE names for xmlsec1 to verify
 * both signatures of each (tests/Dsig/Fixture/oracle/README.md, the job Oracle of the CI). The files are the
 * input of the oracle, not fixtures: the test is skipped when the variable is not set.
 */
#[RequiresEnvironmentVariable('XMLSEC_ORACLE')]
final class SignerOracleTest extends TestCase
{
    #[Test]
    #[DataProvider('provideSchemes')]
    public function itWritesAResponseSignedTwiceForXmlsec1(
        SignatureAlgorithm $algorithm,
        DigestAlgorithm $digest,
        CanonicalizationMethod $method,
    ): void {
        // Given
        $directory = getenv('XMLSEC_ORACLE');
        static::assertIsString($directory);
        static::assertTrue(is_dir($directory) || mkdir($directory, 0o777, true));
        $signer = new Signer(new Loader(Stack::idAttributes()));
        $key = PrivateKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
        $certificate = Fixtures::bytes('keys/test-signing-certificate.pem');
        $issuer = new Name(Stack::SAML_ASSERTION, 'Issuer');
        $document = Built::responseWithAssertion();
        $xml = $document->root()->ownerDocument;
        static::assertInstanceOf(XMLDocument::class, $xml);
        // a comment inside the signed element: a same-document reference digests it away, whatever the method
        Children::one(
            $document->root(),
            new Name(Stack::SAML_ASSERTION, 'Assertion'),
        )->appendChild($xml->createComment(' left out of the digest '));

        // When
        $assertion = $signer->sign(
            $document,
            Built::ASSERTION_ID,
            $key,
            $algorithm,
            $issuer,
            $certificate,
            $method,
            $digest,
        );
        $both = $signer->sign(
            $assertion,
            Built::RESPONSE_ID,
            $key,
            $algorithm,
            $issuer,
            $certificate,
            $method,
            $digest,
        );
        $written = file_put_contents(
            sprintf('%s/%s-%s-%s.xml', $directory, $algorithm->name, $digest->name, $method->name),
            new Serializer()->serialize($both),
        );

        // Then
        static::assertNotFalse($written);
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm, DigestAlgorithm, CanonicalizationMethod}>
     */
    public static function provideSchemes(): iterable
    {
        foreach (SignatureAlgorithm::cases() as $algorithm) {
            if (! $algorithm->isAvailable()) {
                continue;
            }
            foreach ([CanonicalizationMethod::Exclusive, CanonicalizationMethod::ExclusiveWithComments] as $method) {
                yield sprintf('%s, %s', $algorithm->name, $method->name) => [
                    $algorithm,
                    $algorithm->digest(),
                    $method,
                ];
            }
        }
        yield 'RsaSha256 over a digest of Sha512' => [
            SignatureAlgorithm::RsaSha256,
            DigestAlgorithm::Sha512,
            CanonicalizationMethod::Exclusive,
        ];
    }
}
