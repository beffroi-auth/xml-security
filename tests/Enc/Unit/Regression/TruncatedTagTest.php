<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit\Regression;

use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\EncryptedData;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, the truncated tag: CVE-2026-32313 in xmlseclibs and CVE-2026-32600 in simplesamlphp/xml-security,
 * March 2026, missing AES-GCM authentication tag validation, where a tag truncated down to nothing authenticated
 * anything; and PHP's primitive accepts a truncated tag and says nothing (section 13). The rules: the tag is the
 * last 16 bytes of the cipher value whatever its length (E-2), so a shortened value loses ciphertext, not tag, and
 * fails in the one way (E-3); a value too short for an IV, a byte and a tag never reaches the primitive.
 */
final class TruncatedTagTest extends TestCase
{
    /**
     * CVE-2026-32313, CVE-2026-32600, §9.2 row 24: the cipher value shortened by one byte is a 16-byte tag that
     * does not verify, not a 15-byte tag the primitive would accept.
     */
    #[Test]
    public function cve202632313AndCve202632600ATruncatedTagFailsInTheOneWay(): void
    {
        // Given
        $document = Loaded::fixture('hostile/tag-truncated-refused.xml');
        $element = Encrypted::dataOf($document);
        $decryptor = new Decryptor(new Loader(Stack::idAttributes()));
        $key = PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        $decryptor->decrypt($element, $key);
    }

    /**
     * §9.2 rows 17 and 26, E-2: a cipher value of an IV and a tag with nothing between is refused by the model,
     * which is why an empty plaintext is not reachable: GCM keeps the length, and there is always a byte to keep.
     */
    #[Test]
    public function theModelRefusesACipherValueWithNoRoomForCiphertext(): void
    {
        // Given
        $document = Loaded::fixture('hostile/data-cipher-value-28-bytes-refused.xml');
        $element = Encrypted::dataOf($document);

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('The cipher value of an EncryptedData holds an IV of 12 bytes, at least one byte of ciphertext and a tag of 16 bytes (E-2).');

        // When
        EncryptedData::of($element);
    }
}
