<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Enc\Exception\LimitExceeded;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Internal\CipherData;
use Beffroi\Xml\Enc\Internal\Names;
use Beffroi\Xml\Enc\Internal\Structure;
use Dom\Element;
use function sprintf;
use function strlen;

/**
 * Section 5.3, E-5
 */
final readonly class EncryptedKey
{
    /**
     * Section 7: the decoded cipher value of an RSA-2048 transport.
     */
    public const int MIN_CIPHER_BYTES = 256;

    public const int MAX_CIPHER_BYTES = 1024;

    /**
     * Section 7
     */
    public const int MAX_TEXT_BYTES = 4096;

    public function __construct(
        public Element $element,
        public KeyTransport $transport,
        public string $cipherValue,
    ) {
    }

    /**
     * @throws MalformedEncryption
     * @throws Exception\UnknownKeyTransport
     * @throws LimitExceeded
     * @throws ForeignNode
     */
    public static function of(Element $element): self
    {
        Document::owning($element);
        if (! Names::xenc('EncryptedKey')->matches($element)) {
            throw new MalformedEncryption('The element is not an xenc:EncryptedKey (E-5).');
        }
        $encryptionMethod = Names::xenc('EncryptionMethod');
        $keyInfo = Names::dsig('KeyInfo');
        $cipherData = Names::xenc('CipherData');
        Structure::refuseOtherChildren(
            $element,
            [$encryptionMethod, $keyInfo, $cipherData],
            'An EncryptedKey holds a child other than EncryptionMethod, KeyInfo and CipherData (E-5).',
        );
        // The recipient's hint is counted, never read (E-6).
        Structure::optional($element, $keyInfo, 'An EncryptedKey holds at most one KeyInfo (E-5).');
        $transport = KeyTransport::of(
            Structure::one($element, $encryptionMethod, 'An EncryptedKey holds exactly one EncryptionMethod (E-5).'),
        );
        $value = CipherData::valueOf(
            Structure::one($element, $cipherData, 'An EncryptedKey holds exactly one CipherData (E-5).'),
            self::MAX_TEXT_BYTES,
            'maxEncryptedKeyTextBytes',
        );
        if (strlen($value) < self::MIN_CIPHER_BYTES || strlen($value) > self::MAX_CIPHER_BYTES) {
            throw new LimitExceeded(sprintf(
                'The cipher value of an EncryptedKey is not between %d and maxEncryptedKeyBytes, %d bytes (E-13).',
                self::MIN_CIPHER_BYTES,
                self::MAX_CIPHER_BYTES,
            ));
        }

        return new self($element, $transport, $value);
    }
}
