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
 * The xenc:EncryptedKey inside the KeyInfo of an EncryptedData, read strictly (section 5.3, E-5): an
 * EncryptionMethod of the closed list (E-1), an optional KeyInfo that is never read (E-6), a CipherData holding a
 * CipherValue whose decoded length is that of an RSA key transport (E-13); ReferenceList, CarriedKeyName and
 * everything else refused.
 */
final readonly class EncryptedKey
{
    /**
     * Section 7: the decoded cipher value, from an RSA-2048 transport to an RSA-8192 one.
     */
    public const int MIN_CIPHER_BYTES = 256;

    public const int MAX_CIPHER_BYTES = 1024;

    public function __construct(
        public Element $element,
        public KeyTransport $transport,
        public string $cipherValue,
    ) {
    }

    /**
     * @throws MalformedEncryption when the element is not an xenc:EncryptedKey, or the structure, a child or a base64
     *                             text is not what section 5.3 says
     * @throws Exception\UnknownKeyTransport
     * @throws LimitExceeded
     * @throws ForeignNode when $element is not of a document of the brick
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
        // the recipient's hint: counted, never read (E-6)
        Structure::optional($element, $keyInfo, 'An EncryptedKey holds at most one KeyInfo (E-5).');
        $transport = KeyTransport::of(
            Structure::one($element, $encryptionMethod, 'An EncryptedKey holds exactly one EncryptionMethod (E-5).'),
        );
        $value = CipherData::valueOf(
            Structure::one($element, $cipherData, 'An EncryptedKey holds exactly one CipherData (E-5).'),
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
