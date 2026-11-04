<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Enc\Exception\LimitExceeded;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Exception\UnknownContentAlgorithm;
use Beffroi\Xml\Enc\Internal\CipherData;
use Beffroi\Xml\Enc\Internal\Names;
use Beffroi\Xml\Enc\Internal\Structure;
use Dom\Element;
use function strlen;

/**
 * Section 5.3, E-5
 */
final readonly class EncryptedData
{
    /**
     * E-2
     */
    public const int MIN_CIPHER_BYTES = ContentAlgorithm::IV_BYTES + 1 + ContentAlgorithm::TAG_BYTES;

    /**
     * @param string $cipherValue decoded: the IV, the ciphertext, then the tag under AES-GCM
     */
    public function __construct(
        public Element $element,
        public ContentAlgorithm|CbcContentAlgorithm $algorithm,
        public EncryptedKey $key,
        public string $cipherValue,
    ) {
    }

    /**
     * @throws MalformedEncryption
     * @throws Exception\UnknownContentAlgorithm
     * @throws Exception\UnknownKeyTransport
     * @throws LimitExceeded
     * @throws ForeignNode
     */
    public static function of(Element $element): self
    {
        Document::owning($element);
        if (! Names::xenc('EncryptedData')->matches($element)) {
            throw new MalformedEncryption('The element is not a xenc:EncryptedData (E-5).');
        }
        if (Attributes::optional($element, Names::attribute('Type')) !== Names::TYPE_ELEMENT) {
            throw new MalformedEncryption('The Type of an EncryptedData is Element: the plaintext is a whole element or nothing (E-5).');
        }
        $encryptionMethod = Names::xenc('EncryptionMethod');
        $keyInfo = Names::dsig('KeyInfo');
        $cipherData = Names::xenc('CipherData');
        Structure::refuseOtherChildren(
            $element,
            [$encryptionMethod, $keyInfo, $cipherData],
            'An EncryptedData holds a child other than EncryptionMethod, KeyInfo and CipherData (E-5).',
        );
        $algorithm = self::algorithm(
            Structure::one($element, $encryptionMethod, 'An EncryptedData holds exactly one EncryptionMethod (E-5).'),
        );
        $key = self::key(Structure::one($element, $keyInfo, 'An EncryptedData holds exactly one KeyInfo (E-5).'));
        $value = CipherData::valueOf(
            Structure::one($element, $cipherData, 'An EncryptedData holds exactly one CipherData (E-5).'),
        );
        if ($algorithm instanceof CbcContentAlgorithm) {
            if (strlen($value) < CbcContentAlgorithm::MIN_CIPHER_BYTES || (strlen($value) % CbcContentAlgorithm::BLOCK_BYTES) !== 0) {
                throw new MalformedEncryption('The cipher value of an AES-CBC EncryptedData holds an IV of 16 bytes and whole blocks of 16 bytes, at least one (E-2).');
            }
        } elseif (strlen($value) < self::MIN_CIPHER_BYTES) {
            throw new MalformedEncryption('The cipher value of an EncryptedData holds an IV of 12 bytes, at least one byte of ciphertext and a tag of 16 bytes (E-2).');
        }

        return new self($element, $algorithm, $key, $value);
    }

    /**
     * @throws MalformedEncryption
     * @throws UnknownContentAlgorithm
     */
    private static function algorithm(Element $encryptionMethod): ContentAlgorithm|CbcContentAlgorithm
    {
        $uri = Attributes::optional(
            $encryptionMethod,
            Names::attribute('Algorithm'),
        ) ?? throw new MalformedEncryption('An EncryptionMethod names its Algorithm (E-5).');
        $algorithm =
            ContentAlgorithm::tryFrom($uri)
            ?? CbcContentAlgorithm::tryFrom($uri)
            ?? throw new UnknownContentAlgorithm('The content algorithm is not AES-128-GCM, AES-256-GCM, AES-128-CBC or AES-256-CBC (E-1).');
        Structure::none($encryptionMethod, 'The EncryptionMethod of an EncryptedData holds no child (E-5).');

        return $algorithm;
    }

    /**
     * @throws MalformedEncryption
     * @throws Exception\UnknownKeyTransport
     * @throws LimitExceeded
     */
    private static function key(Element $keyInfo): EncryptedKey
    {
        $encryptedKey = Names::xenc('EncryptedKey');
        Structure::refuseOtherChildren(
            $keyInfo,
            [$encryptedKey],
            'The KeyInfo of an EncryptedData holds nothing but an EncryptedKey (E-5).',
        );

        return EncryptedKey::of(
            Structure::one(
                $keyInfo,
                $encryptedKey,
                'The KeyInfo of an EncryptedData holds exactly one EncryptedKey (E-5).',
            ),
        );
    }
}
