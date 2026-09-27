<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Enc\Exception\LimitExceeded;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Internal\CipherData;
use Beffroi\Xml\Enc\Internal\Names;
use Beffroi\Xml\Enc\Internal\Structure;
use Dom\Element;
use function strlen;

/**
 * The xenc:EncryptedData element read strictly (section 5.3, E-5), nothing decrypted: a Type of Element, an
 * EncryptionMethod of the closed list with no child (E-1), a KeyInfo holding exactly one EncryptedKey, a CipherData
 * holding a CipherValue long enough for an IV, a byte of ciphertext and a tag (E-2); CipherReference,
 * EncryptionProperties and everything else refused. A consumer may read an encrypted element without decrypting it;
 * only Decryptor decrypts.
 */
final readonly class EncryptedData
{
    /**
     * E-2: an IV, at least one byte of ciphertext, and a tag.
     */
    public const int MIN_CIPHER_BYTES = ContentAlgorithm::IV_BYTES + 1 + ContentAlgorithm::TAG_BYTES;

    /**
     * @param string $cipherValue decoded: the IV, the ciphertext and the tag, in that order (XML Encryption 1.1 §5.2.4)
     */
    public function __construct(
        public Element $element,
        public ContentAlgorithm $algorithm,
        public EncryptedKey $key,
        public string $cipherValue,
    ) {
    }

    /**
     * @throws MalformedEncryption when the structure, the Type, a child, a base64 text or a length is not what
     *                             section 5.3 says
     * @throws Exception\UnknownContentAlgorithm
     * @throws Exception\UnknownKeyTransport
     * @throws LimitExceeded
     * @throws ForeignNode when $element is not of a document of the brick
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
        if (strlen($value) < self::MIN_CIPHER_BYTES) {
            throw new MalformedEncryption('The cipher value of an EncryptedData holds an IV of 12 bytes, at least one byte of ciphertext and a tag of 16 bytes (E-2).');
        }

        return new self($element, $algorithm, $key, $value);
    }

    /**
     * @throws MalformedEncryption
     * @throws Exception\UnknownContentAlgorithm
     */
    private static function algorithm(Element $encryptionMethod): ContentAlgorithm
    {
        $algorithm = ContentAlgorithm::fromUri(
            Attributes::optional(
                $encryptionMethod,
                Names::attribute('Algorithm'),
            ) ?? throw new MalformedEncryption('An EncryptionMethod names its Algorithm (E-5).'),
        );
        Structure::none($encryptionMethod, 'The EncryptionMethod of an EncryptedData holds no child (E-5).');

        return $algorithm;
    }

    /**
     * The one EncryptedKey the KeyInfo holds, the form SimpleSAMLphp's library and xmlsec1 produce (section 5.3).
     *
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
