<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Dom\Element;
use function openssl_decrypt;
use const OPENSSL_RAW_DATA;
use function strlen;
use function substr;

/**
 * Decryption in the order of section 6.1: ownership and the reading model with its closed lists (E-1, E-5), the
 * availability of the hash, the session key unwrapped by the consumer's port (E-6) and checked to the byte (E-2),
 * the content opened under AES-GCM with the IV and the tag cut from the cipher value (E-2), and the plaintext loaded
 * by the consumer's Loader (E-4). Every cryptographic failure is the one failure (E-3). The one openssl_decrypt()
 * call of the namespace lives here (E-10).
 */
final readonly class Decryptor
{
    /**
     * @param Loader $loader the consumer's, with its ID attributes and limits: it loads the plaintext (E-4)
     */
    public function __construct(
        private Loader $loader,
    ) {
    }

    /**
     * @param Element $encrypted the xenc:EncryptedData element, the child of a saml:EncryptedAssertion
     *
     * @throws Exception\EncryptionRefused one of its subclasses naming the rule (E-12), or the one failure (E-3)
     * @throws AlgorithmUnavailable a hash this build cannot unwrap under, before any key is touched
     * @throws ForeignNode when $encrypted is not of a document of the brick
     * @throws RefusedXml what Core refuses of the plaintext (E-4): the ciphertext was authentic, the content is not
     */
    public function decrypt(Element $encrypted, DecryptionKeyInterface $key): Document
    {
        $data = EncryptedData::of($encrypted);
        $hash = $data->key->transport->hash;
        if (! $hash->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot unwrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }
        $sessionKey = $key->unwrap($data->key->cipherValue, $hash);
        // the length before the primitive, which accepts a longer key and says nothing (E-2, section 13)
        if ($sessionKey === null || strlen($sessionKey) !== $data->algorithm->keyBytes()) {
            throw new DecryptionFailed();
        }
        // the IV first, the tag last, the ciphertext between: the model refused a value too short for the three
        // (E-2), and GCM keeps the length, so a plaintext that comes back is never empty (section 9.2, row 26)
        $plaintext = openssl_decrypt(
            substr($data->cipherValue, ContentAlgorithm::IV_BYTES, -ContentAlgorithm::TAG_BYTES),
            $data->algorithm->cipher(),
            $sessionKey,
            OPENSSL_RAW_DATA,
            substr($data->cipherValue, 0, ContentAlgorithm::IV_BYTES),
            substr($data->cipherValue, -ContentAlgorithm::TAG_BYTES),
        );
        if ($plaintext === false) {
            throw new DecryptionFailed();
        }

        return $this->loader->load($plaintext);
    }
}
