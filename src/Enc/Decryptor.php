<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\CoveringSignatureRequired;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\Internal\BlockPadding;
use Dom\Element;
use function openssl_decrypt;
use const OPENSSL_RAW_DATA;
use const OPENSSL_ZERO_PADDING;
use function random_bytes;
use function strlen;
use function substr;

/**
 * Decryption in the order of section 6.1: ownership, the reading model with its closed lists (E-1, E-5), AES-CBC only
 * under a signature that covers the encrypted element (E-15), the availability of the hash, the session key unwrapped
 * by the consumer's port (E-6) and checked to the byte (E-2), the content opened under AES-GCM with the IV and the tag
 * cut from the cipher value, or under AES-CBC with its padding read by its count (E-2, E-16), and the plaintext loaded
 * by the consumer's Loader (E-4). Every cryptographic failure is the one failure, raised in one place (E-3, section 6.1
 * step 9). The one openssl_decrypt() call of the namespace lives here, for both modes (E-10).
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
     * AES-GCM only: AES-CBC, which authenticates nothing, is refused by name before any key is touched (E-15). The
     * Document Core loaded from the plaintext; the consumer holds it for as long as it reads its nodes, never the root
     * alone: a document no one holds is forgotten by Core's registry, and its nodes become foreign (section 5.4).
     *
     * @param Element $encrypted the xenc:EncryptedData element, the child of a saml:EncryptedAssertion
     *
     * @throws CoveringSignatureRequired when the content is AES-CBC (E-15)
     * @throws Exception\EncryptionRefused one of its subclasses naming the rule (E-12), or the one failure (E-3)
     * @throws AlgorithmUnavailable a hash this build cannot unwrap under, before any key is touched
     * @throws ForeignNode when $encrypted is not of a document of the brick
     * @throws RefusedXml what Core refuses of the plaintext (E-4): the ciphertext was authentic, the content is not
     */
    public function decrypt(Element $encrypted, DecryptionKeyInterface $key): Document
    {
        $data = EncryptedData::of($encrypted);
        if ($data->algorithm instanceof CbcContentAlgorithm) {
            throw new CoveringSignatureRequired('AES-CBC is decrypted only under a verified signature that covers the encrypted element (E-15).');
        }

        return $this->open($data, $key);
    }

    /**
     * AES-GCM as decrypt() opens it, and AES-CBC, once $signature covers $encrypted: the element is a node of the
     * document the signature covers (E-15). Under AES-CBC, a plaintext Core refuses is the one failure (E-16).
     *
     * @param Element $encrypted the xenc:EncryptedData element, the child of a saml:EncryptedAssertion
     * @param CoveringSignatureInterface $signature the proof the consumer built from a verification, and from nothing else
     *
     * @throws CoveringSignatureRequired when $encrypted is not a node of the document $signature covers (E-15)
     * @throws Exception\EncryptionRefused one of its subclasses naming the rule (E-12), or the one failure (E-3)
     * @throws AlgorithmUnavailable a hash this build cannot unwrap under, before any key is touched
     * @throws ForeignNode when $encrypted is not of a document of the brick
     * @throws RefusedXml what Core refuses of an AES-GCM plaintext (E-4)
     */
    public function decryptCovered(
        Element $encrypted,
        DecryptionKeyInterface $key,
        CoveringSignatureInterface $signature,
    ): Document {
        if (Document::owning($encrypted) !== $signature->document()) {
            throw new CoveringSignatureRequired('The encrypted element is not a node of the document the signature covers (E-15).');
        }

        return $this->open(EncryptedData::of($encrypted), $key);
    }

    /**
     * Section 6.1 steps 4 to 9: every failure of the session key, of the content, of the padding and, under AES-CBC,
     * of the plaintext ends in the one throw of this method, so that the line and the trace of the exception say
     * nothing of which step failed (E-3).
     *
     * @throws Exception\EncryptionRefused
     * @throws RefusedXml
     */
    private function open(EncryptedData $data, DecryptionKeyInterface $key): Document
    {
        $hash = $data->key->transport->hash;
        if (! $hash->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot unwrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }
        $algorithm = $data->algorithm;
        $unwrapped = $key->unwrap($data->key->cipherValue, $hash);
        // the length before the primitive, which accepts a longer key and says nothing (E-2, section 13)
        $sessionKey = $unwrapped !== null && strlen($unwrapped) === $algorithm->keyBytes() ? $unwrapped : null;
        if ($algorithm instanceof ContentAlgorithm) {
            $document = $sessionKey === null ? null : $this->gcm($data->cipherValue, $algorithm, $sessionKey);
        } else {
            // a key that does not unwrap is replaced by random bytes, and the content opened all the same: a wrong
            // key costs what a wrong padding does (E-16, section 13)
            $document = $this->cbc($data->cipherValue, $algorithm, $sessionKey ?? random_bytes($algorithm->keyBytes()));
        }
        if ($sessionKey === null || ! $document instanceof Document) {
            throw new DecryptionFailed();
        }

        return $document;
    }

    /**
     * Section 6.1 steps 6 and 8, AES-GCM: the IV first, the tag last, the ciphertext between; the model refused a value
     * too short for the three (E-2), and GCM keeps the length, so a plaintext that comes back is never empty (section
     * 9.2, row 26). What Core refuses of the plaintext is Core's refusal (E-4).
     *
     * @return ?Document null when the tag or the ciphertext is refused (E-3)
     *
     * @throws RefusedXml
     */
    private function gcm(string $cipherValue, ContentAlgorithm $algorithm, string $sessionKey): ?Document
    {
        $plaintext = self::content(
            substr($cipherValue, ContentAlgorithm::IV_BYTES, -ContentAlgorithm::TAG_BYTES),
            $algorithm->cipher(),
            $sessionKey,
            OPENSSL_RAW_DATA,
            substr($cipherValue, 0, ContentAlgorithm::IV_BYTES),
            substr($cipherValue, -ContentAlgorithm::TAG_BYTES),
        );

        return $plaintext === null ? null : $this->loader->load($plaintext);
    }

    /**
     * Section 6.1 steps 6 to 8, AES-CBC: the IV first, whole blocks after it (E-2); no padding removed by OpenSSL,
     * whose PKCS#7 check refuses the padding of XML Encryption, the count read by BlockPadding and nothing else; a
     * plaintext Core refuses is a failure like the others, CBC having authenticated nothing (E-16).
     *
     * @return ?Document null for a padding, a plaintext or a content refused
     */
    private function cbc(string $cipherValue, CbcContentAlgorithm $algorithm, string $sessionKey): ?Document
    {
        $padded = self::content(
            substr($cipherValue, CbcContentAlgorithm::BLOCK_BYTES),
            $algorithm->cipher(),
            $sessionKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            substr($cipherValue, 0, CbcContentAlgorithm::BLOCK_BYTES),
            null,
        );
        $plaintext = $padded === null ? null : BlockPadding::strip($padded);
        if ($plaintext === null) {
            return null;
        }
        try {
            return $this->loader->load($plaintext);
        } catch (RefusedXml) {
            return null;
        }
    }

    /**
     * The one openssl_decrypt() of the namespace (E-10): the plaintext, or null for whatever the cipher refuses.
     */
    private static function content(
        string $ciphertext,
        string $cipher,
        string $sessionKey,
        int $options,
        string $iv,
        ?string $tag,
    ): ?string {
        $plaintext = openssl_decrypt($ciphertext, $cipher, $sessionKey, $options, $iv, $tag);

        return $plaintext === false ? null : $plaintext;
    }
}
