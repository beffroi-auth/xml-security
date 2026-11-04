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
use Beffroi\Xml\Enc\Internal\LoadedPlaintext;
use Dom\Element;
use function openssl_decrypt;
use const OPENSSL_RAW_DATA;
use const OPENSSL_ZERO_PADDING;
use function random_bytes;
use function strlen;
use function substr;

/**
 * Section 6.1
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
     * The consumer holds the returned Document for as long as it reads its nodes, never the root alone: a document
     * no one holds is forgotten by Core's registry, and its nodes become foreign.
     *
     * @param Element $encrypted the xenc:EncryptedData element
     *
     * @throws CoveringSignatureRequired when the content is AES-CBC
     * @throws Exception\EncryptionRefused
     * @throws AlgorithmUnavailable
     * @throws ForeignNode
     * @throws RefusedXml
     */
    public function decrypt(Element $encrypted, DecryptionKeyInterface $key): Document
    {
        $data = EncryptedData::of($encrypted);
        if ($data->algorithm instanceof CbcContentAlgorithm) {
            throw new CoveringSignatureRequired('AES-CBC is decrypted only under a verified signature that covers the encrypted element (E-15).');
        }

        return $this->open($data, $key, new LoadedPlaintext());
    }

    /**
     * AES-CBC too, once $signature covers $encrypted (E-15). $reader reads the plaintext inside the decryption,
     * so that under AES-CBC its refusals are the one failure (E-16).
     *
     * @template T
     *
     * @param Element $encrypted the xenc:EncryptedData element
     * @param DecryptionKeyInterface $key the key whose certificate went to the peer whose signature $signature
     *                                    is, and to no other peer (E-15)
     * @param PlaintextReaderInterface<T> $reader
     *
     * @return T
     *
     * @throws CoveringSignatureRequired
     * @throws Exception\EncryptionRefused
     * @throws AlgorithmUnavailable
     * @throws ForeignNode
     * @throws RefusedXml
     */
    public function decryptCovered(
        Element $encrypted,
        DecryptionKeyInterface $key,
        CoveringSignatureInterface $signature,
        PlaintextReaderInterface $reader,
    ): mixed {
        $covered = $signature->document();
        // A node of the covered document outside its root, removed or never put in the tree, was not signed.
        if (Document::owning($encrypted) !== $covered || ! $covered->root()->contains($encrypted)) {
            throw new CoveringSignatureRequired('The encrypted element is not a node of the document the signature covers (E-15).');
        }

        return $this->open(EncryptedData::of($encrypted), $key, $reader);
    }

    /**
     * Section 6.1 steps 4 to 9: every failure ends in the one throw of this method, so that the line and the trace
     * of the exception say nothing of which step failed (E-3, E-16).
     *
     * @template T
     *
     * @param PlaintextReaderInterface<T> $reader
     *
     * @return T
     *
     * @throws Exception\EncryptionRefused
     * @throws RefusedXml
     */
    private function open(EncryptedData $data, DecryptionKeyInterface $key, PlaintextReaderInterface $reader): mixed
    {
        $hash = $data->key->transport->hash;
        if (! $hash->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot unwrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }
        $algorithm = $data->algorithm;
        $unwrapped = $key->unwrap($data->key->cipherValue, $hash);
        // The length is checked before the primitive, which accepts a longer key and says nothing (E-2, section 13).
        $sessionKey = $unwrapped !== null && strlen($unwrapped) === $algorithm->keyBytes() ? $unwrapped : null;
        if ($algorithm instanceof ContentAlgorithm) {
            $read = $sessionKey === null ? null : $this->gcm($data->cipherValue, $algorithm, $sessionKey, $reader);
        } else {
            // A key that does not unwrap is replaced by random bytes and the content opened all the same:
            // a wrong key costs what a wrong padding does (E-16, section 13).
            $read = $this->cbc($data->cipherValue, $algorithm, $sessionKey ?? random_bytes($algorithm->keyBytes()), $reader);
        }
        if ($sessionKey === null || $read === null) {
            throw new DecryptionFailed();
        }

        return $read[0];
    }

    /**
     * Section 6.1 steps 6 and 8
     *
     * @template T
     *
     * @param PlaintextReaderInterface<T> $reader
     *
     * @return ?array{T} null when the tag or the ciphertext is refused
     *
     * @throws RefusedXml
     */
    private function gcm(
        string $cipherValue,
        ContentAlgorithm $algorithm,
        string $sessionKey,
        PlaintextReaderInterface $reader,
    ): ?array {
        $plaintext = self::content(
            substr($cipherValue, ContentAlgorithm::IV_BYTES, -ContentAlgorithm::TAG_BYTES),
            $algorithm->cipher(),
            $sessionKey,
            OPENSSL_RAW_DATA,
            substr($cipherValue, 0, ContentAlgorithm::IV_BYTES),
            substr($cipherValue, -ContentAlgorithm::TAG_BYTES),
        );

        return $plaintext === null ? null : [$reader->read($this->loader->load($plaintext))];
    }

    /**
     * Section 6.1 steps 6 to 8: OpenSSL removes no padding, its PKCS#7 check refusing the padding of XML Encryption.
     *
     * @template T
     *
     * @param PlaintextReaderInterface<T> $reader
     *
     * @return ?array{T} null for a content, a padding, a plaintext or a reading refused
     */
    private function cbc(
        string $cipherValue,
        CbcContentAlgorithm $algorithm,
        string $sessionKey,
        PlaintextReaderInterface $reader,
    ): ?array {
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
            return [$reader->read($this->loader->load($plaintext))];
        } catch (RefusedXml) {
            return null;
        }
    }

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
