<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use function base64_encode;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Internal\Registry;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\EncryptionFailed;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use Beffroi\Xml\Enc\Internal\Names;
use Beffroi\Xml\Enc\Internal\Pem;
use function chunk_split;
use Dom\Element;
use Dom\XMLDocument;
use InvalidArgumentException;
use function openssl_encrypt;
use const OPENSSL_RAW_DATA;
use function random_bytes;
use function rtrim;
use SensitiveParameter;

/**
 * Encryption in the order of section 6.2: the availability of the hash, the element canonicalized with comments so
 * that the plaintext carries every declaration it uses (E-9), a fresh session key and IV (E-8), the content under
 * AES-GCM, the session key wrapped to the peer under RSA-OAEP, and a xenc:EncryptedData built with a prefix on
 * every element, in the document of the element, returned unattached for the consumer to place. The one
 * openssl_encrypt() call of the namespace lives here (E-10).
 */
final readonly class Encryptor
{
    public function __construct(
        private Canonicalizer $canonicalizer = new Canonicalizer(),
    ) {
    }

    /**
     * A new xenc:EncryptedData element, built in the document of $element and returned unattached, holding the
     * exclusive canonical form with comments of $element under a fresh session key and IV, the key under RSA-OAEP
     * to $peer. The consumer puts it where its protocol says and removes the plaintext element itself.
     *
     * @param ?string $certificatePem when given, one PEM certificate (E-14), carried by the KeyInfo of the EncryptedKey
     *                                for peers that want the hint
     *
     * @throws InvalidKey when $certificatePem is not exactly one certificate (E-14)
     * @throws AlgorithmUnavailable a hash this build cannot wrap under
     * @throws InvalidArgumentException when $element is not connected to its document, or an element of its
     *                                  subtree without a prefix has no declaration in scope (core.md 6.3)
     * @throws EncryptionFailed when a primitive fails: never input
     * @throws ForeignNode when $element is not of a document of the brick
     */
    public function encrypt(
        Element $element,
        PeerKey $peer,
        ContentAlgorithm $algorithm = ContentAlgorithm::Aes256Gcm,
        KeyTransport $transport = new KeyTransport(OaepHash::Sha1),
        #[SensitiveParameter]
        ?string $certificatePem = null,
    ): Element {
        if (! $transport->hash->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot wrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }
        $certificate = $certificatePem === null
            ? null
            : base64_encode(
                Pem::block(
                    $certificatePem,
                    'CERTIFICATE',
                ) ?? throw new InvalidKey('The certificate is one PEM block of type CERTIFICATE and nothing else (E-14).'),
            );
        $plaintext = $this->canonicalizer->canonicalize(
            $element,
            CanonicalizationMethod::ExclusiveWithComments,
        )->bytes;
        $sessionKey = random_bytes($algorithm->keyBytes());
        $iv = random_bytes(ContentAlgorithm::IV_BYTES);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            $algorithm->cipher(),
            $sessionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            ContentAlgorithm::TAG_BYTES,
        );
        // openssl_encrypt() gives the ciphertext and fills the tag: a key of the length the cipher takes never
        // reaches the false
        if ($ciphertext === false) {
            throw new EncryptionFailed('OpenSSL could not encrypt the element (section 6.2).');
        }
        $wrapped = $peer->wrap($sessionKey, $transport->hash);

        $xml = Registry::xmlOf(Document::owning($element));
        $data = $xml->createElementNS(Names::XMLENC, 'xenc:EncryptedData');
        $data->setAttribute('Type', Names::TYPE_ELEMENT);
        $this->child($xml, $data, Names::XMLENC, 'xenc:EncryptionMethod')->setAttribute('Algorithm', $algorithm->value);
        $key = $this->child(
            $xml,
            $this->child($xml, $data, Names::DSIG, 'ds:KeyInfo'),
            Names::XMLENC,
            'xenc:EncryptedKey',
        );
        $method = $this->child($xml, $key, Names::XMLENC, 'xenc:EncryptionMethod');
        $method->setAttribute('Algorithm', $transport->uri());
        if ($transport->hash !== OaepHash::Sha1) {
            $this->child($xml, $method, Names::DSIG, 'ds:DigestMethod')->setAttribute(
                'Algorithm',
                $transport->hash->value,
            );
            $this->child($xml, $method, Names::XMLENC11, 'xenc11:MGF')->setAttribute(
                'Algorithm',
                $transport->hash->mgfUri(),
            );
        }
        if ($certificate !== null) {
            $x509 = $this->child(
                $xml,
                $this->child($xml, $key, Names::DSIG, 'ds:KeyInfo'),
                Names::DSIG,
                'ds:X509Data',
            );
            $this->child(
                $xml,
                $x509,
                Names::DSIG,
                'ds:X509Certificate',
            )->appendChild($xml->createTextNode($certificate));
        }
        $this->cipherData($xml, $key, $wrapped);
        $this->cipherData($xml, $data, $iv . $ciphertext . $tag);

        return $data;
    }

    /**
     * A prefixed element appended to its parent: the rule of core.md 6.5 for a built tree.
     */
    private function child(XMLDocument $xml, Element $parent, string $namespace, string $qualified): Element
    {
        $child = $xml->createElementNS($namespace, $qualified);
        $parent->appendChild($child);

        return $child;
    }

    /**
     * A CipherData holding the one CipherValue of $bytes, base64 with a line break every 76 characters, as the
     * interoperability targets write it (section 6.2 step 6).
     */
    private function cipherData(XMLDocument $xml, Element $parent, string $bytes): void
    {
        $this->child(
            $xml,
            $this->child($xml, $parent, Names::XMLENC, 'xenc:CipherData'),
            Names::XMLENC,
            'xenc:CipherValue',
        )->appendChild($xml->createTextNode(rtrim(chunk_split(base64_encode($bytes), 76, "\n"), "\n")));
    }
}
