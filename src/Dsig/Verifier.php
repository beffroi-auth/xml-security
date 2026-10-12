<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Core\Exception\AmbiguousChild;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\MissingChild;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\Exception\WrongReference;
use Beffroi\Xml\Dsig\Internal\Names;
use function constant;
use Dom\Element;
use function hash_equals;
use function openssl_verify;
use function sprintf;
use function strlen;

/**
 * Verification in the order of section 6.1: the Signature as the direct child of the claimed element (D-1), the
 * reading model and its whitelists (D-3, D-4, D-5, D-9), SignedInfo canonicalized and its signature verified
 * against the trusted keys (D-7, D-8), and only then the reference resolved by identity (D-2) and the digest of
 * the element computed with the Signature excluded (D-6). The result is the reload of the bytes that were hashed
 * (D-10). The one openssl_verify() call of the namespace lives here (D-15).
 */
final readonly class Verifier
{
    /**
     * @param Loader $loader the consumer's, with its ID attributes and limits: it re-parses the hashed bytes (D-10)
     */
    public function __construct(
        private Loader $loader,
        private Canonicalizer $canonicalizer = new Canonicalizer(),
    ) {
    }

    /**
     * @param Element $signed the element the consumer claims is signed: the Signature is its direct child (D-1)
     *
     * @throws Exception\SignatureRefused one of its subclasses, naming the rule (D-13)
     * @throws ForeignNode when $signed is not of a document of the brick
     * @throws RefusedXml what Core refuses of the reload (D-10)
     */
    public function verify(Element $signed, VerificationKeys $keys): Verified
    {
        $document = Document::owning($signed);
        try {
            $element = Children::one($signed, Names::dsig('Signature'));
        } catch (MissingChild|AmbiguousChild) {
            throw new MalformedSignature('The claimed element holds exactly one ds:Signature, a direct child (D-1).');
        }
        $signature = Signature::of($element);
        $algorithm = $signature->signedInfo->signatureMethod;
        if (! $algorithm->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot verify RSASSA-PSS: it needs PHP 8.5 and OpenSSL 3.1 (section 13).');
        }
        $signedInfo = $this->canonicalizer->canonicalize(
            $signature->signedInfo->element,
            $signature->signedInfo->canonicalizationMethod,
            $signature->signedInfo->inclusiveNamespaces,
        );
        $key = $this->keyThatVerifies($signedInfo->bytes, $signature->signatureValue, $algorithm, $keys);
        $reference = $signature->signedInfo->reference;
        if (! $document->hasId($reference->id) || $document->elementById($reference->id) !== $signed) {
            throw new WrongReference('The reference does not name the claimed element (D-2).');
        }
        // always without comments: the node-set a same-document reference identifies omits them (XML Signature 1.1
        // §4.4.3.3), whatever the transform says (section 6.1 step 8)
        $canonical = $this->canonicalizer->canonicalize(
            $signed,
            CanonicalizationMethod::Exclusive,
            $reference->inclusiveNamespaces,
            [$element],
        );
        if (! hash_equals($reference->digestValue, $reference->digestMethod->hash($canonical->bytes))) {
            throw new DigestMismatch('The claimed element is not what was signed (D-8).');
        }

        return new Verified($this->loader->load($canonical->bytes), $canonical, $algorithm, $key);
    }

    /**
     * The trusted key under which $signature is a signature of $bytes, for the one signature of the stack that is not
     * XML Signature (section 6.4): the query string of the HTTP-Redirect binding, which saml2-bindings builds in the
     * exact order of its parameters. The rules are those of verify(): the closed list of schemes (D-5), the keys of
     * the peer's metadata (D-7), openssl_verify() compared to 1 (D-8), the length bounded (D-14).
     *
     * @param string $signature the signature, decoded
     *
     * @throws AlgorithmUnavailable a PSS scheme on a build that cannot verify it
     * @throws LimitExceeded when $signature is not between 256 and maxSignatureValueBytes bytes
     * @throws SignatureMismatch when no trusted key verifies it
     */
    public function verifyDetached(
        string $bytes,
        string $signature,
        SignatureAlgorithm $algorithm,
        VerificationKeys $keys,
    ): VerificationKey {
        if (! $algorithm->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot verify RSASSA-PSS: it needs PHP 8.5 and OpenSSL 3.1 (section 13).');
        }
        if (strlen($signature) < Signature::MIN_SIGNATURE_BYTES || strlen($signature) > Signature::MAX_SIGNATURE_BYTES) {
            throw new LimitExceeded(sprintf(
                'A signature is not between %d and maxSignatureValueBytes, %d bytes (D-14).',
                Signature::MIN_SIGNATURE_BYTES,
                Signature::MAX_SIGNATURE_BYTES,
            ));
        }

        return $this->keyThatVerifies(
            $bytes,
            $signature,
            $algorithm,
            $keys,
            'No trusted key verifies the detached signature (D-7, D-8).',
        );
    }

    /**
     * The first trusted key under which openssl_verify() returns 1 (D-8); 0, -1 and false on every key is a
     * mismatch, and nothing about which key came close is kept (D-13).
     *
     * @throws SignatureMismatch
     */
    private function keyThatVerifies(
        string $bytes,
        string $signatureValue,
        SignatureAlgorithm $algorithm,
        VerificationKeys $keys,
        string $mismatch = 'No trusted key verifies the signature over SignedInfo (D-7, D-8).',
    ): VerificationKey {
        $digest = $algorithm->digest()->opensslAlgorithm();
        // the padding parameter exists on PHP 8.5 only, and isAvailable() was checked: a PSS scheme passes it,
        // a PKCS#1 v1.5 scheme leaves the default in place, whatever the build
        $padding = $algorithm->isPss() ? [constant('OPENSSL_PKCS1_PSS_PADDING')] : [];
        foreach ($keys->keys as $key) {
            if (openssl_verify($bytes, $signatureValue, $key->handle(), $digest, ...$padding) === 1) {
                return $key;
            }
        }

        throw new SignatureMismatch($mismatch);
    }
}
