<?php

declare(strict_types=1);

/*
 * The hostile fixtures the decryptor refuses (spec/enc.md section 9.2, rows 20 to 28): each one is the vector
 * ../vectors/response-encrypted-assertion-aes256-gcm.xml altered or re-encrypted under the test keys of ../keys/,
 * with the one change its name says. Run from this directory: php derive-decryptor.php. The session keys and IVs
 * are derived from the fixture's name, so that a run reproduces the same ciphertexts; the RSA-OAEP wrapping is
 * randomized by construction, so the wrapped keys differ from one run to the next.
 */

const XMLENC11 = 'http://www.w3.org/2009/xmlenc11#';
const IV_BYTES = 12;
const TAG_BYTES = 16;

$vector = file_get_contents(__DIR__ . '/../vectors/response-encrypted-assertion-aes256-gcm.xml');
$private = openssl_pkey_get_private((string) file_get_contents(__DIR__ . '/../keys/test-signing-key.pem'));
$public = openssl_pkey_get_public((string) file_get_contents(__DIR__ . '/../keys/test-signing-certificate.pem'));
if ($vector === false || $private === false || $public === false) {
    exit(1);
}

$keyValue = '~(?<=\n)        <xenc:CipherValue>([^<]*)</xenc:CipherValue>~';
$dataValue = '~(?<=\n)    <xenc:CipherValue>([^<]*)</xenc:CipherValue>~';
$content = '<xenc:EncryptionMethod Algorithm="' . XMLENC11 . 'aes256-gcm"/>';

// the session key and the plaintext of the vector, to re-encrypt under other keys
preg_match($keyValue, $vector, $match);
$wrapped = base64_decode((string) preg_replace('~\s+~', '', $match[1]), true);
preg_match($dataValue, $vector, $match);
$data = base64_decode((string) preg_replace('~\s+~', '', $match[1]), true);
if ($wrapped === false || $data === false) {
    exit(1);
}
$sessionKey = null;
if (! openssl_private_decrypt($wrapped, $sessionKey, $private, OPENSSL_PKCS1_OAEP_PADDING)) {
    exit(1);
}
$plaintext = openssl_decrypt(
    substr($data, IV_BYTES, -TAG_BYTES),
    'aes-256-gcm',
    (string) $sessionKey,
    OPENSSL_RAW_DATA,
    substr($data, 0, IV_BYTES),
    substr($data, -TAG_BYTES),
);
if (! is_string($plaintext)) {
    exit(1);
}

/** A session key of $bytes derived from the fixture's name. */
$keyFor = static fn (string $name, int $bytes): string => substr(hash('sha256', 'key:' . $name, true), 0, $bytes);

/** The IV, the ciphertext and the tag of $plaintext under $key, the IV derived from the fixture's name. */
$encrypt = static function (string $name, string $plaintext, string $key, string $cipher): string {
    $iv = substr(hash('sha256', 'iv:' . $name, true), 0, IV_BYTES);
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, '', TAG_BYTES);
    if (! is_string($ciphertext)) {
        exit(1);
    }

    return $iv . $ciphertext . $tag;
};

/** The session key wrapped to the test certificate under $padding. */
$wrap = static function (string $key, int $padding) use ($public): string {
    $wrapped = null;
    if (! openssl_public_encrypt($key, $wrapped, $public, $padding)) {
        exit(1);
    }

    return (string) $wrapped;
};

/** A byte of $bytes flipped at $offset. */
$flip = static fn (string $bytes, int $offset): string => substr_replace($bytes, chr(ord($bytes[$offset]) ^ 0x01), $offset, 1);

$base64 = static fn (string $bytes): string => rtrim(chunk_split(base64_encode($bytes), 76, "\n"), "\n");

// [the wrapped key or null to keep the vector's, the data cipher value or null to keep the vector's, the content method]
$cases = [
    'key-wrapped-under-pkcs1-v1-5-refused' => [
        $wrap($keyFor('pkcs1', 32), OPENSSL_PKCS1_PADDING),
        $encrypt('pkcs1', $plaintext, $keyFor('pkcs1', 32), 'aes-256-gcm'),
        $content,
    ],
    'wrapped-key-altered-refused' => [$flip($wrapped, strlen($wrapped) - 1), null, $content],
    'session-key-32-bytes-declared-aes128-gcm-refused' => [
        $wrap($keyFor('32', 32), OPENSSL_PKCS1_OAEP_PADDING),
        $encrypt('32', $plaintext, $keyFor('32', 32), 'aes-256-gcm'),
        '<xenc:EncryptionMethod Algorithm="' . XMLENC11 . 'aes128-gcm"/>',
    ],
    'session-key-16-bytes-declared-aes256-gcm-refused' => [
        $wrap($keyFor('16', 16), OPENSSL_PKCS1_OAEP_PADDING),
        $encrypt('16', $plaintext, $keyFor('16', 16), 'aes-128-gcm'),
        $content,
    ],
    'tag-truncated-refused' => [null, substr($data, 0, -1), $content],
    'tag-altered-refused' => [null, $flip($data, strlen($data) - 1), $content],
    'ciphertext-altered-refused' => [null, $flip($data, IV_BYTES), $content],
    'iv-altered-refused' => [null, $flip($data, 0), $content],
    'plaintext-with-doctype-refused' => [
        $wrap($keyFor('doctype', 32), OPENSSL_PKCS1_OAEP_PADDING),
        $encrypt('doctype', '<!DOCTYPE saml:Assertion>' . $plaintext, $keyFor('doctype', 32), 'aes-256-gcm'),
        $content,
    ],
    'plaintext-with-two-roots-refused' => [
        $wrap($keyFor('roots', 32), OPENSSL_PKCS1_OAEP_PADDING),
        $encrypt(
            'roots',
            $plaintext . '<saml:Extra xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>',
            $keyFor('roots', 32),
            'aes-256-gcm',
        ),
        $content,
    ],
    'plaintext-not-xml-refused' => [
        $wrap($keyFor('text', 32), OPENSSL_PKCS1_OAEP_PADDING),
        $encrypt('text', 'not xml at all', $keyFor('text', 32), 'aes-256-gcm'),
        $content,
    ],
];

foreach ($cases as $name => [$key, $value, $method]) {
    $derived = $vector;
    if ($key !== null) {
        $derived = (string) preg_replace($keyValue, '        <xenc:CipherValue>' . $base64($key) . '</xenc:CipherValue>', $derived);
    }
    if ($value !== null) {
        $derived = (string) preg_replace($dataValue, '    <xenc:CipherValue>' . $base64($value) . '</xenc:CipherValue>', $derived);
    }
    if (substr_count($derived, $content) !== 1) {
        exit(1);
    }
    file_put_contents(__DIR__ . '/' . $name . '.xml', str_replace($content, $method, $derived));
}
printf("%d fixtures derived\n", count($cases));
