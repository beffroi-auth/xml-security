<?php

declare(strict_types=1);

/*
 * The adversarial pass of spec/enc.md section 9.7: each row of section 3 attacked with inputs the corpus of 9.2 does
 * not list, every attempt a fixture whatever its outcome, refused (adversarial-*-refused.xml, here) or decrypted
 * (../behaviour/adversarial-*-decrypts.xml). Each is the vector ../vectors/response-encrypted-assertion-aes256-gcm.xml
 * altered, or its plaintext re-encrypted under the test keys of ../keys/, with the one change its name says. Run
 * from this directory: php derive-adversarial.php.
 */

const XMLENC = 'http://www.w3.org/2001/04/xmlenc#';
const XMLENC11 = 'http://www.w3.org/2009/xmlenc11#';
const DSIG = 'http://www.w3.org/2000/09/xmldsig#';
const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
const IV_BYTES = 12;
const TAG_BYTES = 16;

$vector = file_get_contents(__DIR__ . '/../vectors/response-encrypted-assertion-aes256-gcm.xml');
$private = openssl_pkey_get_private((string) file_get_contents(__DIR__ . '/../keys/test-signing-key.pem'));
$public = openssl_pkey_get_public((string) file_get_contents(__DIR__ . '/../keys/test-signing-certificate.pem'));
if ($vector === false || $private === false || $public === false) {
    exit(1);
}
$details = openssl_pkey_get_details($public);
$modulus = is_array($details) ? (string) $details['rsa']['n'] : '';

$keyValue = '~(?<=\n)        <xenc:CipherValue>([^<]*)</xenc:CipherValue>~';
$dataValue = '~(?<=\n)    <xenc:CipherValue>([^<]*)</xenc:CipherValue>~';
preg_match($keyValue, $vector, $match);
$wrapped = base64_decode((string) preg_replace('~\s+~', '', $match[1]), true);
preg_match($dataValue, $vector, $match);
$dataText = $match[1];
$data = base64_decode((string) preg_replace('~\s+~', '', $dataText), true);
if ($wrapped === false || $data === false || strlen($modulus) !== 256) {
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

$base64 = static fn (string $bytes): string => rtrim(chunk_split(base64_encode($bytes), 76, "\n"), "\n");

/** The vector with $old replaced by $new, $old found exactly once. */
$replace = static function (string $old, string $new, ?string $subject = null) use ($vector): string {
    $subject ??= $vector;
    if (substr_count($subject, $old) !== 1) {
        fwrite(STDERR, sprintf("not found once: %s\n", substr($old, 0, 60)));
        exit(1);
    }

    return str_replace($old, $new, $subject);
};
$withDataText = static fn (string $text): string => (string) preg_replace($dataValue, '    <xenc:CipherValue>' . $text . '</xenc:CipherValue>', $vector);
$withDataBytes = static fn (string $bytes) => $withDataText($base64($bytes));
$withKeyBytes = static fn (string $bytes): string => (string) preg_replace($keyValue, '        <xenc:CipherValue>' . $base64($bytes) . '</xenc:CipherValue>', $vector);
$contentMethod = static fn (string $algorithm): string => '<xenc:EncryptionMethod Algorithm="' . $algorithm . '"/>';

$content = $contentMethod(XMLENC11 . 'aes256-gcm');
$key = $contentMethod(XMLENC . 'rsa-oaep-mgf1p');
$type = ' Type="' . XMLENC . 'Element"';
$start = '<xenc:EncryptedData xmlns:xenc="' . XMLENC . '"';
if (strtr($dataText, '+/', '-_') === $dataText) {
    fwrite(STDERR, "the data value holds no + and no /\n");
    exit(1);
}

// the SAML sibling form of section 12: the EncryptedKey next to the EncryptedData, named by a RetrievalMethod
preg_match('~    <xenc:EncryptedKey>.*?</xenc:EncryptedKey>\n~s', $vector, $match);
$block = $match[0];
$sibling = str_replace(
    '<xenc:EncryptedKey>',
    '<xenc:EncryptedKey xmlns:xenc="' . XMLENC . '" xmlns:ds="' . DSIG . '" Id="_encrypted-key">',
    $block,
);
$siblingForm = $replace(
    '</xenc:EncryptedData>',
    "</xenc:EncryptedData>\n" . $sibling,
    $replace($block, '    <ds:RetrievalMethod URI="#_encrypted-key" Type="' . XMLENC . 'EncryptedKey"/>' . "\n"),
);

// an assertion holding the vector's EncryptedData, encrypted again under a fresh key (section 9.7)
preg_match('~<xenc:EncryptedData .*?</xenc:EncryptedData>~s', $vector, $match);
$nestedPlaintext = $replace(
    '</saml:Assertion>',
    '<saml:Advice><saml:EncryptedAssertion>' . $match[0] . '</saml:EncryptedAssertion></saml:Advice></saml:Assertion>',
    $plaintext,
);
$nestedKey = substr(hash('sha256', 'key:nested', true), 0, 32);
$nestedIv = substr(hash('sha256', 'iv:nested', true), 0, IV_BYTES);
$nestedTag = '';
$nestedCiphertext = openssl_encrypt($nestedPlaintext, 'aes-256-gcm', $nestedKey, OPENSSL_RAW_DATA, $nestedIv, $nestedTag, '', TAG_BYTES);
$nestedWrapped = null;
if (! is_string($nestedCiphertext) || ! openssl_public_encrypt($nestedKey, $nestedWrapped, $public, OPENSSL_PKCS1_OAEP_PADDING)) {
    exit(1);
}
$nested = (string) preg_replace(
    $keyValue,
    '        <xenc:CipherValue>' . $base64((string) $nestedWrapped) . '</xenc:CipherValue>',
    $withDataBytes($nestedIv . $nestedCiphertext . $nestedTag),
);

$refused = [
    'content-algorithm-upper-case' => $replace($content, $contentMethod(XMLENC11 . 'AES256-GCM')),
    'content-algorithm-trailing-slash' => $replace($content, $contentMethod(XMLENC11 . 'aes256-gcm/')),
    'content-algorithm-slash-for-fragment' => $replace($content, $contentMethod('http://www.w3.org/2009/xmlenc11/aes256-gcm')),
    'content-algorithm-surrounded-by-spaces' => $replace($content, $contentMethod(' ' . XMLENC11 . 'aes256-gcm ')),
    'key-transport-upper-case' => $replace($key, $contentMethod(XMLENC . 'RSA-OAEP-MGF1P')),
    'key-transport-in-the-1-1-namespace' => $replace($key, $contentMethod(XMLENC11 . 'rsa-oaep-mgf1p')),
    'type-in-another-case' => $replace($type, ' Type="' . XMLENC . 'element"'),
    'type-with-a-trailing-space' => $replace($type, ' Type="' . XMLENC . 'Element "'),
    'cipher-value-padding-inside' => $withDataText(substr_replace($dataText, '=', 10, 0)),
    'cipher-value-url-safe-alphabet' => $withDataText(strtr($dataText, '+/', '-_')),
    'cipher-value-extra-padding' => $withDataText($dataText . '='),
    'encrypted-key-as-a-sibling' => $siblingForm,
    'cipher-value-shortened-by-two' => $withDataBytes(substr($data, 0, -2)),
    'cipher-value-lengthened-by-one' => $withDataBytes($data . "\0"),
    'cipher-value-lengthened-by-sixteen' => $withDataBytes($data . str_repeat("\0", 16)),
    'wrapped-key-of-zeros' => $withKeyBytes(str_repeat("\0", 256)),
    'wrapped-key-of-ones' => $withKeyBytes(str_repeat("\xff", 256)),
    'wrapped-key-equal-to-the-modulus' => $withKeyBytes($modulus),
    'encrypted-data-id-equal-to-the-response-id' => $replace($start, $start . ' Id="_response-a1b2c3"'),
    'encrypted-data-in-almost-the-namespace' => $replace('xmlns:xenc="' . XMLENC . '"', 'xmlns:xenc="http://www.w3.org/2001/04/xmlenc"'),
    'mgf-in-the-xmlenc-namespace' => $replace($key, '<xenc:EncryptionMethod Algorithm="' . XMLENC11 . 'rsa-oaep"><ds:DigestMethod Algorithm="' . SHA256 . '"/><xenc:MGF Algorithm="' . XMLENC11 . 'mgf1sha256"/></xenc:EncryptionMethod>'),
    'digest-method-in-the-xmlenc-namespace' => $replace($key, '<xenc:EncryptionMethod Algorithm="' . XMLENC11 . 'rsa-oaep"><xenc:DigestMethod Algorithm="' . SHA256 . '"/><xenc11:MGF xmlns:xenc11="' . XMLENC11 . '" Algorithm="' . XMLENC11 . 'mgf1sha256"/></xenc:EncryptionMethod>'),
    'element-inside-cipher-value' => $withDataText(substr_replace($dataText, '<xenc:X/>', 10, 0)),
];
$decrypts = [
    'cipher-value-with-whitespace-inside' => $withDataText(substr_replace(substr_replace($dataText, "\n\t  \n", 30, 0), ' ', 10, 0)),
    'cipher-value-in-cdata' => $withDataText('<![CDATA[' . $dataText . ']]>'),
    'comment-inside-cipher-value' => $withDataText(substr_replace($dataText, '<!-- an attempt -->', 10, 0)),
    'processing-instruction-inside-cipher-value' => $withDataText('<?attempt nothing?>' . $dataText),
    'key-info-with-garbage' => (string) preg_replace('~<ds:X509Data>.*?</ds:X509Data>~s', '<ds:KeyName>anything</ds:KeyName><ds:RetrievalMethod URI="#nowhere"/><xenc:Unknown/>', $vector),
    'encryption-method-with-comment-and-whitespace' => $replace($content, '<xenc:EncryptionMethod Algorithm="' . XMLENC11 . 'aes256-gcm"> <!-- nothing --> </xenc:EncryptionMethod>'),
    'encrypted-data-under-another-prefix' => str_replace(['xmlns:xenc=', 'xenc:'], ['xmlns:e=', 'e:'], $vector),
    'id-attributes-on-encrypted-data-and-key' => $replace('<xenc:EncryptedKey>', '<xenc:EncryptedKey Id="_encrypted-key">', $replace($start, $start . ' Id="_encrypted-data"')),
    'mime-type-and-encoding-attributes' => $replace($start, $start . ' MimeType="text/xml" Encoding="' . DSIG . 'base64"'),
    'xml-space-on-encrypted-data' => $replace($start, $start . ' xml:space="preserve"'),
    'nested-encrypted-data' => $nested,
];
foreach ($refused as $name => $bytes) {
    file_put_contents(__DIR__ . '/adversarial-' . $name . '-refused.xml', $bytes);
}
foreach ($decrypts as $name => $bytes) {
    file_put_contents(__DIR__ . '/../behaviour/adversarial-' . $name . '-decrypts.xml', $bytes);
}
printf("%d refused, %d decrypting fixtures derived\n", count($refused), count($decrypts));
