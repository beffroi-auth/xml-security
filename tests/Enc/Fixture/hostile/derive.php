<?php

declare(strict_types=1);

/*
 * The hostile fixtures the reading model refuses (spec/enc.md section 9.2, rows 1 to 18): each one is the vector
 * ../vectors/response-encrypted-assertion-aes256-gcm.xml with the one change its name says, and nothing else.
 * Run from this directory: php derive.php. The fixtures of the decryptor (rows 19 to 33) are made by hand from the
 * same vector and described in README.md.
 */

$vector = file_get_contents(__DIR__ . '/../vectors/response-encrypted-assertion-aes256-gcm.xml');
if ($vector === false) {
    exit(1);
}

const XMLENC = 'http://www.w3.org/2001/04/xmlenc#';
const XMLENC11 = 'http://www.w3.org/2009/xmlenc11#';
const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

$content = '<xenc:EncryptionMethod Algorithm="' . XMLENC11 . 'aes256-gcm"/>';
$key = '<xenc:EncryptionMethod Algorithm="' . XMLENC . 'rsa-oaep-mgf1p"/>';
$type = ' Type="' . XMLENC . 'Element"';
$contentMethod = static fn (string $algorithm): string => '<xenc:EncryptionMethod Algorithm="' . $algorithm . '"/>';
$mgf1p = static fn (string $children): string => '<xenc:EncryptionMethod Algorithm="' . XMLENC . 'rsa-oaep-mgf1p">' . $children . '</xenc:EncryptionMethod>';
$oaep = static fn (string $children): string => '<xenc:EncryptionMethod Algorithm="' . XMLENC11 . 'rsa-oaep">' . $children . '</xenc:EncryptionMethod>';
$digest = static fn (string $hash): string => '<ds:DigestMethod Algorithm="' . $hash . '"/>';
$mgf = static fn (string $hash): string => '<xenc11:MGF xmlns:xenc11="' . XMLENC11 . '" Algorithm="' . XMLENC11 . 'mgf1' . $hash . '"/>';
$dataValue = static fn (string $text): string => '    <xenc:CipherValue>' . $text . '</xenc:CipherValue>';
$keyValue = static fn (string $text): string => '        <xenc:CipherValue>' . $text . '</xenc:CipherValue>';

// [what to replace, its replacement, whether the first is a regular expression]
$cases = [
    'content-aes128-cbc-refused' => [$content, $contentMethod(XMLENC . 'aes128-cbc')],
    'content-aes256-cbc-refused' => [$content, $contentMethod(XMLENC . 'aes256-cbc')],
    'content-tripledes-cbc-refused' => [$content, $contentMethod(XMLENC . 'tripledes-cbc')],
    'content-aes192-gcm-refused' => [$content, $contentMethod(XMLENC11 . 'aes192-gcm')],
    'key-transport-rsa-1-5-refused' => [$key, $contentMethod(XMLENC . 'rsa-1_5')],
    'key-transport-kw-aes256-refused' => [$key, $contentMethod(XMLENC . 'kw-aes256')],
    'rsa-oaep-digest-sha256-mgf-sha1-refused' => [$key, $oaep($digest(SHA256) . $mgf('sha1'))],
    'rsa-oaep-digest-sha256-no-mgf-refused' => [$key, $oaep($digest(SHA256))],
    'mgf1p-digest-sha256-refused' => [$key, $mgf1p($digest(SHA256))],
    'mgf1p-with-mgf-refused' => [$key, $mgf1p($mgf('sha1'))],
    'mgf1p-oaepparams-refused' => [$key, $mgf1p('<xenc:OAEPparams>AAAA</xenc:OAEPparams>')],
    'type-content-refused' => [$type, ' Type="' . XMLENC . 'Content"'],
    'type-absent-refused' => [$type, ''],
    'cipher-reference-refused' => ['~(?<=\n)    <xenc:CipherValue>[^<]*</xenc:CipherValue>~', '    <xenc:CipherReference URI="#cipher"/>', true],
    'encryption-properties-refused' => ['</xenc:EncryptedData>', "  <xenc:EncryptionProperties/>\n</xenc:EncryptedData>"],
    'reference-list-inside-key-refused' => ['    </xenc:EncryptedKey>', "      <xenc:ReferenceList><xenc:DataReference URI=\"#data\"/></xenc:ReferenceList>\n    </xenc:EncryptedKey>"],
    'carried-key-name-refused' => ['    </xenc:EncryptedKey>', "      <xenc:CarriedKeyName>the session key</xenc:CarriedKeyName>\n    </xenc:EncryptedKey>"],
    'two-encrypted-keys-refused' => ['~    <xenc:EncryptedKey>.*?</xenc:EncryptedKey>\n~s', '$0$0', true],
    'no-encrypted-key-refused' => ['~    <xenc:EncryptedKey>.*?</xenc:EncryptedKey>\n~s', '', true],
    'key-info-holding-a-key-name-refused' => ['~    <xenc:EncryptedKey>.*?</xenc:EncryptedKey>\n~s', "    <ds:KeyName>the peer</ds:KeyName>\n", true],
    'key-size-refused' => [$content, '<xenc:EncryptionMethod Algorithm="' . XMLENC11 . 'aes256-gcm"><xenc:KeySize>256</xenc:KeySize></xenc:EncryptionMethod>'],
    'cipher-value-outside-alphabet-refused' => ['~(?<=\n)    <xenc:CipherValue>[^<]~', '    <xenc:CipherValue>!', true],
    'cipher-value-empty-refused' => ['~(?<=\n)    <xenc:CipherValue>[^<]*</xenc:CipherValue>~', $dataValue(''), true],
    'data-cipher-value-28-bytes-refused' => ['~(?<=\n)    <xenc:CipherValue>[^<]*</xenc:CipherValue>~', $dataValue(base64_encode(str_repeat("\0", 28))), true],
    'key-cipher-value-255-bytes-refused' => ['~(?<=\n)        <xenc:CipherValue>[^<]*</xenc:CipherValue>~', $keyValue(base64_encode(str_repeat("\0", 255))), true],
    'key-cipher-value-1025-bytes-refused' => ['~(?<=\n)        <xenc:CipherValue>[^<]*</xenc:CipherValue>~', $keyValue(base64_encode(str_repeat("\0", 1025))), true],
    'content-method-without-algorithm-refused' => [$content, '<xenc:EncryptionMethod/>'],
    'key-method-without-algorithm-refused' => [$key, '<xenc:EncryptionMethod/>'],
    'two-encryption-methods-refused' => [$content, $content . "\n  " . $content],
    'no-key-info-refused' => ['~  <ds:KeyInfo xmlns:ds="[^"]*">.*?\n  </ds:KeyInfo>\n~s', '', true],
    'two-cipher-data-refused' => ['~  <xenc:CipherData>\n    <xenc:CipherValue>[^<]*</xenc:CipherValue>\n  </xenc:CipherData>\n~', '$0$0', true],
    'key-without-cipher-data-refused' => ['~      <xenc:CipherData>\n        <xenc:CipherValue>[^<]*</xenc:CipherValue>\n      </xenc:CipherData>\n~', '', true],
    'two-key-infos-in-the-key-refused' => ['~      <ds:KeyInfo>\n.*?\n      </ds:KeyInfo>\n~s', '$0$0', true],
];

foreach ($cases as $name => [$old, $new]) {
    $regex = ($cases[$name][2] ?? false) === true;
    $count = $regex ? preg_match_all($old, $vector) : substr_count($vector, $old);
    if ($count !== 1) {
        fwrite(STDERR, sprintf("%s: expected one match, found %d\n", $name, $count));
        exit(1);
    }
    $derived = $regex ? preg_replace($old, $new, $vector) : str_replace($old, $new, $vector);
    file_put_contents(__DIR__ . '/' . $name . '.xml', $derived);
}
printf("%d fixtures derived\n", count($cases));
