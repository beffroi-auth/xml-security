<?php
declare(strict_types=1);
require '/app/vendor/autoload.php';
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Assertion;
use SAML2\Compat\ContainerSingleton;
use SAML2\Compat\MockContainer;
use SAML2\Constants;
use SAML2\EncryptedAssertion;
use SAML2\Response;
use SAML2\XML\saml\Issuer;
use SAML2\XML\saml\NameID;
ContainerSingleton::setContainer(new MockContainer());
$cert = file_get_contents('/fixtures/keys/test-signing-certificate.pem');
function peer(string $cert): XMLSecurityKey { $k = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, ['type' => 'public']); $k->loadKey($cert, false, true); return $k; }
// 1. xmlseclibs, the library under saml2, called directly: the assertion of the plain data file under AES-GCM, the session key under RSA-OAEP (SHA-1)
foreach (['aes256-gcm' => XMLSecurityKey::AES256_GCM, 'aes128-gcm' => XMLSecurityKey::AES128_GCM] as $name => $type) {
    $dom = new DOMDocument(); $dom->loadXML(file_get_contents('/fixtures/vectors/response-assertion.data.xml'));
    $assertion = $dom->getElementsByTagNameNS(Constants::NS_SAML, 'Assertion')->item(0);
    $session = new XMLSecurityKey($type); $session->generateSessionKey();
    $enc = new XMLSecEnc(); $enc->setNode($assertion); $enc->type = XMLSecEnc::Element;
    $enc->encryptKey(peer($cert), $session);
    $enc->encryptNode($session);
    file_put_contents("/out/simplesamlphp-xmlseclibs-3.1.5-response-encrypted-$name-2026-09-27.xml", $dom->saveXML());
    printf("xmlseclibs %s: %s\n", $name, preg_match('~Algorithm="([^"]*gcm)"~', $dom->saveXML(), $m) ? $m[1] : 'no gcm method');
}
// 2. saml2's own EncryptedAssertion::setAssertion() with the peer's RSA key: what a SimpleSAMLphp IdP does
$issuer = new Issuer(); $issuer->setValue('https://idp.example.org');
$assertion = new Assertion();
$assertion->setId('_ssp-assertion-p1q2r3'); $assertion->setIssueInstant(1790503200); $assertion->setIssuer($issuer);
$nameId = new NameID(); $nameId->setValue('user-0001'); $nameId->setFormat(Constants::NAMEID_PERSISTENT); $assertion->setNameId($nameId);
$assertion->setNotBefore(1790503140); $assertion->setNotOnOrAfter(1790503500); $assertion->setValidAudiences(['https://sp.example.org']);
$assertion->setAuthnInstant(1790503080); $assertion->setAuthnContextClassRef(Constants::AC_PASSWORD_PROTECTED_TRANSPORT);
$assertion->setAttributes(['mail' => ['user@example.org']]);
$encrypted = new EncryptedAssertion(); $encrypted->setAssertion($assertion, peer($cert));
$response = new Response(); $response->setId('_ssp-response-s4t5u6'); $response->setIssueInstant(1790503200); $response->setIssuer($issuer);
$response->setDestination('https://sp.example.org/acs'); $response->setAssertions([$encrypted]);
$xml = $response->toUnsignedXML()->ownerDocument->saveXML();
file_put_contents('/out/simplesamlphp-saml2-4.20.3-response-encrypted-assertion-default-2026-09-27.xml', $xml);
preg_match_all('~EncryptionMethod Algorithm="([^"]*)"~', $xml, $m);
printf("saml2 setAssertion() with an RSA key: %s\n", implode(', ', $m[1]));
echo "encrypted by simplesamlphp/saml2 ", \Composer\InstalledVersions::getVersion('simplesamlphp/saml2'), " with xmlseclibs ", \Composer\InstalledVersions::getVersion('robrichards/xmlseclibs'), "\n";
