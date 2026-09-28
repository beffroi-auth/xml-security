<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Exception;

/**
 * No trusted key verifies SignedInfo (D-7, D-8).
 */
final class SignatureMismatch extends SignatureRefused
{
}
