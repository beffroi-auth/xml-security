<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Beffroi\Xml\Core\Exception\UnknownCanonicalizationMethod;

/**
 * The four methods Canonical XML 1.0 and Exclusive XML Canonicalization 1.0 define and PHP's C14N() can express: an
 * exclusive flag and a comments flag (section 5.4). Canonical XML 1.1 is not reachable from PHP and is refused
 * like any unknown URI.
 */
enum CanonicalizationMethod: string
{
    case Inclusive = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    case InclusiveWithComments = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    case Exclusive = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    case ExclusiveWithComments = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    /**
     * @throws UnknownCanonicalizationMethod
     */
    public static function fromUri(string $uri): self
    {
        return (
            self::tryFrom($uri) ?? throw new UnknownCanonicalizationMethod('The canonicalization method is not one of the four the brick renders (section 5.4).')
        );
    }

    public function isExclusive(): bool
    {
        return $this === self::Exclusive || $this === self::ExclusiveWithComments;
    }

    public function withComments(): bool
    {
        return $this === self::InclusiveWithComments || $this === self::ExclusiveWithComments;
    }
}
