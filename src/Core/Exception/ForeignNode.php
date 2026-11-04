<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

use LogicException;

/**
 * A node of a document the brick did not load or create (I-4): a programming error of the caller.
 */
final class ForeignNode extends LogicException
{
}
