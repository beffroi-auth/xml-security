<?php

declare(strict_types=1);

/*
 * The tasks live in .castor/, imported whole (Castor loads every PHP file of the directory); they share the
 * global namespace, so a task keeps the name of its function. One file, qa.php: what checks the brick and what
 * the CI runs.
 */

use function Castor\guard_min_version;
use function Castor\import;

guard_min_version('v0.23.0');
// the working directory stays the one castor was started from, which every task reads with getcwd()
defined('CASTOR_USE_CHDIR') || define('CASTOR_USE_CHDIR', false);

import(__DIR__ . '/.castor');
