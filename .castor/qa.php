<?php

declare(strict_types=1);

/*
 * The quality tools, what the CI runs on every push (.github/workflows/ci.yml): each one in the phpqa image
 * when Docker is available, directly when already inside a container (the CI) or without Docker.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\run;

/**
 * The files section 9 of the specification accepts only with no escaped mutant: "castor infect" mutates them
 * whole, uncovered lines included, and fails under a hundred percent. Loader delegates the rules of 6.1 steps 5
 * and 6 to Internal\Inspector, which is why that file is held to the same bar.
 */
const INFECTION_STRICT_FILES = [
    'src/Core/Loader.php',
    'src/Core/Internal/Inspector.php',
    'src/Core/Canonicalizer.php',
    'src/Core/Text.php',
    'src/Core/Children.php',
    'src/Core/CanonicalXml.php',
    'src/Core/Serializer.php',
];

/**
 * Runs a command in the phpqa image, or directly when already inside a container (CI) or without Docker.
 * The environment applies in both cases.
 *
 * @param array<string> $command
 * @param array<string, string> $environment
 */
function phpqa(array $command, array $environment = []): void
{
    $inContainer = file_exists('/.dockerenv');
    $hasDocker = trim(shell_exec('command -v docker') ?? '') !== '';
    $phpVersion = getenv('PHP_VERSION') ?: \PHP_MAJOR_VERSION . '.' . \PHP_MINOR_VERSION;
    $environment += [
        'XDEBUG_MODE' => 'off',
        'COMPOSER_PROCESS_TIMEOUT' => '0',
    ];

    if (! $hasDocker || $inContainer) {
        run($command, context: context()->withEnvironment($environment));
        return;
    }

    if (! is_dir(getcwd() . '/tmp-phpqa')) {
        mkdir(getcwd() . '/tmp-phpqa');
    }

    $dockerOptions = [
        '--rm',
        '--init',
        stream_isatty(\STDOUT) ? '-it' : '-i',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-v',
        getcwd() . ':/project',
        '-v',
        getcwd() . '/tmp-phpqa:/project/tmp-phpqa',
        '-w',
        '/project',
        '-e',
        'PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d',
        '-e',
        'PHP_INI_ENTRY=sys_temp_dir=/project/tmp-phpqa',
        // The checkout belongs to the host user, the container runs as that uid without a name: git would refuse
        // the "dubious ownership", and Infection's --git-diff-lines needs git to work.
        '-e',
        'GIT_CONFIG_COUNT=1',
        '-e',
        'GIT_CONFIG_KEY_0=safe.directory',
        '-e',
        'GIT_CONFIG_VALUE_0=/project',
    ];
    foreach ($environment as $name => $value) {
        $dockerOptions[] = '-e';
        $dockerOptions[] = $name . '=' . $value;
    }

    run([
        'docker',
        'run',
        ...$dockerOptions,
        sprintf('ghcr.io/spomky-labs/phpqa:%s', $phpVersion),
        ...$command,
    ]);
}

#[AsTask(description: 'Update the PHPQA Docker image')]
function phpqa_update(): void
{
    $phpVersion = getenv('PHP_VERSION') ?: \PHP_MAJOR_VERSION . '.' . \PHP_MINOR_VERSION;

    run(['docker', 'pull', 'ghcr.io/spomky-labs/phpqa:' . $phpVersion]);
}

#[AsTask(
    description: 'Print the PHP and libxml versions and whether LIBXML_NO_XXE is defined: what the corpus can and cannot exercise on this build (specification, section 12)',
)]
function libxml(): void
{
    phpqa([
        'php',
        '-r',
        'printf("PHP %s, libxml %s, LIBXML_NO_XXE %s\n", PHP_VERSION, LIBXML_DOTTED_VERSION, defined("LIBXML_NO_XXE") ? "defined" : "undefined");',
    ]);
}

#[AsTask(description: 'Run PHPUnit tests with coverage', ignoreValidationErrors: true)]
function phpunit(#[AsRawTokens] array $args = []): void
{
    phpqa(
        [
            'composer',
            'exec',
            '--',
            'phpunit',
            '--coverage-xml',
            '.ci-tools/coverage',
            '--log-junit=.ci-tools/coverage/junit.xml',
            '--configuration',
            '.ci-tools/phpunit.xml.dist',
            '--display-warnings',
            '--display-deprecations',
            ...$args,
        ],
        [
            'XDEBUG_MODE' => 'coverage',
        ],
    );
}

/*
 * Mago (https://mago.carthage.software/), the toolchain of Carthage Software: one Rust binary, already installed
 * in the phpqa image (/tools/mago), configured by mago.toml at the root of the repository. It holds the formatter
 * and the linter. Its analyzer is not PHPStan's equal and replaces nothing.
 */

#[AsTask(description: 'Check the formatting with Mago')]
function mago_format(): void
{
    phpqa(['mago', 'format', '--check']);
}

#[AsTask(description: 'Format the code with Mago')]
function mago_format_fix(): void
{
    phpqa(['mago', 'format']);
}

#[AsTask(description: 'Run the Mago linter')]
function mago_lint(): void
{
    phpqa(['mago', 'lint']);
}

#[AsTask(description: 'Apply the fixes the Mago linter offers')]
function mago_lint_fix(): void
{
    phpqa(['mago', 'lint', '--fix']);
}

#[AsTask(description: 'Run Rector dry-run')]
function rector(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--dry-run', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run Rector with fix')]
function rector_fix(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run PHPStan at level max, with no baseline')]
function phpstan(): void
{
    phpqa([
        'composer',
        'exec',
        '--',
        'phpstan',
        'analyse',
        '--error-format=github',
        '--configuration=.ci-tools/phpstan.neon',
    ]);
}

#[AsTask(
    description: 'Run Deptrac between the namespaces: Dsig and Enc depend on Core, never the reverse, never on each other (decision 0014)',
)]
function deptrac(): void
{
    phpqa([
        'deptrac',
        'analyse',
        '--config-file=.ci-tools/deptrac.yaml',
        '--cache-file=tmp-phpqa/.deptrac.cache',
        '--no-progress',
    ]);
}

#[AsTask(description: 'Run PHP parallel linter')]
function lint(): void
{
    phpqa(['composer', 'exec', '--', 'parallel-lint', 'src', 'tests']);
}

#[AsTask(description: 'Validate composer.json strictly and check the PSR-4 layout')]
function composer_validate(): void
{
    phpqa(['composer', 'validate', '--strict']);
    phpqa(['composer', 'dump-autoload', '--optimize', '--strict-psr']);
}

#[AsTask(
    description: 'Run Infection on the coverage of a fresh PHPUnit run. By default the files of section 9 are mutated whole and no escaped mutant is allowed; --diff mutates the lines added or modified since --base over the whole source, the shape of every CI run on the rest; --all mutates the whole source with no minimum',
)]
function infect(
    #[AsOption(
        description: 'Mutate only the lines added or modified since --base, committed or not, over the whole source',
    )]
    bool $diff = false,
    #[AsOption(description: 'Mutate the whole source, informative only')]
    bool $all = false,
    #[AsOption(
        description: 'The branch or commit the diff of --diff is taken from; Infection narrows it to the merge base with HEAD',
    )]
    string $base = 'origin/main',
    #[AsOption(
        description: 'Mutate these files only, comma-separated, with no escaped mutant allowed: the strict run narrowed while the tree is being built',
    )]
    string $files = '',
    #[AsOption(description: 'Mutant processes run in parallel; "max" is the number of cores minus one')]
    string $threads = 'max',
    #[AsOption(
        description: 'Reuse the coverage of the last "castor phpunit" in .ci-tools/coverage instead of running the tests again; it must come from the same source and the same paths',
    )]
    bool $reuseCoverage = false,
): void {
    // The XML coverage and the JUnit report of a "castor phpunit" run are what Infection reads from .ci-tools/coverage.
    if ($reuseCoverage && (! is_file('.ci-tools/coverage/index.xml') || ! is_file('.ci-tools/coverage/junit.xml'))) {
        io()->error('No coverage to reuse in .ci-tools/coverage: run "castor phpunit" first, or drop --reuse-coverage.');
        exit(1);
    }
    $scope = infection_scope($diff, $all, $base, $files);
    if ($scope === null) {
        io()->warning('None of the files of section 9 exists yet: nothing to mutate.');
        return;
    }
    if (! $reuseCoverage) {
        phpunit();
    }

    $options = [
        '--coverage=.ci-tools/coverage',
        '--skip-initial-tests',
        '--threads=' . $threads,
        '--logger-github',
        '--show-mutations=max',
        // Each mutant runs only the test cases that cover its line (PHPUnit --filter), not the whole test files.
        '--only-covering-test-cases',
        ...$scope,
    ];

    phpqa(['composer', 'exec', '--', 'infection', ...$options], [
        'XDEBUG_MODE' => 'coverage',
    ]);
}

/**
 * The options selecting what Infection mutates and the minimum it must reach; null while the tree holds none of the
 * files of section 9. A listed file that is missing once the tree is no longer empty is an error, never a silent skip.
 *
 * @return ?list<string>
 */
function infection_scope(bool $diff, bool $all, string $base, string $files): ?array
{
    if ($files !== '') {
        return ['--filter=' . $files, '--with-uncovered', '--min-msi=100', '--min-covered-msi=100'];
    }
    if ($diff) {
        // Infection runs "git diff <merge base> -- <source directories>" from the working directory and passes the
        // directories of infection.json.dist as they are written: this is why that file sits at the root of the
        // repository, not in .ci-tools with the other configurations. A diff that touches no source file is a success.
        return ['--git-diff-lines', '--git-diff-base=' . $base, '--min-msi=0', '--min-covered-msi=0'];
    }
    if ($all) {
        return ['--min-msi=0', '--min-covered-msi=0'];
    }
    $files = array_values(array_filter(INFECTION_STRICT_FILES, is_file(...)));
    if ($files === []) {
        return null;
    }
    if ($files !== INFECTION_STRICT_FILES) {
        io()->error(sprintf('Missing from the tree: %s.', implode(', ', array_diff(INFECTION_STRICT_FILES, $files))));
        exit(1);
    }

    return ['--filter=' . implode(',', $files), '--with-uncovered', '--min-msi=100', '--min-covered-msi=100'];
}

#[AsTask(description: 'Fix code style and apply Rector rules, then run static analysis')]
function prepare_pr(): void
{
    io()->title('Preparing code for pull request…');

    // The formatter runs last: Rector and the linter rewrite statements, the formatter lays them out.
    mago_lint_fix();
    rector_fix();
    mago_format_fix();

    io()->section('Running static analysis…');
    phpstan();
    deptrac();
    lint();
    composer_validate();

    io()->success('Code is ready. You may now commit your changes.');
}
