<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\PhpStan;

use function implode;
use PhpParser\Node;
use PhpParser\Node\Expr\CallLike;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Class_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use function sprintf;
use function str_starts_with;
use function strtolower;

/**
 * Section 8 of the specifications: the methods of the Dom API and the functions of OpenSSL never called, and the
 * calls allowed in one file each (createFromString() in Loader, createEmpty() in DocumentFactory, C14N() in
 * Canonicalizer, saveXml() in Serializer for Core, I-4, I-13, I-15; openssl_verify() in Verifier, openssl_sign() in
 * PrivateKey and the two key loaders for Dsig, D-15). A dynamic call or a dynamic instantiation would escape the
 * rule, so both are refused too. ekino/phpstan-banned-code bans a function everywhere or nowhere; this rule confines
 * one to named files.
 *
 * @implements Rule<CallLike>
 */
final class BannedCallsRule implements Rule
{
    /**
     * @var array<string, array{spelling: string, allowedIn: list<string>}> keyed by the lowercased method name
     */
    private array $calls = [];

    /**
     * @var array<string, array{spelling: string, allowedIn: list<string>}> keyed by the lowercased function name
     */
    private array $functions = [];

    /**
     * @param list<array{method?: string, function?: string, allowedIn: list<string>}> $calls one of method or function each
     */
    public function __construct(
        array $calls,
        private readonly string $workingDirectory,
    ) {
        foreach ($calls as $call) {
            if (isset($call['function'])) {
                $this->functions[strtolower($call['function'])] = [
                    'spelling' => $call['function'],
                    'allowedIn' => $call['allowedIn'],
                ];
                continue;
            }
            if (isset($call['method'])) {
                $this->calls[strtolower($call['method'])] = [
                    'spelling' => $call['method'],
                    'allowedIn' => $call['allowedIn'],
                ];
            }
        }
    }

    public function getNodeType(): string
    {
        return CallLike::class;
    }

    /**
     * @return list<IdentifierRuleError>
     */
    public function processNode(Node $node, Scope $scope): array
    {
        if ($node instanceof New_) {
            return (
                $node->class instanceof Name || $node->class instanceof Class_
                    ? []
                    : [$this->error('A dynamic instantiation escapes the review: name the class.')]
            );
        }
        if ($node instanceof FuncCall) {
            if (! $node->name instanceof Name) {
                return [$this->error('A dynamic call escapes the review: name the function.')];
            }

            return $this->confined($this->functions[$node->name->toLowerString()] ?? null, $scope);
        }
        if (! $node instanceof MethodCall && ! $node instanceof NullsafeMethodCall && ! $node instanceof StaticCall) {
            return [];
        }
        if (! $node->name instanceof Identifier) {
            return [$this->error('A dynamic call escapes the review: name the method.')];
        }

        return $this->confined($this->calls[$node->name->toLowerString()] ?? null, $scope);
    }

    /**
     * @param ?array{spelling: string, allowedIn: list<string>} $call
     *
     * @return list<IdentifierRuleError>
     */
    private function confined(?array $call, Scope $scope): array
    {
        if ($call === null) {
            return [];
        }
        foreach ($call['allowedIn'] as $path) {
            if (str_starts_with($scope->getFile(), $this->workingDirectory . '/' . $path)) {
                return [];
            }
        }

        return [
            $this->error(
                $call['allowedIn'] === []
                    ? sprintf('%s() is never called: section 8 of the specification bans it.', $call['spelling'])
                    : sprintf(
                        '%s() is called in %s only: section 8 of the specification confines it there.',
                        $call['spelling'],
                        implode(', ', $call['allowedIn']),
                    ),
            ),
        ];
    }

    private function error(string $message): IdentifierRuleError
    {
        return RuleErrorBuilder::message($message)->identifier('beffroi.bannedCall')->nonIgnorable()->build();
    }
}
