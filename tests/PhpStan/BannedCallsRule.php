<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\PhpStan;

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

/**
 * Section 8 of the specification: the methods of the Dom API never called, and the calls allowed in one class each
 * (createFromString() in Loader, createEmpty() in DocumentFactory, C14N() in Canonicalizer, saveXml() in Serializer:
 * I-4, I-13, I-15). A dynamic call or a dynamic instantiation would escape the rule, so both are refused too.
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
     * @param list<array{method: string, allowedIn: list<string>}> $calls
     */
    public function __construct(
        array $calls,
        private readonly string $workingDirectory,
    ) {
        foreach ($calls as $call) {
            $this->calls[strtolower($call['method'])] = [
                'spelling' => $call['method'],
                'allowedIn' => $call['allowedIn'],
            ];
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
            return (
                $node->name instanceof Name
                    ? []
                    : [$this->error('A dynamic call escapes the review: name the function.')]
            );
        }
        if (! $node instanceof MethodCall && ! $node instanceof NullsafeMethodCall && ! $node instanceof StaticCall) {
            return [];
        }
        if (! $node->name instanceof Identifier) {
            return [$this->error('A dynamic call escapes the review: name the method.')];
        }

        $call = $this->calls[$node->name->toLowerString()] ?? null;
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
