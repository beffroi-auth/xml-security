<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\PhpStan;

use function array_map;
use function ltrim;
use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\GroupUse;
use PhpParser\Node\Stmt\Use_;
use PhpParser\Node\UseItem;
use PhpParser\NodeFinder;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use function sprintf;
use function strtolower;

/**
 * Section 8 of the specification: the classes and the constants never used, in the brick and in its consumers.
 * ekino/phpstan-banned-code bans function names and whole node types; this rule reads every name written inside
 * a class, an enum, an interface or a trait, and every name a use statement imports.
 *
 * @implements Rule<Node>
 */
final class BannedNamesRule implements Rule
{
    /**
     * @var array<string, string> the banned names, lowercased, mapped to the spelling of the configuration
     */
    private array $names = [];

    /**
     * @param list<string> $names
     */
    public function __construct(array $names)
    {
        foreach ($names as $name) {
            $this->names[strtolower(ltrim($name, '\\'))] = $name;
        }
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    /**
     * @return list<IdentifierRuleError>
     */
    public function processNode(Node $node, Scope $scope): array
    {
        $names = match (true) {
            $node instanceof ClassLike => new NodeFinder()->findInstanceOf($node, Name::class),
            $node instanceof Use_ => array_map(static fn (UseItem $use): Name => $use->name, $node->uses),
            $node instanceof GroupUse => array_map(
                static fn (UseItem $use): Name => Name::concat($node->prefix, $use->name) ?? $use->name,
                $node->uses,
            ),
            default => [],
        };

        $errors = [];
        foreach ($names as $name) {
            $banned = $this->bannedSpelling($name);
            if ($banned === null) {
                continue;
            }
            $errors[] = RuleErrorBuilder::message(sprintf(
                '%s is never used: section 8 of the specification bans it.',
                $banned,
            ))
                ->identifier('beffroi.bannedName')
                ->line($name->getStartLine())
                ->nonIgnorable()
                ->build();
        }

        return $errors;
    }

    private function bannedSpelling(Name $name): ?string
    {
        $candidates = [$name->toLowerString()];
        foreach (['resolvedName', 'namespacedName'] as $attribute) {
            $resolved = $name->getAttribute($attribute);
            if ($resolved instanceof Name) {
                $candidates[] = $resolved->toLowerString();
            }
        }
        foreach ($candidates as $candidate) {
            $spelling = $this->names[$candidate] ?? null;
            if ($spelling !== null) {
                return $spelling;
            }
        }

        return null;
    }
}
