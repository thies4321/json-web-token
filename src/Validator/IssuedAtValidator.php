<?php

declare(strict_types=1);

namespace JsonWebToken\Validator;

final class IssuedAtValidator implements Validator
{
    private readonly int $issuedAt;

    public function __construct(int $issuedAt)
    {
        $this->issuedAt = $issuedAt;
    }

    public function validate(bool|int|string $value): bool
    {
        if ($this->issuedAt !== $value) {
            return false;
        }

        return true;
    }
}