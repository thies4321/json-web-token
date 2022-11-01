<?php

declare(strict_types=1);

namespace JsonWebToken\Validator;

final class IssuerClaimValidator implements Validator
{
    private readonly string $issuer;

    public function __construct(string $issuer)
    {
        $this->issuer = $issuer;
    }

    public function validate(int|string|bool $value): bool
    {
        if ($this->issuer !== $value) {
            return false;
        }

        return true;
    }
}