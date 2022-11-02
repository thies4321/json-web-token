<?php

declare(strict_types=1);

namespace JsonWebToken\Validator;

final class AudienceClaimValidator implements Validator
{
    private readonly string $audience;

    public function __construct(string $audience)
    {
        $this->audience = $audience;
    }

    public function validate(int|string|bool $value): bool
    {
        return $value === $this->audience;
    }
}
