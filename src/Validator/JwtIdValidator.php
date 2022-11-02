<?php

declare(strict_types=1);

namespace JsonWebToken\Validator;

final class JwtIdValidator implements Validator
{
    private readonly string $jwtId;

    public function __construct(string $jwtId)
    {
        $this->jwtId = $jwtId;
    }

    public function validate(bool|int|string $value): bool
    {
        if ($this->jwtId !== $value) {
            return false;
        }

        return true;
    }
}
