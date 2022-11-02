<?php

declare(strict_types=1);

namespace JsonWebToken\Validator;

interface Validator
{
    public function validate(int|string|bool $value): bool;
}
