<?php

declare(strict_types=1);

namespace JsonWebToken\Validator;

final class SubjectClaimValidator implements Validator
{
    private readonly string $subject;

    public function __construct(string $subject)
    {
        $this->subject = $subject;
    }

    public function validate(int|string|bool $value): bool
    {
        return $this->subject === $value;
    }
}
