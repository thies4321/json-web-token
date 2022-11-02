<?php

declare(strict_types=1);

namespace JsonWebToken\Exception;

use Exception;

use function sprintf;

final class ValidationFailedException extends Exception
{
    public static function forClaim(string $claimName): self
    {
        return new self(sprintf('Validation for claim [%s] failed', $claimName));
    }
}
