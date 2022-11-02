<?php

declare(strict_types=1);

namespace JsonWebToken\Exception;

use Exception;

use function sprintf;

final class ValidatorNotFound extends Exception
{
    public static function forClaim(string $claimName): self
    {
        return new self(sprintf('No supported validator found for claim name [%s]', $claimName));
    }
}
