<?php

declare(strict_types=1);

namespace JsonWebToken\Exception;

use Exception;

final class HeaderNotFoundException extends Exception
{
    public static function forAlgorithm(): self
    {
        return new self('Algorithm header (alg) missing');
    }
}