<?php

declare(strict_types=1);

namespace JsonWebToken\Exception;

use Exception;

use function sprintf;

final class AlgorithmNotSupported extends Exception
{
    public static function forEncoder(string $value): self
    {
        return new self(sprintf('Algorithm [%s] has not a supported Encoder', $value));
    }

    public static function forDecoder(string $value): self
    {
        return new self(sprintf('Algorithm [%s] has not a supported Decoder', $value));
    }
}