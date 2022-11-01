<?php

declare(strict_types=1);

namespace JsonWebToken\Exception;

use Exception;

use function sprintf;

final class InvalidSignatureException extends Exception
{
    public static function forHMAC(string $signature, string $check): self
    {
        return new self(sprintf('Provided signature [%s] does not match check [%s]', $signature, $check));
    }

    public static function forRSA(string $signature): self
    {
        return new self(sprintf('Signature [%s] could not be verified with public key', $signature));
    }
}