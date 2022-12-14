<?php

declare(strict_types=1);

namespace JsonWebToken\Encoder\RSA;

use JsonWebToken\Encoder\RSA;

use const OPENSSL_ALGO_SHA256;

final class RS256 extends RSA
{
    private const HASHING_ALGORITHM = OPENSSL_ALGO_SHA256;

    public function __construct(array $header, array $payload, string $privateKey)
    {
        parent::__construct($header, $payload, $privateKey, self::HASHING_ALGORITHM);
    }
}
