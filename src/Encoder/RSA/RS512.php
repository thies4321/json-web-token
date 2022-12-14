<?php

declare(strict_types=1);

namespace JsonWebToken\Encoder\RSA;

use JsonWebToken\Encoder\RSA;

use const OPENSSL_ALGO_SHA512;

final class RS512 extends RSA
{
    private const HASHING_ALGORITHM = OPENSSL_ALGO_SHA512;

    public function __construct(array $header, array $payload, string $privateKey)
    {
        parent::__construct($header, $payload, $privateKey, self::HASHING_ALGORITHM);
    }
}
