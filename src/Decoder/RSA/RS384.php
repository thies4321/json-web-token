<?php

declare(strict_types=1);

namespace JsonWebToken\Decoder\RSA;

use JsonWebToken\Decoder\RSA;

use const OPENSSL_ALGO_SHA384;

final class RS384 extends RSA
{
    private const HASHING_ALGORITHM = OPENSSL_ALGO_SHA384;

    public function __construct(string $header, string $payload, string $signature, string $secret)
    {
        parent::__construct($header, $payload, $signature, $secret, self::HASHING_ALGORITHM);
    }
}
