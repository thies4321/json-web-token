<?php

declare(strict_types=1);

namespace JsonWebToken\Decoder\RSA;

use JsonWebToken\Decoder\Decoder;
use JsonWebToken\Decoder\RSA;

use const OPENSSL_ALGO_SHA256;

final class RS256 extends RSA implements Decoder
{
    private const HASHING_ALGORITHM = OPENSSL_ALGO_SHA256;

    public function __construct(string $header, string $payload, string $signature, string $secret)
    {
        parent::__construct($header, $payload, $signature, $secret, self::HASHING_ALGORITHM);
    }
}
