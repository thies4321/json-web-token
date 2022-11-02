<?php

declare(strict_types=1);

namespace JsonWebToken\Encoder\RSA;

use JsonWebToken\Encoder\Encoder;
use JsonWebToken\Encoder\RSA;

use const OPENSSL_ALGO_SHA384;

final class RS384 extends RSA implements Encoder
{
    private const HASHING_ALGORITHM = OPENSSL_ALGO_SHA384;

    public function __construct(array $header, array $payload, string $privateKey)
    {
        parent::__construct($header, $payload, $privateKey, self::HASHING_ALGORITHM);
    }
}
