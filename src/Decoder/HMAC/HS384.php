<?php

declare(strict_types=1);

namespace JsonWebToken\Decoder\HMAC;

use JsonWebToken\Decoder\Decoder;
use JsonWebToken\Decoder\HMAC;

final class HS384 extends HMAC implements Decoder
{
    private const HASHING_ALGORITHM = 'sha384';

    public function __construct(string $header, string $payload, string $signature, string $secret)
    {
        parent::__construct($header, $payload, $signature, $secret, self::HASHING_ALGORITHM);
    }
}
