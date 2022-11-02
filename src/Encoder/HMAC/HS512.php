<?php

declare(strict_types=1);

namespace JsonWebToken\Encoder\HMAC;

use JsonWebToken\Encoder\Encoder;
use JsonWebToken\Encoder\HMAC;

final class HS512 extends HMAC implements Encoder
{
    private const HASHING_ALGORITHM = 'sha512';

    public function __construct(array $header, array $payload, string $secret)
    {
        parent::__construct($header, $payload, $secret, self::HASHING_ALGORITHM);
    }
}