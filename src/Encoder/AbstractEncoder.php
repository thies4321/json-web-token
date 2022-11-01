<?php

declare(strict_types=1);

namespace JsonWebToken\Encoder;

use function base64_encode;
use function rtrim;

abstract class AbstractEncoder implements Encoder
{
    protected function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}