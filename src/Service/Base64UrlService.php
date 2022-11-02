<?php

declare(strict_types=1);

namespace JsonWebToken\Service;

use function base64_decode;
use function base64_encode;
use function rtrim;
use function strtr;

final class Base64UrlService
{
    public static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $encodedToken): string
    {
        return base64_decode(strtr($encodedToken, '-_', '+/'));
    }
}
