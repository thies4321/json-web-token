<?php

declare(strict_types=1);

namespace JsonWebToken\Enum;

enum ClaimName: string
{
    case Issuer = 'iss';
    case Subject = 'sub';
    case Audience = 'aud';
    case Expiration_Time = 'exp';
    case Not_Before = 'nbf';
    case Issued_At = 'iat';
    case JWT_ID = 'jti';
}