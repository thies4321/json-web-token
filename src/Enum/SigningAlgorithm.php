<?php

declare(strict_types=1);

namespace JsonWebToken\Enum;

enum SigningAlgorithm
{
    case HS256;
    case HS384;
    case HS512;
    case PS256;
    case PS384;
    case PS512;
    case RS256;
    case RS384;
    case RS512;
    case ES256;
    case ES256K;
    case ES384;
    case ES512;
    case EdDSA;
}
