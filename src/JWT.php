<?php

declare(strict_types=1);

namespace JsonWebToken;

use JsonException;
use JsonWebToken\Entity\DecodedToken;
use JsonWebToken\Entity\EncodedToken;
use JsonWebToken\Enum\ClaimName;
use JsonWebToken\Exception\AlgorithmNotSupported;
use JsonWebToken\Exception\HeaderNotFoundException;
use JsonWebToken\Exception\ValidatorNotFound;
use JsonWebToken\Service\JsonWebTokenService;

final class JWT
{
    public const VERSION = '1.0';

    /**
     * @throws AlgorithmNotSupported
     * @throws HeaderNotFoundException
     */
    public static function encode(array $header, array $payload, string $secret): EncodedToken
    {
        return (new JsonWebTokenService())->encode($header, $payload, $secret);
    }

    /**
     * @throws AlgorithmNotSupported
     * @throws Exception\ValidatorNotFound
     * @throws HeaderNotFoundException
     * @throws JsonException
     */
    public static function decode(string $token, string $secret): DecodedToken
    {
        return (new JsonWebTokenService())->decode($token, $secret);
    }

    /**
     * @throws ValidatorNotFound
     */
    public static function validate(DecodedToken $decodedToken, ClaimName $claimName): bool
    {
        return (new JsonWebTokenService())->validate($decodedToken, $claimName);
    }
}
