<?php

declare(strict_types=1);

namespace JsonWebToken\Mapping;

use JsonWebToken\Decoder\HMAC\HS256;
use JsonWebToken\Decoder\HMAC\HS384;
use JsonWebToken\Decoder\HMAC\HS512;
use JsonWebToken\Decoder\RSA\RS256;
use JsonWebToken\Decoder\RSA\RS384;
use JsonWebToken\Decoder\RSA\RS512;
use JsonWebToken\Enum\SigningAlgorithm;
use JsonWebToken\Exception\AlgorithmNotSupported;

final class DecoderMapping implements Mapping
{
    public function supports(string $value): bool
    {
        try {
            $this->get($value);
            return true;
        } catch (AlgorithmNotSupported $exception) {
            return false;
        }
    }

    /**
     * @throws AlgorithmNotSupported
     */
    public function get(string $value): string
    {
        return match ($value) {
            SigningAlgorithm::HS256->name => HS256::class,
            SigningAlgorithm::HS384->name => HS384::class,
            SigningAlgorithm::HS512->name => HS512::class,
            SigningAlgorithm::RS256->name => RS256::class,
            SigningAlgorithm::RS384->name => RS384::class,
            SigningAlgorithm::RS512->name => RS512::class,
            default => throw AlgorithmNotSupported::forDecoder($value)
        };
    }
}
