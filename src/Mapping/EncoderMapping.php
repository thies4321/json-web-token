<?php

declare(strict_types=1);

namespace JsonWebToken\Mapping;

use JsonWebToken\Encoder\HMAC\HS256;
use JsonWebToken\Encoder\HMAC\HS384;
use JsonWebToken\Encoder\HMAC\HS512;
use JsonWebToken\Encoder\RSA\RS256;
use JsonWebToken\Encoder\RSA\RS384;
use JsonWebToken\Encoder\RSA\RS512;
use JsonWebToken\Enum\SigningAlgorithm;
use JsonWebToken\Exception\AlgorithmNotSupported;

use function array_key_exists;

final class EncoderMapping implements Mapping
{
    private readonly array $supportedAlgorithms;

    public function __construct()
    {
        $this->supportedAlgorithms = [
            SigningAlgorithm::HS256->name => HS256::class,
            SigningAlgorithm::HS384->name => HS384::class,
            SigningAlgorithm::HS512->name => HS512::class,
            SigningAlgorithm::RS256->name => RS256::class,
            SigningAlgorithm::RS384->name => RS384::class,
            SigningAlgorithm::RS512->name => RS512::class,
        ];
    }

    public function supports(string $value): bool
    {
        return array_key_exists($value, $this->supportedAlgorithms);
    }

    /**
     * @throws AlgorithmNotSupported
     */
    public function get(string $value): string
    {
        if (! $this->supports($value)) {
            throw AlgorithmNotSupported::forEncoder($value);
        }

        return $this->supportedAlgorithms[$value];
    }
}