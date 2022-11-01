<?php

declare(strict_types=1);

namespace JsonWebToken\Mapping;

use JsonWebToken\Encoder\Encoder;
use JsonWebToken\Encoder\HMAC\HS256;
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