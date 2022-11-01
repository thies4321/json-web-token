<?php

declare(strict_types=1);

namespace JsonWebToken\Encoder;

use JsonWebToken\Entity\EncodedToken;

use function json_encode;
use function openssl_sign;
use function sprintf;

abstract class RSA extends AbstractEncoder implements Encoder
{
    private readonly array $header;
    private readonly array $payload;
    private readonly string $privateKey;
    private readonly int $hashingAlgorithm;

    public function __construct(array $header, array $payload, string $privateKey, int $hashingAlgorithm)
    {
        $this->header = $header;
        $this->payload = $payload;
        $this->privateKey = $privateKey;
        $this->hashingAlgorithm = $hashingAlgorithm;
    }

    public function encode(): EncodedToken
    {
        $header = $this->base64UrlEncode(json_encode($this->header));
        $payload = $this->base64UrlEncode(json_encode($this->payload));

        openssl_sign(
            sprintf('%s.%s', $header, $payload),
            $signature,
            $this->privateKey,
            $this->hashingAlgorithm
        );

        return new EncodedToken($header, $payload, $this->base64UrlEncode($signature));
    }
}