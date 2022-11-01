<?php

declare(strict_types=1);

namespace JsonWebToken\Encoder;

use JsonWebToken\Entity\EncodedToken;
use function hash_hmac;
use function json_encode;
use function sprintf;

abstract class HMAC extends AbstractEncoder implements Encoder
{
    private readonly array $header;
    private readonly array $payload;
    private readonly string $secret;
    private readonly string $hashingAlgorithm;

    public function __construct(array $header, array $payload, string $secret, string $hashingAlgorithm)
    {
        $this->header = $header;
        $this->payload = $payload;
        $this->secret = $secret;
        $this->hashingAlgorithm = $hashingAlgorithm;
    }

    public function encode(): EncodedToken
    {
        $header = $this->base64UrlEncode(json_encode($this->header));
        $payload = $this->base64UrlEncode(json_encode($this->payload));
        $signature = $this->base64UrlEncode(
            hash_hmac(
                $this->hashingAlgorithm,
                sprintf('%s.%s', $header, $payload),
                $this->secret,
                true
            )
        );

        return new EncodedToken($header, $payload, $signature);
    }
}