<?php

declare(strict_types=1);

namespace JsonWebToken\Encoder;

use JsonException;
use JsonWebToken\Entity\EncodedToken;
use JsonWebToken\Service\Base64UrlService;

use function json_encode;
use function openssl_sign;
use function sprintf;

use const JSON_THROW_ON_ERROR;

abstract class RSA implements Encoder
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

    /**
     * @throws JsonException
     */
    public function encode(): EncodedToken
    {
        $header = Base64UrlService::base64UrlEncode(json_encode($this->header, JSON_THROW_ON_ERROR));
        $payload = Base64UrlService::base64UrlEncode(json_encode($this->payload, JSON_THROW_ON_ERROR));

        openssl_sign(
            sprintf('%s.%s', $header, $payload),
            $signature,
            $this->privateKey,
            $this->hashingAlgorithm
        );

        return new EncodedToken($header, $payload, Base64UrlService::base64UrlEncode($signature));
    }
}
