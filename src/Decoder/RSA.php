<?php

declare(strict_types=1);

namespace JsonWebToken\Decoder;

use JsonWebToken\Entity\DecodedToken;
use JsonWebToken\Exception\InvalidSignatureException;
use JsonWebToken\Service\Base64UrlService;

use function json_decode;
use function openssl_verify;
use function sprintf;

abstract class RSA implements Decoder
{
    private readonly string $header;
    private readonly string $payload;
    private readonly string $signature;
    private readonly string $secret;
    private readonly int $hashingAlgorithm;

    public function __construct(string $header, string $payload, string $signature, string $secret, int $hashingAlgorithm)
    {
        $this->header = $header;
        $this->payload = $payload;
        $this->signature = $signature;
        $this->secret = $secret;
        $this->hashingAlgorithm = $hashingAlgorithm;
    }

    /**
     * @throws InvalidSignatureException
     */
    public function decode(): DecodedToken
    {
        $check = openssl_verify(
            sprintf('%s.%s', $this->header, $this->payload),
            Base64UrlService::base64UrlDecode($this->signature),
            $this->secret,
            $this->hashingAlgorithm
        );

        if ($check !== 1) {
            throw InvalidSignatureException::forRSA($this->signature);
        }

        return new DecodedToken(
            json_decode(Base64UrlService::base64UrlDecode($this->header), true),
            json_decode(Base64UrlService::base64UrlDecode($this->payload), true)
        );
    }
}
