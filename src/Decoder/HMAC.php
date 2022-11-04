<?php

declare(strict_types=1);

namespace JsonWebToken\Decoder;

use JsonException;
use JsonWebToken\Entity\DecodedToken;
use JsonWebToken\Exception\InvalidSignatureException;
use JsonWebToken\Service\Base64UrlService;

use function hash_hmac;
use function json_decode;
use function sprintf;

use const JSON_THROW_ON_ERROR;

abstract class HMAC implements Decoder
{
    private readonly string $header;
    private readonly string $payload;
    private readonly string $signature;
    private readonly string $secret;
    private readonly string $hashingAlgorithm;

    public function __construct(
        string $header,
        string $payload,
        string $signature,
        string $secret,
        string $hashingAlgorithm
    ) {
        $this->header = $header;
        $this->payload = $payload;
        $this->signature = $signature;
        $this->secret = $secret;
        $this->hashingAlgorithm = $hashingAlgorithm;
    }

    /**
     * @throws InvalidSignatureException
     * @throws JsonException
     */
    public function decode(): DecodedToken
    {
        $check = Base64UrlService::base64UrlEncode(
            hash_hmac(
                $this->hashingAlgorithm,
                sprintf('%s.%s', $this->header, $this->payload),
                $this->secret,
                true
            )
        );

        if ($check !== $this->signature) {
            throw InvalidSignatureException::forHMAC($this->signature, $check);
        }

        return new DecodedToken(
            json_decode(Base64UrlService::base64UrlDecode($this->header), true, 512, JSON_THROW_ON_ERROR),
            json_decode(Base64UrlService::base64UrlDecode($this->payload), true, 512, JSON_THROW_ON_ERROR)
        );
    }
}
