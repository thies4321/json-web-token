<?php

declare(strict_types=1);

namespace JsonWebToken;

use JsonWebToken\Decoder\Decoder;
use JsonWebToken\Encoder\Encoder;
use JsonWebToken\Entity\DecodedToken;
use JsonWebToken\Entity\EncodedToken;
use JsonWebToken\Enum\ClaimName;
use JsonWebToken\Exception\AlgorithmNotSupported;
use JsonWebToken\Exception\HeaderNotFoundException;
use JsonWebToken\Mapping\DecoderMapping;
use JsonWebToken\Mapping\EncoderMapping;
use JsonWebToken\Service\Base64UrlService;

use function explode;
use function json_decode;

final class JWT
{
    private readonly EncoderMapping $encoderMapping;
    private readonly DecoderMapping $decoderMapping;

    public function __construct(?EncoderMapping $encoderMapping = null, ?DecoderMapping $decoderMapping = null)
    {
        $this->encoderMapping = $encoderMapping ?? new EncoderMapping();
        $this->decoderMapping = $decoderMapping ?? new DecoderMapping();
    }

    /**
     * @param array $header
     * @param array $payload
     * @param string $secret
     * @return EncodedToken
     * @throws AlgorithmNotSupported
     * @throws HeaderNotFoundException
     */
    public function encode(array $header, array $payload, string $secret): EncodedToken
    {
        $algorithm = $header['alg'] ?? null;

        if ($algorithm === null) {
            throw HeaderNotFoundException::forAlgorithm();
        }

        $encoderClass = $this->encoderMapping->get($algorithm);

        /** @var Encoder $encoder */
        $encoder = new $encoderClass($header, $payload, $secret);

        return $encoder->encode();
    }

    public function decode(string $token, string $secret): DecodedToken
    {
        $tokenParts = explode('.', $token);
        $header = json_decode(Base64UrlService::base64UrlDecode($tokenParts[0]), true);
        $algorithm = $header['alg'] ?? null;

        if ($algorithm === null) {
            throw HeaderNotFoundException::forAlgorithm();
        }

        $decoderClass = $this->decoderMapping->get($algorithm);

        /** @var Decoder $decoder */
        $decoder = new $decoderClass($tokenParts[0], $tokenParts[1], $tokenParts[2], $secret);

        return $decoder->decode();
    }

    public function validate(DecodedToken $decodedToken, ClaimName $claimName): bool
    {

    }
}