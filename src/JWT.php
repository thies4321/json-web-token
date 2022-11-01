<?php

declare(strict_types=1);

namespace JsonWebToken;

use JsonWebToken\Entity\DecodedToken;
use JsonWebToken\Entity\EncodedToken;
use JsonWebToken\Enum\ClaimName;
use JsonWebToken\Exception\AlgorithmNotSupported;
use JsonWebToken\Exception\HeaderNotFoundException;
use JsonWebToken\Mapping\EncoderMapping;

final class JWT
{
    private readonly EncoderMapping $encoderMapping;

    public function __construct(?EncoderMapping $encoderMapping = null)
    {
        $this->encoderMapping = $encoderMapping ?? new EncoderMapping();
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

        $encoder = new $encoderClass($header, $payload, $secret);

        return $encoder->encode();
    }

    public function decode(string $token): DecodedToken
    {

    }

    public function validate(DecodedToken $decodedToken, ClaimName $claimName): bool
    {

    }
}