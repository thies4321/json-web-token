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
use JsonWebToken\Exception\ValidationFailedException;
use JsonWebToken\Exception\ValidatorNotFound;
use JsonWebToken\Mapping\DecoderMapping;
use JsonWebToken\Mapping\EncoderMapping;
use JsonWebToken\Mapping\ValidatorMapping;
use JsonWebToken\Service\Base64UrlService;
use JsonWebToken\Validator\Validator;

use function array_key_exists;
use function explode;
use function json_decode;

final class JWT
{
    private readonly EncoderMapping $encoderMapping;
    private readonly DecoderMapping $decoderMapping;
    private readonly ValidatorMapping $validatorMapping;

    public function __construct(
        ?EncoderMapping $encoderMapping = null,
        ?DecoderMapping $decoderMapping = null,
        ?ValidatorMapping $validatorMapping = null
    ) {
        $this->encoderMapping = $encoderMapping ?? new EncoderMapping();
        $this->decoderMapping = $decoderMapping ?? new DecoderMapping();
        $this->validatorMapping = $validatorMapping ?? new ValidatorMapping();
    }

    /**
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

    /**
     * @throws AlgorithmNotSupported
     * @throws HeaderNotFoundException
     * @throws ValidationFailedException
     * @throws ValidatorNotFound
     */
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

        $decodedToken = $decoder->decode();

        foreach (ClaimName::cases() as $claimName) {
            if (array_key_exists($claimName->value, $decodedToken->getPayload())) {
                if (! $this->validate($decodedToken, $claimName)) {
                    throw ValidationFailedException::forClaim($claimName->value);
                }
            }
        }

        return $decodedToken;
    }

    /**
     * @throws ValidatorNotFound
     */
    public function validate(DecodedToken $decodedToken, ClaimName $claimName): bool
    {
        $validatorClass = $this->validatorMapping->get($claimName->value);
        $claimValue = $decodedToken->getPayload()[$claimName->value] ?? null;

        /** @var Validator $validator */
        $validator = new $validatorClass($claimValue);

        return $validator->validate($claimValue);
    }
}
