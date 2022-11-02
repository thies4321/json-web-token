<?php

declare(strict_types=1);

namespace JsonWebToken\Mapping;

use JsonWebToken\Enum\ClaimName;
use JsonWebToken\Exception\ValidatorNotFound;
use JsonWebToken\Validator\AudienceClaimValidator;
use JsonWebToken\Validator\ExpirationTimeClaimValidator;
use JsonWebToken\Validator\IssuedAtValidator;
use JsonWebToken\Validator\IssuerClaimValidator;
use JsonWebToken\Validator\JwtIdValidator;
use JsonWebToken\Validator\NotBeforeClaimValidator;
use JsonWebToken\Validator\SubjectClaimValidator;

final class ValidatorMapping implements Mapping
{
    public function supports(string $value): bool
    {
        try {
            $this->get($value);
            return true;
        } catch (ValidatorNotFound $exception) {
            return false;
        }
    }

    /**
     * @throws ValidatorNotFound
     */
    public function get(string $value): string
    {
        return match ($value) {
            ClaimName::Issuer->value => IssuerClaimValidator::class,
            ClaimName::Subject->value => SubjectClaimValidator::class,
            ClaimName::Audience->value => AudienceClaimValidator::class,
            ClaimName::Expiration_Time->value => ExpirationTimeClaimValidator::class,
            ClaimName::Not_Before->value => NotBeforeClaimValidator::class,
            ClaimName::Issued_At->value => IssuedAtValidator::class,
            ClaimName::JWT_ID->value => JwtIdValidator::class,
            default => throw ValidatorNotFound::forClaim($value),
        };
    }
}
