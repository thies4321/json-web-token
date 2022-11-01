<?php

declare(strict_types=1);

namespace JsonWebToken\Validator;

use DateTime;
use Exception;

use function sprintf;

final class ExpirationTimeClaimValidator implements Validator
{
    private readonly int $expirationTime;
    private readonly int $allowedTimeDrift;

    /**
     * @throws Exception
     */
    public function __construct(int $expirationTime, int $allowedTimeDrift = 0)
    {
        $this->expirationTime = $expirationTime;
        $this->allowedTimeDrift = $allowedTimeDrift;
    }

    /**
     * @throws Exception
     */
    public function validate(int|string|bool $value): bool
    {
        if ($this->expirationTime !== $value) {
            return false;
        }

        $now = new DateTime();
        $expirationTime = new DateTime(sprintf('@%d', ($this->expirationTime + $this->allowedTimeDrift)));

        if ($now >= $expirationTime) {
            return false;
        }

        return true;
    }
}