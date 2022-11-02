<?php

declare(strict_types=1);

namespace JsonWebToken\Validator;

use DateTime;

use function sprintf;

final class NotBeforeClaimValidator implements Validator
{
    private readonly int $notBefore;
    private readonly int $allowedTimeDrift;

    public function __construct(int $notBefore, int $allowedTimeDrift = 0)
    {
        $this->notBefore = $notBefore;
        $this->allowedTimeDrift = $allowedTimeDrift;
    }

    public function validate(int|string|bool $value): bool
    {
        if ($this->notBefore !== $value) {
            return false;
        }

        $now = new DateTime();
        $notBefore = new DateTime(sprintf('@%d', ($this->notBefore - $this->allowedTimeDrift)));

        if ($now < $notBefore) {
            return false;
        }

        return true;
    }
}
