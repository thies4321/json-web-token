<?php

declare(strict_types=1);

namespace JsonWebToken\Entity;

final class DecodedToken
{
    private readonly array $header;
    private readonly array $payload;
    private readonly bool $valid;

    public function __construct(array $header, array $payload, bool $valid = true)
    {
        $this->header = $header;
        $this->payload = $payload;
        $this->valid = $valid;
    }

    public function getHeader(): array
    {
        return $this->header;
    }

    public function getPayload(): array
    {
        return $this->payload;
    }

    public function isValid(): bool
    {
        return $this->valid;
    }
}
