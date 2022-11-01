<?php

declare(strict_types=1);

namespace JsonWebToken\Entity;

final class DecodedToken
{
    private readonly array $header;
    private readonly array $payload;

    public function __construct(array $header, array $payload)
    {
        $this->header = $header;
        $this->payload = $payload;
    }

    public function getHeader(): array
    {
        return $this->header;
    }

    public function getPayload(): array
    {
        return $this->payload;
    }
}