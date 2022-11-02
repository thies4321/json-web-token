<?php

declare(strict_types=1);

namespace JsonWebToken\Entity;

use function sprintf;

final class EncodedToken
{
    private readonly string $header;
    private readonly string $payload;
    private readonly string $signature;

    public function __construct(string $header, string $payload, string $signature)
    {
        $this->header = $header;
        $this->payload = $payload;
        $this->signature = $signature;
    }

    public function getHeader(): string
    {
        return $this->header;
    }

    public function getPayload(): string
    {
        return $this->payload;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    public function get(): string
    {
        return sprintf('%s.%s.%s', $this->header, $this->payload, $this->signature);
    }

    public function __toString(): string
    {
        return $this->get();
    }
}
