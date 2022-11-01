<?php

declare(strict_types=1);

namespace JsonWebToken\Mapping;

interface Mapping
{
    public function supports(string $value): bool;

    public function get(string $value): mixed;
}