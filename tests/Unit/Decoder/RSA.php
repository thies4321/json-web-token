<?php

declare(strict_types=1);

namespace JsonWebToken\Tests\Unit\Decoder;

use PHPUnit\Framework\TestCase;

use function file_get_contents;
use function sprintf;

abstract class RSA extends TestCase
{
    protected function getPublicKey(): string
    {
        return file_get_contents(sprintf('%s/../../Fixtures/Decoder/RSA/publickey', __DIR__));
    }

    protected function getInvalidPublicKey(): string
    {
        return file_get_contents(sprintf('%s/../../Fixtures/Decoder/RSA/publickey-invalid', __DIR__));
    }
}