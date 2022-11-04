<?php

declare(strict_types=1);

namespace JsonWebToken\Tests\Unit\Encoder;

use PHPUnit\Framework\TestCase;

use function file_get_contents;
use function sprintf;

abstract class RSA extends TestCase
{
    protected function getPrivateKey(): string
    {
        return file_get_contents(sprintf('%s/../../Fixtures/Encoder/RSA/privatekey', __DIR__));
    }

    protected function getInvalidPrivatekey(): string
    {
        return file_get_contents(sprintf('%s/../../Fixtures/Encoder/RSA/privatekey-invalid', __DIR__));
    }
}