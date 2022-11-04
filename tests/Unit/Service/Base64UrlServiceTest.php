<?php

declare(strict_types=1);

namespace JsonWebToken\Tests\Unit\Service;

use JsonWebToken\Service\Base64UrlService;
use PHPUnit\Framework\TestCase;

final class Base64UrlServiceTest extends TestCase
{
    public function getDataProvider(): array
    {
        return [
            ['dGVzdA', 'test'],
            ['dGVzdDI', 'test2'],
            ['dGVzdHRlc3Q', 'testtest'],
            ['dGVzdHRlc3R0ZXN0', 'testtesttest']
        ];
    }

    /**
     * @dataProvider getDataProvider
     */
    public function testBase64UrlEncode(string $expected, string $input): void
    {
        $result = Base64UrlService::base64UrlEncode($input);

        $this->assertEquals($expected, $result);
    }

    /**
     * @dataProvider getDataProvider
     */
    public function testBase64UrlDecode(string $input, string $expected): void
    {
        $result = Base64UrlService::base64UrlDecode($input);

        $this->assertEquals($expected, $result);
    }
}
