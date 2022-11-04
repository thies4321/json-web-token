<?php

declare(strict_types=1);

namespace JsonWebToken\Tests\Unit\Encoder\HMAC;

use JsonException;
use JsonWebToken\Encoder\HMAC\HS256;
use JsonWebToken\Entity\EncodedToken;
use PHPUnit\Framework\TestCase;

final class HS256Test extends TestCase
{
    public function tokenProvider(): array
    {
        return [
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
                'your-256-bit-secret',
                [
                    'alg' => 'HS256',
                    'typ' => 'JWT',
                ],
                [
                    'sub' => '1234567890',
                    'name' => 'John Doe',
                    'iat' => 1516239022,
                ],
            ],
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.reGQzG3OKdoIMWLDKOZ4TICJit3EW69cQE72E2CfzRE',
                'your-256-bit-secret',
                [
                    'alg' => 'HS256',
                    'typ' => 'JWT',
                ],
                [
                    'sub' => '1234567890',
                    'name' => 'John Doe',
                    'admin' => true,
                    'iat' => 1516239022,
                ],
            ]
        ];
    }

    /**
     * @dataProvider tokenProvider
     *
     * @throws JsonException
     */
    public function testEncode(string $expectedToken, string $secret, array $header, array $payload): void
    {
        $encoder = new HS256($header, $payload, $secret);
        $token = $encoder->encode();

        $this->assertInstanceOf(EncodedToken::class, $token);
        $this->assertEquals($expectedToken, $token->get());
    }
}
