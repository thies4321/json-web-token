<?php

declare(strict_types=1);

namespace JsonWebToken\Tests\Unit\Encoder\HMAC;

use JsonException;
use JsonWebToken\Encoder\HMAC\HS384;
use JsonWebToken\Entity\EncodedToken;
use PHPUnit\Framework\TestCase;

final class HS384Test extends TestCase
{
    public function tokenProvider(): array
    {
        return [
            [
                'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8aMsJp4VGY_Ia2s9iWrS8jARCggx0FDRn2FehblXyvGYRrVVbu3LkKKqx_MEuDjQ',
                'your-384-bit-secret',
                [
                    'alg' => 'HS384',
                    'typ' => 'JWT',
                ],
                [
                    'sub' => '1234567890',
                    'name' => 'John Doe',
                    'iat' => 1516239022,
                ],
            ],
            [
                'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh',
                'your-384-bit-secret',
                [
                    'alg' => 'HS384',
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
        $encoder = new HS384($header, $payload, $secret);
        $token = $encoder->encode();

        $this->assertInstanceOf(EncodedToken::class, $token);
        $this->assertEquals($expectedToken, $token->get());
    }
}
