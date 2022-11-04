<?php

declare(strict_types=1);

namespace JsonWebToken\Tests\Unit\Encoder\HMAC;

use JsonException;
use JsonWebToken\Encoder\HMAC\HS512;
use JsonWebToken\Entity\EncodedToken;
use PHPUnit\Framework\TestCase;

final class HS512Test extends TestCase
{
    public function tokenProvider(): array
    {
        return [
            [
                'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ._MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg',
                'your-512-bit-secret',
                [
                    'alg' => 'HS512',
                    'typ' => 'JWT',
                ],
                [
                    'sub' => '1234567890',
                    'name' => 'John Doe',
                    'iat' => 1516239022,
                ],
            ],
            [
                'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg',
                'your-512-bit-secret',
                [
                    'alg' => 'HS512',
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
        $encoder = new HS512($header, $payload, $secret);
        $token = $encoder->encode();

        $this->assertInstanceOf(EncodedToken::class, $token);
        $this->assertEquals($expectedToken, $token->get());
    }
}