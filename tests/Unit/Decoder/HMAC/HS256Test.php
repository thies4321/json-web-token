<?php

declare(strict_types=1);

namespace JsonWebToken\Tests\Unit\Decoder\HMAC;

use JsonException;
use JsonWebToken\Decoder\HMAC\HS256;
use JsonWebToken\Entity\DecodedToken;
use JsonWebToken\Exception\InvalidSignatureException;
use PHPUnit\Framework\TestCase;

use function explode;

final class HS256Test extends TestCase
{
    private function getValidTokens(): array
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
                ]
            ],
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.F-cvL2RcfQhUtCavIM7q7zYE8drmj2LJk0JRkrS6He4',
                'your-256-bit-secret',
                [
                    'alg' => 'HS256',
                    'typ' => 'JWT',
                ],
                [
                    'sub' => '1234567890',
                    'name' => 'John Doe',
                    'iat' => 1516239022,
                    'admin' => true,
                ]
            ],
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.2aNRHFVrCt15ge4D5rZ4aK8mV1-IXHNQBl_BVnYTxEs',
                'anotherpassword',
                [
                    'alg' => 'HS256',
                    'typ' => 'JWT',
                ],
                [
                    'sub' => '1234567890',
                    'name' => 'John Doe',
                    'iat' => 1516239022,
                    'admin' => true,
                ]
            ]
        ];
    }

    private function getInvalidTokens(): array
    {
        return [
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
                'faultypassword',
            ],
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImZhdWx0eSI6ImhlYWRlciJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.F-cvL2RcfQhUtCavIM7q7zYE8drmj2LJk0JRkrS6He4',
                'your-256-bit-secret',
            ],
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZhdWx0eSBOYW1lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.2aNRHFVrCt15ge4D5rZ4aK8mV1-IXHNQBl_BVnYTxEs',
                'anotherpassword',
            ]
        ];
    }

    /**
     * @dataProvider getValidTokens
     *
     * @throws InvalidSignatureException
     * @throws JsonException
     */
    public function testDecodeSuccessful(string $token, string $secret, array $expectedHeader, array $expectedPayload): void
    {
        $tokenParts = explode('.', $token);

        $decoder = new HS256($tokenParts[0], $tokenParts[1], $tokenParts[2], $secret);
        $decodedToken = $decoder->decode();

        $this->assertInstanceOf(DecodedToken::class, $decodedToken);
        $this->assertEquals($expectedHeader, $decodedToken->getHeader());
        $this->assertEquals($expectedPayload, $decodedToken->getPayload());
        $this->assertEquals(true, $decodedToken->isValid());
    }

    /**
     * @dataProvider getInvalidTokens
     *
     * @throws InvalidSignatureException
     * @throws JsonException
     */
    public function testDecodeFail(string $token, string $secret): void
    {
        $tokenParts = explode('.', $token);

        $decoder = new HS256($tokenParts[0], $tokenParts[1], $tokenParts[2], $secret);

        $this->expectException(InvalidSignatureException::class);

        $decoder->decode();
    }
}