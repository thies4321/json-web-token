<?php

declare(strict_types=1);

namespace JsonWebToken\Unit\Decoder\HMAC;

use JsonException;
use JsonWebToken\Decoder\HMAC\HS512;
use JsonWebToken\Entity\DecodedToken;
use JsonWebToken\Exception\InvalidSignatureException;
use PHPUnit\Framework\TestCase;

use function explode;

final class HS512Test extends TestCase
{
    private function getValidTokens(): array
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
                ]
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
                ]
            ],
            [
                'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.y5I4C0IAKLxi-RWLt6qvSd1bFG_yorhv699yM-ln65OSinCJ92omUZScQ2ml2VKCYmTmYLdKlmUTEbjyGdczHg',
                'anotherpassword',
                [
                    'alg' => 'HS512',
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
                'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ._MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg',
                'faultypassword',
            ],
            [
                'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImZhdWx0eSI6ImhlYWRlciJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ._MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg',
                'your-512-bit-secret',
            ],
            [
                'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZmF1bHR5IjoicGF5bG9hZCJ9.8aMsJp4VGY_Ia2s9iWrS8jARCggx0FDRn2FehblXyvGYRrVVbu3LkKKqx_MEuDjQ',
                'your-512-bit-secret',
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

        $decoder = new HS512($tokenParts[0], $tokenParts[1], $tokenParts[2], $secret);
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

        $decoder = new HS512($tokenParts[0], $tokenParts[1], $tokenParts[2], $secret);

        $this->expectException(InvalidSignatureException::class);

        $decoder->decode();
    }
}
