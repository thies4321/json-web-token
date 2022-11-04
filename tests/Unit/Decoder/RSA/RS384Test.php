<?php

declare(strict_types=1);

namespace JsonWebToken\Tests\Unit\Decoder\RSA;

use JsonException;
use JsonWebToken\Decoder\RSA\RS384;
use JsonWebToken\Entity\DecodedToken;
use JsonWebToken\Exception\InvalidSignatureException;
use JsonWebToken\Tests\Unit\Decoder\RSA;

use function explode;

final class RS384Test extends RSA
{
    private function getValidTokens(): array
    {
        return [
            [
                'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.oPvWzaCp8xUpt5mHhPSn0qLsZfCFj0NVmb4mz4dFQPCCMj-F5zVn9e3zZoj0lIXWM8rxB69QHC3Er47mtDt3BKgysTL3BvvV89kD6UjLoUcAI3lwj0mi7acLoE27i1_TnIBqWNRPAsdvTDawNE0_4lvI5bxEWQCqisJwxCoMDIeJsmDzfyApgU_SAFSVULxXwU2VewaxdQB-41OZdWwUEAxh81iB6DFWrqd2CaJkUYoWjgYpeWsyeC2m_-ECGrHGEz1nKTm9c7BaPxurz7fHD7RJd9Wpx-mKDVsfspO9quWb_OLeGGbxTtAomMvjQjut56kx2fqTleDnNDh_0GE88w',
                $this->getPublicKey(),
                [
                    'alg' => 'RS384',
                    'typ' => 'JWT',
                ],
                [
                    'sub' => '1234567890',
                    'name' => 'John Doe',
                    'iat' => 1516239022,
                ]
            ],
            [
                'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJhh994RAPzCG0hmQ',
                $this->getPublicKey(),
                [
                    'alg' => 'RS384',
                    'typ' => 'JWT',
                ],
                [
                    'sub' => '1234567890',
                    'name' => 'John Doe',
                    'iat' => 1516239022,
                    'admin' => true,
                ]
            ],
        ];
    }

    private function getInvalidTokens(): array
    {
        return [
            [
                'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.oPvWzaCp8xUpt5mHhPSn0qLsZfCFj0NVmb4mz4dFQPCCMj-F5zVn9e3zZoj0lIXWM8rxB69QHC3Er47mtDt3BKgysTL3BvvV89kD6UjLoUcAI3lwj0mi7acLoE27i1_TnIBqWNRPAsdvTDawNE0_4lvI5bxEWQCqisJwxCoMDIeJsmDzfyApgU_SAFSVULxXwU2VewaxdQB-41OZdWwUEAxh81iB6DFWrqd2CaJkUYoWjgYpeWsyeC2m_-ECGrHGEz1nKTm9c7BaPxurz7fHD7RJd9Wpx-mKDVsfspO9quWb_OLeGGbxTtAomMvjQjut56kx2fqTleDnNDh_0GE88w',
                $this->getInvalidPublicKey(),
            ],
            [
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImZhdWx0eSI6ImhlYWRlciJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.oPvWzaCp8xUpt5mHhPSn0qLsZfCFj0NVmb4mz4dFQPCCMj-F5zVn9e3zZoj0lIXWM8rxB69QHC3Er47mtDt3BKgysTL3BvvV89kD6UjLoUcAI3lwj0mi7acLoE27i1_TnIBqWNRPAsdvTDawNE0_4lvI5bxEWQCqisJwxCoMDIeJsmDzfyApgU_SAFSVULxXwU2VewaxdQB-41OZdWwUEAxh81iB6DFWrqd2CaJkUYoWjgYpeWsyeC2m_-ECGrHGEz1nKTm9c7BaPxurz7fHD7RJd9Wpx-mKDVsfspO9quWb_OLeGGbxTtAomMvjQjut56kx2fqTleDnNDh_0GE88w',
                $this->getPublicKey(),
            ],
            [
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.oPvWzaCp8xUpt5mHhPSn0qLsZfCFj0NVmb4mz4dFQPCCMj-F5zVn9e3zZoj0lIXWM8rxB69QHC3Er47mtDt3BKgysTL3BvvV89kD6UjLoUcAI3lwj0mi7acLoE27i1_TnIBqWNRPAsdvTDawNE0_4lvI5bxEWQCqisJwxCoMDIeJsmDzfyApgU_SAFSVULxXwU2VewaxdQB-41OZdWwUEAxh81iB6DFWrqd2CaJkUYoWjgYpeWsyeC2m_-ECGrHGEz1nKTm9c7BaPxurz7fHD7RJd9Wpx-mKDVsfspO9quWb_OLeGGbxTtAomMvjQjut56kx2fqTleDnNDh_0GE88w',
                $this->getPublicKey(),
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

        $decoder = new RS384($tokenParts[0], $tokenParts[1], $tokenParts[2], $secret);
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

        $decoder = new RS384($tokenParts[0], $tokenParts[1], $tokenParts[2], $secret);

        $this->expectException(InvalidSignatureException::class);

        $decoder->decode();
    }
}