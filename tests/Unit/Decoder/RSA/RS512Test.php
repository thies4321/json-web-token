<?php

declare(strict_types=1);

namespace JsonWebToken\Tests\Unit\Decoder\RSA;

use JsonException;
use JsonWebToken\Decoder\RSA\RS512;
use JsonWebToken\Entity\DecodedToken;
use JsonWebToken\Exception\InvalidSignatureException;
use JsonWebToken\Tests\Unit\Decoder\RSA;

use function explode;

final class RS512Test extends RSA
{
    private function getValidTokens(): array
    {
        return [
            [
                'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kEZmDAnHHU_0bcGXMd5LA7vF87yQgXNaioPHP4lU4O3JJYuZ54fJdv3HT58xk-MFEDuWro_5fvNIp2VM-PlkZvYWrhQkJ-c-seoSa3ANq_PciC3bGfzYHEdjAE71GrAMI4FlcAGsq3ChkOnCTFqjWDmVwaRYCgMsFQ-U5cjvFhndFMizrkRljTF4v5oFdWytV_J-UafPtNdQXcGND1M74DqObnTHhZHg8aDfNzZcvnIeKcDVGUlUEL5ia1kPMrVhCtOAOJmEU8ivCdWWzt-jMQBf7cZeoCzDKHG72ysTTCfRoBVc1_SrQTHcHDiiBeW9nCazMLkltyP5NeawR_RNlg',
                $this->getPublicKey(),
                [
                    'alg' => 'RS512',
                    'typ' => 'JWT',
                ],
                [
                    'sub' => '1234567890',
                    'name' => 'John Doe',
                    'iat' => 1516239022,
                ]
            ],
            [
                'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ',
                $this->getPublicKey(),
                [
                    'alg' => 'RS512',
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
                'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kEZmDAnHHU_0bcGXMd5LA7vF87yQgXNaioPHP4lU4O3JJYuZ54fJdv3HT58xk-MFEDuWro_5fvNIp2VM-PlkZvYWrhQkJ-c-seoSa3ANq_PciC3bGfzYHEdjAE71GrAMI4FlcAGsq3ChkOnCTFqjWDmVwaRYCgMsFQ-U5cjvFhndFMizrkRljTF4v5oFdWytV_J-UafPtNdQXcGND1M74DqObnTHhZHg8aDfNzZcvnIeKcDVGUlUEL5ia1kPMrVhCtOAOJmEU8ivCdWWzt-jMQBf7cZeoCzDKHG72ysTTCfRoBVc1_SrQTHcHDiiBeW9nCazMLkltyP5NeawR_RNlg',
                $this->getInvalidPublicKey(),
            ],
            [
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImZhdWx0eSI6ImhlYWRlciJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kEZmDAnHHU_0bcGXMd5LA7vF87yQgXNaioPHP4lU4O3JJYuZ54fJdv3HT58xk-MFEDuWro_5fvNIp2VM-PlkZvYWrhQkJ-c-seoSa3ANq_PciC3bGfzYHEdjAE71GrAMI4FlcAGsq3ChkOnCTFqjWDmVwaRYCgMsFQ-U5cjvFhndFMizrkRljTF4v5oFdWytV_J-UafPtNdQXcGND1M74DqObnTHhZHg8aDfNzZcvnIeKcDVGUlUEL5ia1kPMrVhCtOAOJmEU8ivCdWWzt-jMQBf7cZeoCzDKHG72ysTTCfRoBVc1_SrQTHcHDiiBeW9nCazMLkltyP5NeawR_RNlg',
                $this->getPublicKey(),
            ],
            [
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.kEZmDAnHHU_0bcGXMd5LA7vF87yQgXNaioPHP4lU4O3JJYuZ54fJdv3HT58xk-MFEDuWro_5fvNIp2VM-PlkZvYWrhQkJ-c-seoSa3ANq_PciC3bGfzYHEdjAE71GrAMI4FlcAGsq3ChkOnCTFqjWDmVwaRYCgMsFQ-U5cjvFhndFMizrkRljTF4v5oFdWytV_J-UafPtNdQXcGND1M74DqObnTHhZHg8aDfNzZcvnIeKcDVGUlUEL5ia1kPMrVhCtOAOJmEU8ivCdWWzt-jMQBf7cZeoCzDKHG72ysTTCfRoBVc1_SrQTHcHDiiBeW9nCazMLkltyP5NeawR_RNlg',
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

        $decoder = new RS512($tokenParts[0], $tokenParts[1], $tokenParts[2], $secret);
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

        $decoder = new RS512($tokenParts[0], $tokenParts[1], $tokenParts[2], $secret);

        $this->expectException(InvalidSignatureException::class);

        $decoder->decode();
    }
}