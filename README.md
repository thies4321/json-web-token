# json-web-token
JSON Web Token library written in PHP

## Usage
### Encoding
```php
$header = [
    'alg' => 'HS256',
    'typ' => 'JWT',
];

$payload = [
    'sub' => '1234567890',
    'name' => 'John Doe',
    'iat' => 1516239022
];

$encodedToken = \JsonWebToken\JWT::encode($header, $payload, 'your-passphrase-or-key');

$encodedToken->get(); // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.g0nxZDyzNvuhhuPrpwZFNdtGH2q0AQ0jbTdr5g5NMeA
$encodedToken->getHeader(); // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
$encodedToken->getPayload(); // eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
$encodedToken->getSignature(); // g0nxZDyzNvuhhuPrpwZFNdtGH2q0AQ0jbTdr5g5NMeA

echo $encodedToken // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.g0nxZDyzNvuhhuPrpwZFNdtGH2q0AQ0jbTdr5g5NMeA
```
## Decoding
```php
$jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.g0nxZDyzNvuhhuPrpwZFNdtGH2q0AQ0jbTdr5g5NMeA';

$decodedToken = \JsonWebToken\JWT::decode($jwtToken, 'your-passphrase-or-key');

$decodedToken->getHeader(); // array
$decodedToken->getPayload(); // array
$decodedToken->isValid(); // bool
```

## Supported algorithms

| Algorithm | Supported |
|-----------|-----------|
| HS256     | ✔️       |
| HS384     | ✔️       |
| HS512     | ✔️       |
 | PS256     | ❌        |
| PS384     | ❌        |
| PS512     | ❌        |
 | RS256     | ✔️       |
 | RS384     | ✔️       |
 | RS512     | ✔️       |
 | ES256     | ❌        |
 | ES256K    | ❌        |
 | ES384     | ❌        |
 | ES512     | ❌        |
 | EdDSA     | ❌        |