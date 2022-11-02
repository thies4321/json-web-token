<?php

declare(strict_types=1);

namespace JsonWebToken\Encoder;

use JsonWebToken\Entity\EncodedToken;

interface Encoder
{
    public function encode(): EncodedToken;
}
