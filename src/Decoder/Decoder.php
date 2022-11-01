<?php

declare(strict_types=1);

namespace JsonWebToken\Decoder;

use JsonWebToken\Entity\DecodedToken;

interface Decoder
{
    public function decode(): DecodedToken;
}