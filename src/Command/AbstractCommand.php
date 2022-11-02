<?php

declare(strict_types=1);

namespace JsonWebToken\Command;

use JsonWebToken\JWT;
use Symfony\Component\Console\Command\Command;

abstract class AbstractCommand extends Command
{
    protected JWT $service;

    public function __construct(?JWT $service = null)
    {
        $this->service = $service ?? new JWT();

        parent::__construct();
    }
}