<?php

declare(strict_types=1);

namespace JsonWebToken\Command;

use JsonWebToken\Service\JsonWebTokenService;
use Symfony\Component\Console\Command\Command;

abstract class AbstractCommand extends Command
{
    protected JsonWebTokenService $service;

    public function __construct(?JsonWebTokenService $service = null)
    {
        $this->service = $service ?? new JsonWebTokenService();

        parent::__construct();
    }
}
