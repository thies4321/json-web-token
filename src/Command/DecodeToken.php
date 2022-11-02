<?php

declare(strict_types=1);

namespace JsonWebToken\Command;

use JsonWebToken\Exception\InvalidSignatureException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use function array_map;
use function sprintf;

#[AsCommand(
    name: 'token:decode',
    description: 'Decode a token',
)]
final class DecodeToken extends AbstractCommand
{
    protected function configure(): void
    {
        $this->addArgument('token', InputArgument::REQUIRED, 'JWT token to decode');
        $this->addArgument('secret', InputArgument::REQUIRED, 'Passphrase/key to encode with');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $token = $input->getArgument('token');
        $secret = $input->getArgument('secret');

        try {
            $decodedToken = $this->service->decode($token, $secret);
        } catch (InvalidSignatureException $exception) {
            $output->writeln('<error>Failed to verify signature</error>');
            return self::FAILURE;
        }

        $output->writeln(sprintf('<comment>Token valid: %s</comment>', $decodedToken->isValid() ? 'Yes' : 'No'));
        $output->writeln('Headers:');

        $table = new Table($output);
        $table->setHeaders(['Type', 'Value']);
        foreach ($decodedToken->getHeader() as $headerType => $headerValue) {
            $table->addRow([$headerType, $headerValue]);
        }
        $table->render();

        $table = new Table($output);
        $table->setHeaders(['Type', 'Value']);
        foreach ($decodedToken->getPayload() as $payloadType => $payloadValue) {
            $table->addRow([$payloadType, $payloadValue]);
        }
        $table->render();

        return self::SUCCESS;
    }
}