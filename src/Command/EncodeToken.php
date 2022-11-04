<?php

declare(strict_types=1);

namespace JsonWebToken\Command;

use JsonException;
use JsonWebToken\Exception\AlgorithmNotSupported;
use JsonWebToken\Exception\HeaderNotFoundException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

use function json_decode;
use function sprintf;

use const JSON_THROW_ON_ERROR;

#[AsCommand(
    name: 'token:encode',
    description: 'Encode a token',
)]
final class EncodeToken extends AbstractCommand
{
    protected function configure(): void
    {
        $this->addArgument('header', InputArgument::REQUIRED, 'Headers for token (JSON encoded)');
        $this->addArgument('payload', InputArgument::REQUIRED, 'Payload for token (JSON encoded)');
        $this->addArgument('secret', InputArgument::REQUIRED, 'Passphrase/key to encode with');
    }

    /**
     * @throws AlgorithmNotSupported
     * @throws HeaderNotFoundException
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $encodedHeader = $input->getArgument('header');
        try {
            $header = json_decode($encodedHeader, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            $output->writeln('<error>Header is not valid JSON encoded string</error>');
            return self::INVALID;
        }

        $encodedPayload = $input->getArgument('payload');
        try {
            $payload = json_decode($encodedPayload, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            $output->writeln('<error>Payload is not valid JSON encoded string</error>');
            return self::INVALID;
        }

        $secret = $input->getArgument('secret');

        $token = $this->service->encode($header, $payload, $secret);

        $output->writeln(sprintf('Token: <info>%s</info>', $token));
        return self::SUCCESS;
    }
}