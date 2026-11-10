<?php

declare(strict_types=1);

namespace JASSI\Tests;

use JASSI\Client;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ClientTest extends TestCase
{
    public function testRejectsAnEmptyApiKey(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('A non-empty JAS-SI API key is required.');

        new Client('https://api.example.test', '');
    }

    public function testRejectsInsecureNonLocalhostUrl(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('HTTPS is required');

        new Client('http://api.example.test', 'test-key');
    }

    public function testAllowsHttpForLocalDevelopment(): void
    {
        self::expectNotToPerformAssertions();

        new Client('http://localhost:8080', 'test-key');
    }

    public function testRejectsTimeoutOutsideSupportedRange(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Timeout must be between 1 and 120 seconds.');

        new Client('https://api.example.test', 'test-key', 121);
    }

    public function testRequiresObservedStateAndEvidenceReferenceTogether(): void
    {
        $client = new Client('https://api.example.test', 'test-key');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('observedState and evidenceRef must both be provided');

        $client->verify('action-1', true, 'completed', null);
    }

    public function testRequiresAtLeastOneGithubEvidencePath(): void
    {
        $client = new Client('https://api.example.test', 'test-key');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Between 1 and 10 evidence paths are required.');

        $client->verifyGithubEvidence('owner/repo', str_repeat('a', 40), []);
    }

    public function testRejectsMoreThanTenGithubEvidencePaths(): void
    {
        $client = new Client('https://api.example.test', 'test-key');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Between 1 and 10 evidence paths are required.');

        $client->verifyGithubEvidence(
            'owner/repo',
            str_repeat('a', 40),
            array_fill(0, 11, 'README.md')
        );
    }
}
