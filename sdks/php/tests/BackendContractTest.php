<?php

declare(strict_types=1);

namespace JASSI\Tests;

use JASSI\Client;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * These tests call the actual FastAPI application, not an OpenAPI-derived mock.
 * CI starts an isolated test-mode Uvicorn server with a static test-only key.
 */
final class BackendContractTest extends TestCase
{
    private ?Client $client = null;

    protected function setUp(): void
    {
        $baseUrl = getenv('JAS_SI_BACKEND_URL');
        $apiKey = getenv('JAS_SI_BACKEND_API_KEY');

        if (!is_string($baseUrl) || $baseUrl === '' || !is_string($apiKey) || $apiKey === '') {
            self::markTestSkipped('Set JAS_SI_BACKEND_URL and JAS_SI_BACKEND_API_KEY to run FastAPI conformance tests.');
        }

        $this->client = new Client($baseUrl, $apiKey);
    }

    public function testAuthorizeMatchesFastApiWireContractAnd1024CharacterBoundary(): void
    {
        $response = $this->client->authorize(
            'php-backend-authorize',
            'deploy',
            str_repeat('r', 700)
        );

        self::assertSame('php-backend-authorize', $response['action_id'] ?? null);
        self::assertIsBool($response['allowed'] ?? null);
        self::assertIsString($response['reason'] ?? null);
        self::assertArrayHasKey('grant_id', $response);
        self::assertFalse($response['executed'] ?? true);
        self::assertArrayNotHasKey('decision', $response);
    }

    public function testVerifyMatchesFastApiWireContractWithoutClaimingIndependentEvidence(): void
    {
        $response = $this->client->verify('php-backend-verify', true);

        self::assertSame('php-backend-verify', $response['action_id'] ?? null);
        self::assertSame('INCONCLUSIVE', $response['status'] ?? null);
        self::assertIsString($response['reason'] ?? null);
        self::assertSame('not_provided', $response['evidence_origin'] ?? null);
        self::assertArrayNotHasKey('accepted', $response);
        self::assertArrayNotHasKey('independently_verified', $response);
    }

    public function testBackendRejectsObservedStateBeyond256Characters(): void
    {
        try {
            $this->client->verify(
                'php-backend-observed-state-limit',
                true,
                str_repeat('x', 257),
                'https://ci.example.test/run/123'
            );
            self::fail('Expected FastAPI to reject observed_state over 256 characters.');
        } catch (RuntimeException $exception) {
            self::assertSame(422, $exception->getCode());
        }
    }

    public function testBackendRejectsUppercaseGitHubCommitSha(): void
    {
        try {
            $this->client->verifyGithubEvidence(
                'owner/repository',
                str_repeat('A', 40),
                ['README.md']
            );
            self::fail('Expected FastAPI to reject uppercase commit SHA.');
        } catch (RuntimeException $exception) {
            self::assertSame(422, $exception->getCode());
        }
    }

    public function testBackendRejectsGitHubPathLongerThan500Characters(): void
    {
        try {
            $this->client->verifyGithubEvidence(
                'owner/repository',
                str_repeat('a', 40),
                [str_repeat('p', 501)]
            );
            self::fail('Expected FastAPI to reject a path over 500 characters.');
        } catch (RuntimeException $exception) {
            self::assertSame(422, $exception->getCode());
        }
    }

    public function testBackendRejectsDuplicateGitHubPaths(): void
    {
        try {
            $this->client->verifyGithubEvidence(
                'owner/repository',
                str_repeat('a', 40),
                ['README.md', 'README.md']
            );
            self::fail('Expected FastAPI to reject duplicate evidence paths.');
        } catch (RuntimeException $exception) {
            self::assertSame(422, $exception->getCode());
        }
    }
}
