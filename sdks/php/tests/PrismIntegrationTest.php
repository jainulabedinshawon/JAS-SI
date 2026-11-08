<?php

declare(strict_types=1);

namespace JASSI\Tests;

use JASSI\Client;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Runs against the OpenAPI-derived Prism mock when JAS_SI_MOCK_URL is set.
 * The tests are skipped in ordinary local runs without the mock server.
 */
final class PrismIntegrationTest extends TestCase
{
    private ?Client $client = null;

    protected function setUp(): void
    {
        $baseUrl = getenv('JAS_SI_MOCK_URL');
        if (!is_string($baseUrl) || $baseUrl === '') {
            self::markTestSkipped('Set JAS_SI_MOCK_URL to run Prism contract integration tests.');
        }

        $this->client = new Client($baseUrl, 'jas-si-prism-test-key');
    }

    public function testAuthorizeParsesOpenApiSuccessExample(): void
    {
        $response = $this->client->authorize('deploy-2026-001', 'deploy', 'production/my-service');

        self::assertArrayHasKey('allowed', $response);
        self::assertIsBool($response['allowed']);
    }

    public function testVerifyParsesOpenApiSuccessExample(): void
    {
        $response = $this->client->verify('deploy-2026-001', true);

        self::assertArrayHasKey('accepted', $response);
        self::assertIsBool($response['accepted']);
    }

    public function testGithubEvidenceParsesOpenApiSuccessExample(): void
    {
        $response = $this->client->verifyGithubEvidence(
            'owner/repository',
            str_repeat('a', 40),
            ['README.md']
        );

        self::assertSame('owner/repository', $response['repository'] ?? null);
        self::assertIsArray($response['results'] ?? null);
    }

    public function testInvalidAuthorizationRequestSurfacesPrismValidationError(): void
    {
        try {
            $this->client->authorize('', 'deploy', 'production/my-service');
            self::fail('Expected Prism to reject an invalid action_id.');
        } catch (RuntimeException $exception) {
            self::assertSame(422, $exception->getCode());
        }
    }
}
