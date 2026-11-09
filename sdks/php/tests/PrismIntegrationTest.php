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

        self::assertIsString($response['action_id'] ?? null);
        self::assertArrayHasKey('allowed', $response);
        self::assertIsBool($response['allowed']);
        self::assertArrayHasKey('reason', $response);
        self::assertFalse($response['executed'] ?? true);
    }

    public function testVerifyParsesOpenApiSuccessExample(): void
    {
        $response = $this->client->verify('deploy-2026-001', true);

        self::assertSame('deploy-2026-001', $response['action_id'] ?? null);
        self::assertArrayHasKey('status', $response);
        self::assertArrayHasKey('reason', $response);
        self::assertContains($response['evidence_origin'] ?? null, ['caller_submitted', 'not_provided']);
        self::assertArrayNotHasKey('independently_verified', $response);
    }

    public function testGithubEvidenceParsesOpenApiSuccessExample(): void
    {
        $response = $this->client->verifyGithubEvidence(
            'owner/repository',
            str_repeat('a', 40),
            ['README.md']
        );

        self::assertSame('JAS-SI Verify', $response['service'] ?? null);
        self::assertIsString($response['repository'] ?? null);
        self::assertSame('EVIDENCE_INTEGRITY_VERIFIED', $response['status'] ?? null);
        self::assertSame(1, $response['files_verified'] ?? null);
        self::assertIsArray($response['files'] ?? null);
        self::assertFalse($response['semantic_truth_verified'] ?? true);
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
