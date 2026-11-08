<?php

declare(strict_types=1);

namespace JASSI;

use JsonException;
use RuntimeException;

/**
 * Minimal PHP client for the JAS-SI REST API.
 * It evaluates authorization and submits evidence; it never executes actions.
 */
final class Client
{
    private string $baseUrl;
    private string $apiKey;
    private int $timeoutSeconds;

    public function __construct(string $baseUrl, string $apiKey, int $timeoutSeconds = 15)
    {
        $baseUrl = rtrim(trim($baseUrl), '/');
        if ($baseUrl === '' || !filter_var($baseUrl, FILTER_VALIDATE_URL)) {
            throw new RuntimeException('A valid JAS-SI API base URL is required.');
        }
        $scheme = parse_url($baseUrl, PHP_URL_SCHEME);
        $host = parse_url($baseUrl, PHP_URL_HOST);
        if ($scheme !== 'https' && !in_array($host, ['localhost', '127.0.0.1'], true)) {
            throw new RuntimeException('HTTPS is required except for localhost development.');
        }
        if ($apiKey === '') {
            throw new RuntimeException('A non-empty JAS-SI API key is required.');
        }
        if ($timeoutSeconds < 1 || $timeoutSeconds > 120) {
            throw new RuntimeException('Timeout must be between 1 and 120 seconds.');
        }
        if (!extension_loaded('curl')) {
            throw new RuntimeException('The PHP cURL extension (ext-curl) is required.');
        }

        $this->baseUrl = $baseUrl;
        $this->apiKey = $apiKey;
        $this->timeoutSeconds = $timeoutSeconds;
    }

    /** @return array<string, mixed> */
    public function authorize(string $actionId, string $action, string $resource): array
    {
        return $this->post('/v1/authorize', [
            'action_id' => $actionId,
            'action' => $action,
            'resource' => $resource,
        ]);
    }

    /**
     * Caller-submitted evidence is not independently validated by this method.
     * @return array<string, mixed>
     */
    public function verify(
        string $actionId,
        bool $claimedSuccess,
        ?string $observedState = null,
        ?string $evidenceRef = null
    ): array {
        if (($observedState === null) !== ($evidenceRef === null)) {
            throw new RuntimeException(
                'observedState and evidenceRef must both be provided or both be null.'
            );
        }

        $payload = [
            'action_id' => $actionId,
            'claimed_success' => $claimedSuccess,
        ];
        if ($observedState !== null && $evidenceRef !== null) {
            $payload['observed_state'] = $observedState;
            $payload['evidence_ref'] = $evidenceRef;
        }
        return $this->post('/v1/verify', $payload);
    }

    /**
     * Verifies GitHub file integrity at an immutable commit; not semantic truth.
     * @param list<string> $paths
     * @return array<string, mixed>
     */
    public function verifyGithubEvidence(string $repository, string $commitSha, array $paths): array
    {
        if (count($paths) < 1 || count($paths) > 10) {
            throw new RuntimeException('Between 1 and 10 evidence paths are required.');
        }
        return $this->post('/v1/github/evidence', [
            'repository' => $repository,
            'commit_sha' => $commitSha,
            'paths' => array_values($paths),
        ]);
    }

    /** @param array<string, mixed> $payload
     *  @return array<string, mixed>
     */
    private function post(string $path, array $payload): array
    {
        try {
            $body = json_encode($payload, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('Could not encode JAS-SI request JSON.', 0, $exception);
        }

        $handle = curl_init($this->baseUrl . $path);
        if ($handle === false) {
            throw new RuntimeException('Could not initialize HTTP client.');
        }
        curl_setopt_array($handle, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Accept: application/json',
                'X-API-Key: ' . $this->apiKey,
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => min(10, $this->timeoutSeconds),
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $responseBody = curl_exec($handle);
        $curlError = curl_error($handle);
        $statusCode = (int) curl_getinfo($handle, CURLINFO_HTTP_CODE);
        curl_close($handle);

        if ($responseBody === false) {
            throw new RuntimeException('JAS-SI transport error: ' . $curlError);
        }
        try {
            $decoded = json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException(
                'JAS-SI returned non-JSON response (HTTP ' . $statusCode . ').',
                0,
                $exception
            );
        }
        if (!is_array($decoded)) {
            throw new RuntimeException('JAS-SI returned an unexpected response shape.');
        }
        if ($statusCode < 200 || $statusCode >= 300) {
            $detail = $decoded['detail'] ?? ('HTTP ' . $statusCode);
            if (is_array($detail)) {
                $detail = json_encode($detail);
            }
            throw new RuntimeException(
                'JAS-SI API error (' . $statusCode . '): ' . (string) $detail,
                $statusCode
            );
        }
        return $decoded;
    }
}
