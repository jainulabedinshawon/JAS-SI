<?php

declare(strict_types=1);

require dirname(__DIR__, 3) . '/vendor/autoload.php';

use JASSI\Client;

$client = new Client(
    getenv('JAS_SI_API_URL') ?: '',
    getenv('JAS_SI_API_KEY') ?: ''
);

$decision = $client->authorize(
    'example-action-001',
    'deploy',
    'staging/example-app'
);

echo json_encode($decision, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), PHP_EOL;

// Enforce the decision in your own application before doing any work.
if (($decision['allowed'] ?? false) !== true) {
    exit(1);
}
