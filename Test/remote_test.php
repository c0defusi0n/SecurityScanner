<?php
/**
 * Standalone check (no PHPUnit/Magento): run with `php Test/remote_test.php`.
 * Guards the pure parsing/validation of the remote signature DB and the vulnerability feed —
 * the untrusted-data boundary for the "antivirus definitions" and admin-news features.
 *
 * The helpers extend Magento's AbstractHelper; we stub just that base so the files load and the
 * static methods can be exercised without a Magento bootstrap (only `extends` resolves at load).
 */

namespace Magento\Framework\App\Helper {
    if (!class_exists(AbstractHelper::class, false)) {
        class AbstractHelper
        {
            public function __construct() {}
        }
    }
}

namespace {
    require __DIR__ . '/../Helper/Signatures.php';
    require __DIR__ . '/../Helper/VulnFeed.php';

    $S = '\C0defusi0n\SecurityScanner\Helper\Signatures';
    $F = '\C0defusi0n\SecurityScanner\Helper\VulnFeed';

    // 1. Signatures: keep valid regexes (object or bare string), drop the rest.
    $patterns = $S::extractPatterns([
        'patterns' => [
            ['id' => 'a', 'regex' => '/eval\s*\(/i'],   // valid object
            ['id' => 'b', 'regex' => '/[unterminated'],  // invalid regex -> dropped
            ['id' => 'c'],                               // no regex -> dropped
            '/base64_decode/i',                          // valid bare string
            123,                                         // junk -> dropped
            ['regex' => '   '],                          // blank -> dropped
        ],
    ]);
    assert($patterns === ['/eval\s*\(/i', '/base64_decode/i'], 'extractPatterns must keep only valid regexes');
    assert($S::extractPatterns(null) === [], 'null document => no patterns');
    assert($S::extractPatterns(['nope' => 1]) === [], 'missing patterns key => no patterns');

    // 2. Vulnerability feed: validate, default and cap.
    $items = $F::normalizeItems([
        'items' => [
            ['id' => 'APSB25-94', 'title' => 'RCE', 'severity' => 'CRITICAL', 'url' => 'https://adobe.com/x'],
            ['title' => 'No id, bad scheme', 'severity' => 'weird', 'url' => 'javascript:alert(1)'],
            ['severity' => 'high'],                       // no title -> dropped
        ],
    ], 10);
    assert(count($items) === 2, 'two valid items kept (the one without a title is dropped)');
    assert($items[0]['severity'] === 'critical', 'severity is lowercased');
    assert($items[0]['url'] === 'https://adobe.com/x', 'valid https url kept');
    assert($items[1]['url'] === '', 'non-http(s) url dropped');
    assert($items[1]['severity'] === 'medium', 'unknown severity defaults to medium');
    assert($items[1]['id'] !== '', 'missing id is synthesised');

    // 3. Cap is enforced.
    $many = ['items' => []];
    for ($i = 0; $i < 20; $i++) {
        $many['items'][] = ['title' => 'v' . $i];
    }
    assert(count($F::normalizeItems($many, 5)) === 5, 'max items cap enforced');
    assert($F::normalizeItems(null) === [], 'null feed => no items');

    // 4. Signature pattern-count cap bounds a hostile/oversized feed.
    $big = ['patterns' => array_fill(0, $S::MAX_PATTERNS + 50, '/a/')];
    assert(count($S::extractPatterns($big)) === $S::MAX_PATTERNS, 'remote pattern count cap enforced');

    echo "OK: remote signature + vuln-feed parsing assertions passed\n";
}
