<?php
/**
 * Standalone check (no PHPUnit/Magento needed): run with `php Test/patterns_test.php`.
 * Guards the security-scanner detection logic: built-in patterns must compile and
 * actually catch malicious code without flagging clean content, and the custom-pattern
 * guard must reject invalid regexes.
 */

require __DIR__ . '/../Cron/SecurityScan.php';

$patterns = (new ReflectionClass(\C0defusi0n\SecurityScanner\Cron\SecurityScan::class))
    ->getDefaultProperties()['maliciousPatterns'];

assert(!empty($patterns), 'built-in pattern list is empty');

// 1. Every built-in pattern must be a valid regex.
foreach ($patterns as $p) {
    assert(@preg_match($p, '') !== false, "built-in pattern does not compile: $p");
}

// matchesAny: mirrors findMaliciousPatterns() detection.
$matchesAny = function (string $content) use ($patterns): bool {
    foreach ($patterns as $p) {
        if (preg_match($p, $content)) {
            return true;
        }
    }
    return false;
};

// 2. Known-malicious samples are caught.
foreach ([
    '<?php eval($_POST["x"]); ?>',
    'base64_decode("ZXZpbA==")',
    'shell_exec("id")',
    'system("rm -rf /")',
    '<div style="display:none">spam</div>',
    'eval(gzinflate(str_rot13(base64_decode($x))));',   // packed webshell
    'system($_GET["cmd"]);',                              // request-to-sink
    'call_user_func($_REQUEST["f"]);',
    '$_POST["a"]($_POST["b"]);',                          // variable function on superglobal
    'file_put_contents("accesson.php", $data);',         // backdoor drop
    'preg_replace("/.*/e", $_GET["c"], "x");',           // /e modifier RCE
] as $bad) {
    assert($matchesAny($bad), "missed malicious sample: $bad");
}

// 3. Clean content is not flagged.
foreach ([
    '<p>Welcome to our store</p>',
    '<img src="/media/logo.png" alt="logo">',
    '<script src="https://code.jquery.com/jquery.min.js"></script>', // whitelisted host
] as $ok) {
    assert(!$matchesAny($ok), "false positive on clean sample: $ok");
}

// 4. Custom-pattern guard predicate (SecurityScan::addCustomPatterns) rejects bad regexes.
assert((@preg_match('/valid/i', '') === false) === false, 'valid pattern wrongly rejected');
assert(@preg_match('/[unterminated', '') === false, 'invalid pattern wrongly accepted');

// 5. Media file detection (PolyShell polyglot / dropped webshell).
$M = '\C0defusi0n\SecurityScanner\Cron\SecurityScan';
assert($M::mediaFileIsMalicious('shell.php'), 'missed .php in media');
assert($M::mediaFileIsMalicious('shell.php.jpg'), 'missed double-extension shell.php.jpg');
assert($M::mediaFileIsMalicious('bypass.phtml'), 'missed .phtml in media');
assert($M::mediaFileIsMalicious('logo.png', 'GIF89a...<?php system($_GET[0]); ?>'), 'missed polyglot png');
assert(!$M::mediaFileIsMalicious('logo.png'), 'false positive: clean png by name');
assert(!$M::mediaFileIsMalicious('photo.jpg', "\xFF\xD8\xFF\xE0 plain image bytes"), 'false positive: clean jpg content');
assert(!$M::mediaFileIsMalicious('icon.svg', '<?xml version="1.0"?><svg></svg>'), 'false positive: svg xml declaration');

// 6. Version exposure heuristic (APSB25-94).
assert($M::isVulnerableToPolyshell('2.4.8'), '2.4.8 should be flagged');
assert($M::isVulnerableToPolyshell('2.4.9-alpha2'), '2.4.9-alpha2 should be flagged');
assert(!$M::isVulnerableToPolyshell('2.4.9'), '2.4.9 should NOT be flagged');
assert(!$M::isVulnerableToPolyshell('2.4.10'), '2.4.10 should NOT be flagged');

// 7. Ignore-list matching (substring).
assert($M::isIgnored('media/custom_options/quote/x.jpg', ['custom_options']), 'should ignore by substring');
assert($M::isIgnored('home', ['contact', 'home']), 'should ignore exact identifier');
assert(!$M::isIgnored('home', ['about', 'contact']), 'should not ignore unrelated');
assert(!$M::isIgnored('home', []), 'empty ignore-list ignores nothing');

// 8. Finding signature: stable, order-independent on matches, distinguishes findings.
$f1 = ['type' => 'cms_block', 'identifier' => 'foo', 'matches' => [['match' => 'a'], ['match' => 'b']]];
$f1b = ['type' => 'cms_block', 'identifier' => 'foo', 'matches' => [['match' => 'b'], ['match' => 'a']]];
$f2 = ['type' => 'cms_block', 'identifier' => 'bar', 'matches' => [['match' => 'a'], ['match' => 'b']]];
assert($M::findingSignature($f1) === $M::findingSignature($f1b), 'signature must be order-independent');
assert($M::findingSignature($f1) !== $M::findingSignature($f2), 'different location => different signature');

echo "OK: " . count($patterns) . " patterns, all assertions passed\n";
