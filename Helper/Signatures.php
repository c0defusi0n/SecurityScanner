<?php
namespace C0defusi0n\SecurityScanner\Helper;

use Magento\Framework\App\Helper\AbstractHelper;
use Magento\Framework\App\Helper\Context;
use Magento\Store\Model\ScopeInterface;
use Psr\Log\LoggerInterface;

/**
 * Optional remote signature database ("antivirus definitions" model). When enabled, an
 * admin-configured JSON document of regex patterns is fetched (and cached) before a scan and
 * merged ON TOP OF the built-in patterns — it never replaces them, so detection still works
 * offline and the module ships a guaranteed baseline. Update the remote repo to ship new
 * detection without releasing the module.
 *
 * Expected JSON shape:
 *   { "version": "2026-06-27",
 *     "patterns": [ { "id": "...", "severity": "...", "regex": "/.../i", "description": "..." } ] }
 */
class Signatures extends AbstractHelper
{
    const XML_PATH_ENABLED = 'security_scanner/remote_signatures/enabled';
    const XML_PATH_URL = 'security_scanner/remote_signatures/url';
    const XML_PATH_INTERVAL = 'security_scanner/remote_signatures/update_interval';

    /**
     * Hard ceiling on how many remote patterns are merged into the scan. The body is already
     * size-capped, but 1 MB of JSON can hold tens of thousands of tiny valid regexes; running
     * each over every CMS/config source on every scan is a CPU amplifier driven by the remote
     * document, so bound it (generous for a real signature DB).
     */
    const MAX_PATTERNS = 1000;

    /**
     * @param Context $context
     * @param RemoteFetcher $fetcher
     * @param LoggerInterface $logger
     */
    public function __construct(
        Context $context,
        protected RemoteFetcher $fetcher,
        protected LoggerInterface $logger
    ) {
        parent::__construct($context);
    }

    /**
     * @return bool
     */
    public function isEnabled()
    {
        return $this->scopeConfig->isSetFlag(self::XML_PATH_ENABLED, ScopeInterface::SCOPE_STORE);
    }

    /**
     * Returns the validated remote regex patterns to merge into the scan. Fetches if the cache is
     * stale (honouring the configured interval); returns [] when disabled or on any problem.
     *
     * @return string[]
     */
    public function getPatterns()
    {
        if (!$this->isEnabled()) {
            return [];
        }

        $url = (string) $this->scopeConfig->getValue(self::XML_PATH_URL);
        $interval = (int) $this->scopeConfig->getValue(self::XML_PATH_INTERVAL) ?: 24;
        $data = $this->fetcher->fetch($url, 'signatures', $interval);

        return self::extractPatterns($data, $this->logger);
    }

    /**
     * Validates and flattens a decoded signatures document into usable regex strings. Pure (the
     * logger is optional) so it can be unit-tested. Each pattern must compile, or it is skipped —
     * a bad remote regex must never break the scan.
     *
     * @param array|null $data
     * @param LoggerInterface|null $logger
     * @return string[]
     */
    public static function extractPatterns($data, $logger = null)
    {
        if (!is_array($data) || empty($data['patterns']) || !is_array($data['patterns'])) {
            return [];
        }

        $out = [];
        foreach ($data['patterns'] as $entry) {
            if (is_string($entry)) {
                $regex = $entry;
            } elseif (is_array($entry) && isset($entry['regex'])) {
                $regex = $entry['regex'];
            } else {
                continue;
            }
            $regex = trim((string) $regex);
            if ($regex === '') {
                continue;
            }
            // Reject anything that does not compile, exactly like admin custom patterns.
            if (@preg_match($regex, '') === false) {
                if ($logger) {
                    // Sanitize: the regex is remote-controlled — strip CR/LF and truncate so a
                    // hostile feed cannot forge or split lines in the log.
                    $logger->warning('SecurityScanner: invalid remote signature ignored: '
                        . substr(str_replace(["\r", "\n"], ' ', $regex), 0, 200));
                }
                continue;
            }
            $out[] = $regex;
            if (count($out) >= self::MAX_PATTERNS) {
                if ($logger) {
                    $logger->warning('SecurityScanner: remote signature cap reached ('
                        . self::MAX_PATTERNS . '); extra patterns ignored');
                }
                break;
            }
        }

        return $out;
    }
}
