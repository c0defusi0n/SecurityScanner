<?php
namespace C0defusi0n\SecurityScanner\Helper;

use Magento\Framework\App\Helper\AbstractHelper;
use Magento\Framework\App\Helper\Context;
use Magento\Store\Model\ScopeInterface;
use Psr\Log\LoggerInterface;

/**
 * Magento vulnerability watch feed. An admin-configured JSON document lists the latest Magento /
 * Adobe Commerce security items; the module caches it and surfaces them in the admin (system
 * message bar + notification inbox). The feed is expected to be produced out-of-band (e.g. an
 * AI job that aggregates Adobe APSB / NVD / Sansec and commits JSON to a repo) — the module only
 * consumes it, so the producer is fully swappable.
 *
 * Expected JSON shape:
 *   { "updated": "2026-06-27T08:00:00Z",
 *     "items": [ { "id": "APSB25-94", "severity": "critical", "title": "...",
 *                  "published": "2025-..", "url": "https://...", "summary": "..." } ] }
 */
class VulnFeed extends AbstractHelper
{
    const XML_PATH_ENABLED = 'security_scanner/vuln_feed/enabled';
    const XML_PATH_URL = 'security_scanner/vuln_feed/url';
    const XML_PATH_INTERVAL = 'security_scanner/vuln_feed/update_interval';
    const XML_PATH_MAX_ITEMS = 'security_scanner/vuln_feed/max_items';

    /**
     * Safety bound on items processed for inbox notifications, decoupled from the admin DISPLAY
     * cap (max_items): every new vulnerability should reach the inbox even if only the top few
     * are shown in the system-message bar.
     */
    const NOTIFY_CAP = 200;

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
     * Network refresh (used by cron). Fetches if stale and returns the normalized items.
     *
     * @return array[]
     */
    public function refresh()
    {
        if (!$this->isEnabled()) {
            return [];
        }
        $url = (string) $this->scopeConfig->getValue(self::XML_PATH_URL);
        $interval = (int) $this->scopeConfig->getValue(self::XML_PATH_INTERVAL) ?: 1;
        // NOTIFY_CAP (not the display cap) so every new item can be deduped/notified by the cron.
        return self::normalizeItems($this->fetcher->fetch($url, 'vuln_feed', $interval), self::NOTIFY_CAP);
    }

    /**
     * Cache-only read (used by admin display paths). Never performs a network call.
     *
     * @return array[]
     */
    public function getItems()
    {
        if (!$this->isEnabled()) {
            return [];
        }
        // Display path: capped to the admin's max_items for the system-message bar.
        return self::normalizeItems($this->fetcher->readCached('vuln_feed'), $this->getMaxItems());
    }

    /**
     * @return int
     */
    public function getMaxItems()
    {
        return (int) $this->scopeConfig->getValue(self::XML_PATH_MAX_ITEMS) ?: 10;
    }

    /**
     * Validates, cleans and caps a decoded feed document. Output fields are plain strings; callers
     * are responsible for escaping at the point of rendering. Drops a non-http(s) item URL rather
     * than emitting it. Pure for testability.
     *
     * @param array|null $data
     * @param int $max
     * @return array[]
     */
    public static function normalizeItems($data, $max = 10)
    {
        if (!is_array($data) || empty($data['items']) || !is_array($data['items'])) {
            return [];
        }

        $items = [];
        foreach ($data['items'] as $raw) {
            if (!is_array($raw)) {
                continue;
            }
            $title = trim((string) ($raw['title'] ?? ''));
            if ($title === '') {
                continue;
            }
            $url = trim((string) ($raw['url'] ?? ''));
            $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
            if (!in_array($scheme, ['http', 'https'], true)) {
                $url = '';
            }
            $severity = strtolower((string) ($raw['severity'] ?? ''));
            if (!in_array($severity, ['critical', 'high', 'medium', 'low'], true)) {
                $severity = 'medium';
            }
            $id = trim((string) ($raw['id'] ?? ''));
            $items[] = [
                'id' => $id !== '' ? $id : substr(md5($title), 0, 12),
                'title' => $title,
                'severity' => $severity,
                'published' => trim((string) ($raw['published'] ?? '')),
                'url' => $url,
                'summary' => trim((string) ($raw['summary'] ?? '')),
            ];
            if (count($items) >= max(1, $max)) {
                break;
            }
        }

        return $items;
    }
}
