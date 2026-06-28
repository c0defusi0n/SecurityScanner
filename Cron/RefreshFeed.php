<?php
namespace C0defusi0n\SecurityScanner\Cron;

use Psr\Log\LoggerInterface;
use Magento\Framework\Notification\NotifierInterface;
use Magento\Framework\FlagManager;
use C0defusi0n\SecurityScanner\Helper\VulnFeed;
use C0defusi0n\SecurityScanner\Helper\Signatures;

/**
 * Hourly maintenance cron for the remote data sources. Keeps the network work OUT of admin page
 * loads and the scan: it refreshes the vulnerability feed and pushes any newly-seen items into the
 * admin notification inbox (the bell), and pre-warms the remote signature cache so the next scan
 * starts from a fresh copy without paying the download itself.
 */
class RefreshFeed
{
    /**
     * Flag holding the ids of feed items already pushed to the admin inbox, so each vulnerability
     * is notified once rather than every hour.
     */
    const FLAG_SEEN_VULNS = 'c0defusi0n_security_scanner_seen_vulns';

    /** Cap the persisted seen-id set so it cannot grow unbounded. */
    const MAX_SEEN = 500;

    /**
     * @param LoggerInterface $logger
     * @param NotifierInterface $notifier
     * @param FlagManager $flagManager
     * @param VulnFeed $vulnFeed
     * @param Signatures $signatures
     */
    public function __construct(
        protected LoggerInterface $logger,
        protected NotifierInterface $notifier,
        protected FlagManager $flagManager,
        protected VulnFeed $vulnFeed,
        protected Signatures $signatures
    ) {}

    /**
     * @return void
     */
    public function execute()
    {
        // Pre-warm the signature cache (fetch-if-stale) so the scan does not pay the download.
        try {
            $this->signatures->getPatterns();
        } catch (\Exception $e) {
            $this->logger->error('SecurityScanner: signature pre-warm failed: ' . $e->getMessage());
        }

        if (!$this->vulnFeed->isEnabled()) {
            return;
        }

        try {
            $items = $this->vulnFeed->refresh();
        } catch (\Exception $e) {
            $this->logger->error('SecurityScanner: vulnerability feed refresh failed: ' . $e->getMessage());
            return;
        }

        $seen = (array) ($this->flagManager->getFlagData(self::FLAG_SEEN_VULNS) ?: []);
        $new = 0;
        foreach ($items as $item) {
            $id = $item['id'];
            if (isset($seen[$id])) {
                continue;
            }
            $seen[$id] = true;
            $new++;
            // strip_tags: the feed is untrusted; the inbox renders the description.
            $this->notifier->addNotice(
                strip_tags('Magento vulnerability: ' . $item['title']),
                strip_tags(trim($item['summary'] . ' ' . $item['url'])),
                (string) $item['url']
            );
        }

        if ($new > 0) {
            // Keep only the most recent ids to bound the flag size.
            if (count($seen) > self::MAX_SEEN) {
                $seen = array_slice($seen, -self::MAX_SEEN, null, true);
            }
            $this->flagManager->saveFlag(self::FLAG_SEEN_VULNS, $seen);
            $this->logger->info(sprintf('SecurityScanner: %d new Magento vulnerability item(s) added to the admin inbox', $new));
        }
    }
}
