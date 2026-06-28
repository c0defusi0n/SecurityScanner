<?php
namespace C0defusi0n\SecurityScanner\Model\Notification;

use Magento\Framework\Notification\MessageInterface;
use Magento\Framework\Escaper;
use C0defusi0n\SecurityScanner\Helper\VulnFeed;

/**
 * Renders the latest Magento vulnerabilities as a Magento "system message" — the dismissible bar
 * shown at the top of every admin page, alongside the native system notifications. Reads the
 * cached feed only (no network on page render). All dynamic text is escaped: the feed content is
 * untrusted (remote / AI-generated).
 */
class VulnSystemMessage implements MessageInterface
{
    /** @var array[]|null */
    private $cache;

    /**
     * @param VulnFeed $feed
     * @param Escaper $escaper
     */
    public function __construct(
        private VulnFeed $feed,
        private Escaper $escaper
    ) {}

    /**
     * Stable per content: a changed item set yields a new identity so a dismissed bar reappears
     * when fresh vulnerabilities arrive.
     *
     * @return string
     */
    public function getIdentity()
    {
        $ids = array_map(function ($i) { return $i['id']; }, $this->items());
        return 'c0defusi0n_security_vuln_' . md5(implode(',', $ids));
    }

    /**
     * @return bool
     */
    public function isDisplayed()
    {
        return $this->feed->isEnabled() && !empty($this->items());
    }

    /**
     * @return \Magento\Framework\Phrase|string
     */
    public function getText()
    {
        $items = $this->items();
        $count = count($items);
        $top = $items[0] ?? ['title' => '', 'id' => '', 'url' => ''];

        $label = $top['id'] !== '' ? $top['id'] . ' — ' . $top['title'] : $top['title'];
        $text = $this->escaper->escapeHtml(
            sprintf('Security Scanner: %d Magento vulnerability item(s). Latest: %s', $count, $label)
        );
        if (!empty($top['url'])) {
            $text .= ' <a href="' . $this->escaper->escapeUrl($top['url'])
                . '" target="_blank" rel="noopener noreferrer">'
                . $this->escaper->escapeHtml(__('details')) . '</a>';
        }
        return $text;
    }

    /**
     * Critical if any current item is critical, otherwise a major notice.
     *
     * @return int
     */
    public function getSeverity()
    {
        foreach ($this->items() as $item) {
            if ($item['severity'] === 'critical') {
                return self::SEVERITY_CRITICAL;
            }
        }
        return self::SEVERITY_MAJOR;
    }

    /**
     * @return array[]
     */
    private function items()
    {
        if ($this->cache === null) {
            $this->cache = $this->feed->getItems();
        }
        return $this->cache;
    }
}
