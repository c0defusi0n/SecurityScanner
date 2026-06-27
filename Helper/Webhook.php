<?php
namespace C0defusi0n\SecurityScanner\Helper;

use Magento\Framework\App\Helper\AbstractHelper;
use Magento\Framework\App\Helper\Context;
use Magento\Framework\HTTP\Client\Curl;
use Psr\Log\LoggerInterface;

/**
 * Generic incoming-webhook sender (Slack, Discord, Teams, Mattermost, Google Chat,
 * ntfy.sh, ...). One payload fits all the JSON receivers; ntfy gets a plain body.
 */
class Webhook extends AbstractHelper
{
    const XML_PATH_ENABLED = 'security_scanner/webhook_notification/enabled';
    const XML_PATH_URL = 'security_scanner/webhook_notification/url';

    /**
     * @param Context $context
     * @param Curl $curl
     * @param LoggerInterface $logger
     */
    public function __construct(
        Context $context,
        protected Curl $curl,
        protected LoggerInterface $logger
    ) {
        parent::__construct($context);
    }

    /**
     * POSTs a plain-text message to a webhook URL.
     *
     * @param string $url
     * @param string $message
     * @return bool true on a 2xx response
     */
    public function send($url, $message)
    {
        if (empty($url)) {
            $this->logger->warning('Webhook notification enabled but no URL configured');
            return false;
        }

        // Only http(s) is ever a valid webhook target. Reject file://, gopher://, etc. that could
        // be smuggled through the admin/test param. We deliberately do NOT block private/loopback
        // hosts: a self-hosted Slack/Mattermost/ntfy on an internal IP is a legitimate, documented
        // target, so an IP-range block would break real setups. The endpoint is admin-only anyway.
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if (!in_array($scheme, ['http', 'https'], true)) {
            $this->logger->warning('Webhook notification rejected: unsupported URL scheme');
            return false;
        }

        try {
            if (stripos($url, 'ntfy') !== false) {
                // ntfy takes the raw body as the message text (Title/Tags via headers).
                $this->curl->addHeader('Content-Type', 'text/plain');
                $this->curl->addHeader('Title', 'Magento Security Scanner');
                $this->curl->addHeader('Tags', 'shield');
                $this->curl->post($url, $message);
            } else {
                // ponytail: one payload for all JSON targets — Slack/Teams/Mattermost/Google Chat read
                // "text", Discord reads "content"; each ignores the key it doesn't use. Add a per-format
                // adapter only if a target needs blocks/embeds.
                $this->curl->addHeader('Content-Type', 'application/json');
                $this->curl->post($url, json_encode([
                    'text' => $message,
                    'content' => $message,
                    // Discord: never expand @everyone/@here/role pings injected via scanned content.
                    'allowed_mentions' => ['parse' => []],
                ]));
            }

            $status = $this->curl->getStatus();
            if ($status >= 200 && $status < 300) {
                $this->logger->info('Webhook notification sent (HTTP ' . $status . ')');
                return true;
            }
            // Log status only — the remote body is untrusted (log injection / unbounded inflation).
            $this->logger->error('Webhook notification failed: HTTP ' . $status);
            return false;
        } catch (\Exception $e) {
            $this->logger->error('Exception when sending webhook notification: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Sends a test message and reports the outcome (used by the admin test button).
     *
     * @param string $url
     * @return array{success: bool, message: string}
     */
    public function testConnection($url)
    {
        if (empty($url)) {
            return ['success' => false, 'message' => 'A webhook URL is required.'];
        }

        $ok = $this->send($url, "✅ Test from Magento Security Scanner — your webhook is working.");

        return $ok
            ? ['success' => true, 'message' => 'Test message sent. Check your webhook destination.']
            : ['success' => false, 'message' => 'Failed to deliver the test message. Check the URL and system logs.'];
    }
}
