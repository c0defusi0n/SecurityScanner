<?php
namespace C0defusi0n\SecurityScanner\Cron;

use Magento\Cms\Model\ResourceModel\Block\CollectionFactory as BlockCollectionFactory;
use Psr\Log\LoggerInterface;
use Magento\Framework\Notification\NotifierInterface;
use Magento\Framework\Mail\Template\TransportBuilder;
use Magento\Store\Model\StoreManagerInterface;
use Magento\Framework\Translate\Inline\StateInterface;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\HTTP\Client\Curl;
use Magento\Framework\App\State;
use Magento\Framework\ObjectManagerInterface;

class SecurityScan
{
    /**
     * @var array
     */

    /**
     * @var array
     */
    protected $maliciousPatterns = [
        // Scripts suspects
        '/\<script.*?src\s*=\s*[\'"]https?:\/\/(?!www\.paypal\.com|www\.googleapis\.com|code\.jquery\.com)[^\'"]+[\'"].*?\>/i',
        '/\<img.*?onload\s*=\s*[\'"].*?(createElement\s*\(\s*[\'"]script[\'"]\)).*?[\'"].*?\>/i',
        '/document\.write\s*\(\s*[\'"].*?<script.*?[\'"].*?\)/i',
        '/eval\s*\(/i',
        '/base64_decode\s*\(/i',

        // Redirections suspectes
        '/window\.location\s*=\s*[\'"]https?:\/\/(?!www\.paypal\.com|www\.googleapis\.com|www\.google\.com)[^\'"]+[\'"].*?\>/i',

        // Fonctions dangereuses de PHP (si utilisées de manière inhabituelle)
        '/\bexec\s*\(/i',
        '/\bshell_exec\s*\(/i',
        '/\bsystem\s*\(/i',
        '/\bpassthru\s*\(/i',
        '/\bproc_open\s*\(/i',

        // Injection de HTML invisible
        '/\<div.*?style\s*=\s*[\'"]display\s*:\s*none.*?[\'"].*?\>/i',

        ];

    /**
     * @param BlockCollectionFactory $blockCollectionFactory
     * @param LoggerInterface $logger
     * @param NotifierInterface $notifier
     * @param TransportBuilder $transportBuilder
     * @param StoreManagerInterface $storeManager
     * @param StateInterface $inlineTranslation
     * @param ScopeConfigInterface $scopeConfig
     * @param Curl $curl
     * @param State $appState
     * @param ObjectManagerInterface $objectManager
     */
    public function __construct(
        protected BlockCollectionFactory $blockCollectionFactory,
        protected LoggerInterface $logger,
        protected NotifierInterface $notifier,
        protected TransportBuilder $transportBuilder,
        protected StoreManagerInterface $storeManager,
        protected StateInterface $inlineTranslation,
        protected ScopeConfigInterface $scopeConfig,
        protected Curl $curl,
        protected State $appState,
        protected ObjectManagerInterface $objectManager
    ) {}

    /**
     * Executes the security scan
     *
     * @return void
     */
    public function execute()
    {
        // Check if the module is enabled
        if (!$this->isModuleEnabled()) {
            return;
        }

        $this->logger->info('Starting C0defusi0n Security Scanner scan (CMS blocks only)');
        $suspiciousBlocks = [];

        // Add custom patterns from configuration
        $this->addCustomPatterns();

        // Analyze CMS blocks
        $this->scanCmsBlocks($suspiciousBlocks);

        if (!empty($suspiciousBlocks)) {
            $this->handleSuspiciousCode($suspiciousBlocks);
        } else {
            $this->logger->info('Security scan completed: no malicious code detected in CMS blocks');

            // Send clean reports if configured
            $this->sendCleanReports();
        }
    }

    /**
     * Checks if the module is enabled
     *
     * @return bool
     */
    protected function isModuleEnabled()
    {
        return $this->scopeConfig->isSetFlag(
            'security_scanner/general/enabled',
            \Magento\Store\Model\ScopeInterface::SCOPE_STORE
        );
    }

    /**
     * Adds custom patterns from configuration
     */
    protected function addCustomPatterns()
    {
        $customPatterns = $this->scopeConfig->getValue(
            'security_scanner/malicious_patterns/custom_patterns',
            \Magento\Store\Model\ScopeInterface::SCOPE_STORE
        );

        if (!empty($customPatterns)) {
            $patterns = explode("\n", $customPatterns);
            foreach ($patterns as $pattern) {
                $pattern = trim($pattern);
                if (!empty($pattern)) {
                    $this->maliciousPatterns[] = $pattern;
                }
            }
        }
    }

    /**
     * Analyzes CMS blocks to detect malicious code
     *
     * @param array $suspiciousBlocks
     * @return void
     */
    protected function scanCmsBlocks(&$suspiciousBlocks)
    {
        $blockCollection = $this->blockCollectionFactory->create();
        foreach ($blockCollection as $block) {
            $content = $block->getContent();
            $matches = $this->findMaliciousPatterns($content);

            if (!empty($matches)) {
                $suspiciousBlocks[] = [
                    'type' => 'cms_block',
                    'id' => $block->getId(),
                    'identifier' => $block->getIdentifier(),
                    'title' => $block->getTitle(),
                    'matches' => $matches
                ];

                $this->logger->warning(
                    sprintf(
                        'Suspicious code detected in CMS block #%s (%s): %s',
                        $block->getId(),
                        $block->getIdentifier(),
                        json_encode($matches)
                    )
                );
            }
        }
    }

    /**
     * Searches for malicious patterns in content
     *
     * @param string $content
     * @return array
     */
    protected function findMaliciousPatterns($content)
    {
        $matches = [];

        foreach ($this->maliciousPatterns as $pattern) {
            if (preg_match_all($pattern, $content, $found)) {
                foreach ($found[0] as $match) {
                    $matches[] = [
                        'pattern' => $pattern,
                        'match' => $match
                    ];
                }
            }
        }

        return $matches;
    }

    /**
     * Handles detected suspicious blocks
     *
     * @param array $suspiciousBlocks
     * @return void
     */
    protected function handleSuspiciousCode($suspiciousBlocks)
    {
        // Logging
        $this->logger->critical(
            sprintf(
                'Security scan completed: %d suspicious CMS blocks detected',
                count($suspiciousBlocks)
            )
        );

        // Notification dans l'admin
        $this->notifier->addCritical(
            'Security Alert',
            sprintf(
                '%d suspicious CMS blocks detected by C0defusi0n Security Scanner. Please check the log for more details.',
                count($suspiciousBlocks)
            )
        );

        // Send notifications
        $this->sendEmailNotification($suspiciousBlocks);
        $this->sendTelegramNotification($suspiciousBlocks);
    }

    /**
     * Sets the area code for email sending operations
     */
    protected function setAreaCode()
    {
        try {
            $this->appState->setAreaCode(\Magento\Framework\App\Area::AREA_ADMINHTML);
        } catch (\Exception $e) {
            // Area code is already defined, no need to do anything
        }
    }

    /**
     * Sends an alert email
     *
     * @param array $suspiciousBlocks
     * @return void
     */
    /**
     * Sends an alert email
     *
     * @param array $suspiciousBlocks
     * @return void
     */
    protected function sendEmailNotification($suspiciousBlocks)
    {
        // Check if email notifications are enabled
        if (!$this->scopeConfig->isSetFlag('security_scanner/email_notification/enabled')) {
            return;
        }

        try {
            // Set the area code to avoid the "Area code is not set" error
            $this->setAreaCode();

            $storeId = $this->storeManager->getStore()->getId();
            $recipients = $this->scopeConfig->getValue(
                'security_scanner/email_notification/recipients',
                \Magento\Store\Model\ScopeInterface::SCOPE_STORE,
                $storeId
            );

            if (empty($recipients)) {
                $this->logger->warning('No email recipient configured. Alert email will not be sent.');
                return;
            }

            // Additional verification to ensure recipients are valid
            $validRecipients = false;
            $emailRecipients = explode(',', $recipients);
            foreach ($emailRecipients as $recipient) {
                $recipient = trim($recipient);
                if (!empty($recipient) && filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
                    $validRecipients = true;
                    break;
                }
            }

            if (!$validRecipients) {
                $this->logger->warning('No valid email address found in configuration. Alert email will not be sent.');
                return;
            }

            $this->inlineTranslation->suspend();

            $detailedReport = $this->generateDetailedReport($suspiciousBlocks);
            $emailSender = $this->scopeConfig->getValue(
                'security_scanner/email_notification/email_sender',
                \Magento\Store\Model\ScopeInterface::SCOPE_STORE,
                $storeId
            );

            if (empty($emailSender)) {
                $emailSender = 'general';
            }

            foreach ($emailRecipients as $recipient) {
                $recipient = trim($recipient);
                if (empty($recipient) || !filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
                    continue;
                }

                try {
                    $transport = $this->transportBuilder
                        ->setTemplateIdentifier('security_scan_alert')
                        ->setTemplateOptions([
                            'area' => \Magento\Framework\App\Area::AREA_ADMINHTML,
                            'store' => $storeId
                        ])
                        ->setTemplateVars([
                            'count' => count($suspiciousBlocks),
                            'details' => $detailedReport,
                            'store_name' => $this->storeManager->getStore()->getName()
                        ])
                        ->setFromByScope($emailSender, $storeId)  // Utiliser setFromByScope au lieu de setFrom
                        ->addTo($recipient)
                        ->getTransport();

                    $transport->sendMessage();
                    $this->logger->info('Security alert email sent to ' . $recipient);
                } catch (\Exception $e) {
                    $this->logger->error('Error sending email to ' . $recipient . ': ' . $e->getMessage());
                }
            }

            $this->inlineTranslation->resume();
        } catch (\Exception $e) {
            $this->logger->error('Error sending alert emails: ' . $e->getMessage());
        }
    }

    /**
     * Sends a Telegram notification
     *
     * @param array $suspiciousBlocks
     * @return void
     */
    protected function sendTelegramNotification($suspiciousBlocks)
    {
        // Check if Telegram notifications are enabled
        if (!$this->scopeConfig->isSetFlag('security_scanner/telegram_notification/enabled')) {
            return;
        }

        $botToken = $this->scopeConfig->getValue('security_scanner/telegram_notification/bot_token');
        $chatIds = $this->scopeConfig->getValue('security_scanner/telegram_notification/chat_id');

        if (empty($botToken) || empty($chatIds)) {
            $this->logger->warning('Incomplete Telegram configuration: missing token or chat ID');
            return;
        }

        $storeName = $this->storeManager->getStore()->getName();
        $scanDate = date('Y-m-d H:i:s');

        // Main message with alert
        $message = "🚨 *SECURITY ALERT* 🚨\n\n";
        $message .= "Store: *{$storeName}*\n";
        $message .= "Date: *{$scanDate}*\n";
        $message .= "Detection: *" . count($suspiciousBlocks) . " potentially malicious CMS blocks*\n\n";

        // Summary of detected elements
        foreach ($suspiciousBlocks as $index => $item) {
            if ($index >= 5) {
                $message .= "_(and " . (count($suspiciousBlocks) - 5) . " other blocks...)_\n";
                break;
            }

            $message .= "• CMS Block: *" . $item['identifier'] . "* (ID: " . $item['id'] . ")\n";
        }

        $message .= "\nCheck the administration for more details.";

        // Send the main message
        $this->sendTelegramMessage($botToken, $chatIds, $message);

        // Create a second message with details of the malicious code
        foreach ($suspiciousBlocks as $index => $item) {
            $detailMessage = "📋 *DETECTION DETAILS* 📋\n\n";
            $detailMessage .= "Block: *" . $item['identifier'] . "* (ID: " . $item['id'] . ")\n";
            $detailMessage .= "Title: *" . $item['title'] . "*\n\n";
            $detailMessage .= "*Malicious code detected:*\n";

            foreach ($item['matches'] as $matchIdx => $match) {
                // Escape special Markdown characters
                $escapedCode = str_replace(
                    ['_', '*', '`', '[', ']'],
                    ['\_', '\*', '\`', '\[', '\]'],
                    $match['match']
                );

                // Limit length to avoid issues with Telegram
                if (strlen($escapedCode) > 800) {
                    $escapedCode = substr($escapedCode, 0, 800) . "...";
                }

                $detailMessage .= "```\n" . $escapedCode . "\n```\n";

                // Limit to 1 code example per block to avoid overloading
                if ($matchIdx >= 0) {
                    break;
                }
            }

            // Send the detailed message
            $this->sendTelegramMessage($botToken, $chatIds, $detailMessage);

            // Limit to 1 detailed block to avoid overloading
            if ($index >= 0) {
                break;
            }
        }
    }

    /**
     * Sends a message via the Telegram API
     *
     * @param string $botToken
     * @param string $chatIds
     * @param string $message
     * @return void
     */
    protected function sendTelegramMessage($botToken, $chatIds, $message)
    {
        // Send to all configured chats
        $chatIdList = explode(',', $chatIds);
        foreach ($chatIdList as $chatId) {
            $chatId = trim($chatId);
            if (empty($chatId)) {
                continue;
            }

            try {
                $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
                $this->curl->addHeader('Content-Type', 'application/json');
                $this->curl->post($url, json_encode([
                    'chat_id' => $chatId,
                    'text' => $message,
                    'parse_mode' => 'Markdown'
                ]));

                $response = json_decode($this->curl->getBody(), true);
                if (isset($response['ok']) && $response['ok']) {
                    $this->logger->info('Telegram message successfully sent to ' . $chatId);
                } else {
                    $this->logger->error('Error sending Telegram message: ' . json_encode($response));
                }
            } catch (\Exception $e) {
                $this->logger->error('Exception when sending Telegram message: ' . $e->getMessage());
            }
        }
    }

    /**
     * Generates a detailed report
     *
     * @param array $suspiciousBlocks
     * @return string
     */
    protected function generateDetailedReport($suspiciousBlocks)
    {
        $report = "Details of suspicious CMS blocks:\n\n";

        foreach ($suspiciousBlocks as $item) {
            $report .= "CMS Block #{$item['id']} ({$item['identifier']}): {$item['title']}\n";

            foreach ($item['matches'] as $match) {
                $report .= "- Suspicious code: " . htmlspecialchars($match['match']) . "\n";
            }

            $report .= "\n";
        }

        return $report;
    }

    /**
     * Sends clean reports if configured
     *
     * @return void
     */
    protected function sendCleanReports()
    {
        // Check for email
        if ($this->scopeConfig->isSetFlag('security_scanner/email_notification/enabled') &&
            $this->scopeConfig->isSetFlag('security_scanner/email_notification/send_clean_report')) {

            $this->sendCleanEmailReport();
        }

        // Check for Telegram
        if ($this->scopeConfig->isSetFlag('security_scanner/telegram_notification/enabled') &&
            $this->scopeConfig->isSetFlag('security_scanner/telegram_notification/send_clean_report')) {

            $this->sendCleanTelegramReport();
        }
    }

    /**
     * Sends a clean report by email
     *
     * @return void
     */
    protected function sendCleanEmailReport()
    {
        try {
            // Set the area code to avoid the "Area code is not set" error
            $this->setAreaCode();

            $storeId = $this->storeManager->getStore()->getId();
            $recipients = $this->scopeConfig->getValue(
                'security_scanner/email_notification/recipients',
                \Magento\Store\Model\ScopeInterface::SCOPE_STORE,
                $storeId
            );

            if (empty($recipients)) {
                return;
            }

            $this->inlineTranslation->suspend();

            $storeName = $this->storeManager->getStore()->getName();
            $scanDate = date('Y-m-d H:i:s');

            $emailRecipients = explode(',', $recipients);
            foreach ($emailRecipients as $recipient) {
                $recipient = trim($recipient);
                if (empty($recipient)) {
                    continue;
                }

                $transport = $this->transportBuilder
                    ->setTemplateIdentifier('security_scan_clean')
                    ->setTemplateOptions([
                        'area' => \Magento\Framework\App\Area::AREA_ADMINHTML,
                        'store' => $storeId
                    ])
                    ->setTemplateVars([
                        'store_name' => $storeName,
                        'scan_date' => $scanDate
                    ])
                    ->setFromByScope('general', $storeId)  // Use setFromByScope instead of setFrom
                    ->addTo($recipient)
                    ->getTransport();

                $transport->sendMessage();
            }

            $this->inlineTranslation->resume();

            $this->logger->info('Clean security report sent by email to ' . $recipients);
        } catch (\Exception $e) {
            $this->logger->error('Error sending clean report by email: ' . $e->getMessage());
        }
    }

    /**
     * Sends a clean report by Telegram
     *
     * @return void
     */
    protected function sendCleanTelegramReport()
    {
        $botToken = $this->scopeConfig->getValue('security_scanner/telegram_notification/bot_token');
        $chatIds = $this->scopeConfig->getValue('security_scanner/telegram_notification/chat_id');

        if (empty($botToken) || empty($chatIds)) {
            $this->logger->warning('Incomplete Telegram configuration: missing token or chat ID');
            return;
        }

        $storeName = $this->storeManager->getStore()->getName();
        $scanDate = date('Y-m-d H:i:s');

        $message = "✅ *SECURITY REPORT* ✅\n\n";
        $message .= "Store: *{$storeName}*\n";
        $message .= "Scan date: *{$scanDate}*\n\n";
        $message .= "No malicious code detected in CMS blocks during this scan.";

        // Send to all configured chats
        $chatIdList = explode(',', $chatIds);
        foreach ($chatIdList as $chatId) {
            $chatId = trim($chatId);
            if (empty($chatId)) {
                continue;
            }

            try {
                $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
                $this->curl->addHeader('Content-Type', 'application/json');
                $this->curl->post($url, json_encode([
                    'chat_id' => $chatId,
                    'text' => $message,
                    'parse_mode' => 'Markdown'
                ]));

                $this->logger->info('Clean security report sent by Telegram to ' . $chatId);
            } catch (\Exception $e) {
                $this->logger->error('Error sending clean report by Telegram: ' . $e->getMessage());
            }
        }
    }
}
