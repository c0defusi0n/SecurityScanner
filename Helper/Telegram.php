<?php
namespace C0defusi0n\SecurityScanner\Helper;

use Magento\Framework\App\Helper\AbstractHelper;
use Magento\Framework\App\Helper\Context;
use Magento\Framework\HTTP\Client\Curl;
use Magento\Store\Model\ScopeInterface;
use Psr\Log\LoggerInterface;

class Telegram extends AbstractHelper
{
    const XML_PATH_TELEGRAM_ENABLED = 'security_scanner/telegram_notification/enabled';
    const XML_PATH_TELEGRAM_BOT_TOKEN = 'security_scanner/telegram_notification/bot_token';
    const XML_PATH_TELEGRAM_CHAT_ID = 'security_scanner/telegram_notification/chat_id';

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
     * Checks if Telegram notifications are enabled
     *
     * @param int|null $storeId
     * @return bool
     */
    public function isEnabled($storeId = null)
    {
        return $this->scopeConfig->isSetFlag(
            self::XML_PATH_TELEGRAM_ENABLED,
            ScopeInterface::SCOPE_STORE,
            $storeId
        );
    }

    /**
     * Gets the Telegram bot token
     *
     * @param int|null $storeId
     * @return string
     */
    public function getBotToken($storeId = null)
    {
        return $this->scopeConfig->getValue(
            self::XML_PATH_TELEGRAM_BOT_TOKEN,
            ScopeInterface::SCOPE_STORE,
            $storeId
        );
    }

    /**
     * Gets the Telegram chat IDs
     *
     * @param int|null $storeId
     * @return array
     */
    public function getChatIds($storeId = null)
    {
        $chatIds = $this->scopeConfig->getValue(
            self::XML_PATH_TELEGRAM_CHAT_ID,
            ScopeInterface::SCOPE_STORE,
            $storeId
        );

        if (empty($chatIds)) {
            return [];
        }

        return array_map('trim', explode(',', $chatIds));
    }

    /**
     * Sends a message via the Telegram API
     *
     * @param string $message
     * @param int|null $storeId
     * @param bool $markdown
     * @return bool
     */
    public function sendMessage($message, $storeId = null, $markdown = true)
    {
        if (!$this->isEnabled($storeId)) {
            return false;
        }

        $botToken = $this->getBotToken($storeId);
        $chatIds = $this->getChatIds($storeId);

        if (empty($botToken) || empty($chatIds)) {
            return false;
        }

        $success = true;

        foreach ($chatIds as $chatId) {
            if (empty($chatId)) {
                continue;
            }

            try {
                $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
                $this->curl->addHeader('Content-Type', 'application/json');
                $this->curl->post($url, json_encode([
                    'chat_id' => $chatId,
                    'text' => $message,
                    'parse_mode' => $markdown ? 'Markdown' : null
                ]));

                $response = json_decode($this->curl->getBody(), true);

                if (!isset($response['ok']) || !$response['ok']) {
                    $this->logger->error('Telegram Error: ' . json_encode($response));
                    $success = false;
                }
            } catch (\Exception $e) {
                $this->logger->error('Telegram Exception: ' . $e->getMessage());
                $success = false;
            }
        }

        return $success;
    }

    /**
     * Sends a module installation notification
     *
     * @param int|null $storeId
     * @return bool
     */
    public function sendSetupNotification($storeId = null)
    {
        $message = "🔒 *C0defusi0n Security Scanner* 🔒\n\n";
        $message .= "The security module has been successfully installed and is now configured to send notifications to this chat.\n\n";
        $message .= "Module version: *1.0.0*\n";
        $message .= "Installation date: *" . date('Y-m-d H:i:s') . "*\n\n";
        $message .= "You will receive notifications if malicious code is detected on your Magento site.";

        return $this->sendMessage($message, $storeId);
    }

    /**
     * Tests the connection to the Telegram bot
     *
     * @param string $botToken
     * @param string $chatId
     * @return array
     */
    public function testConnection($botToken, $chatId)
    {
        if (empty($botToken) || empty($chatId)) {
            return [
                'success' => false,
                'message' => 'Bot token and chat ID are required.'
            ];
        }

        try {
            $message = "✅ *Connection test successful* ✅\n\n";
            $message .= "The C0defusi0n Security Scanner is correctly configured to send notifications to this chat.";

            $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
            $this->curl->addHeader('Content-Type', 'application/json');
            $this->curl->post($url, json_encode([
                'chat_id' => $chatId,
                'text' => $message,
                'parse_mode' => 'Markdown'
            ]));

            $response = json_decode($this->curl->getBody(), true);

            if (isset($response['ok']) && $response['ok']) {
                return [
                    'success' => true,
                    'message' => 'Test successful! A message has been sent to the Telegram chat.'
                ];
            } else {
                return [
                    'success' => false,
                    'message' => 'Error: ' . (isset($response['description']) ? $response['description'] : 'Invalid response from the Telegram API.')
                ];
            }
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => 'Exception: ' . $e->getMessage()
            ];
        }
    }
}
