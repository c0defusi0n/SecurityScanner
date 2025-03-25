<?php
namespace C0defusi0n\SecurityScanner\Controller\Adminhtml\Telegram;

use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Framework\Controller\Result\JsonFactory;
use C0defusi0n\SecurityScanner\Helper\Telegram;

class Test extends Action
{
    /**
     * Authorization level
     */
    const ADMIN_RESOURCE = 'C0defusi0n_SecurityScanner::config';

    /**
     * @param Context $context
     * @param JsonFactory $resultJsonFactory
     * @param Telegram $telegramHelper
     */
    public function __construct(
        Context $context,
        protected JsonFactory $resultJsonFactory,
        protected Telegram $telegramHelper
    ) {
        parent::__construct($context);
    }

    /**
     * Test connection to Telegram
     *
     * @return \Magento\Framework\Controller\Result\Json
     */
    public function execute()
    {
        $result = $this->resultJsonFactory->create();

        $botToken = $this->getRequest()->getParam('bot_token');
        $chatId = $this->getRequest()->getParam('chat_id');

        try {
            $testResult = $this->telegramHelper->testConnection($botToken, $chatId);
            return $result->setData($testResult);
        } catch (\Exception $e) {
            return $result->setData([
                'success' => false,
                'message' => $e->getMessage()
            ]);
        }
    }
}
