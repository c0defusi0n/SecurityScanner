<?php
namespace C0defusi0n\SecurityScanner\Controller\Adminhtml\Webhook;

use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Framework\Controller\Result\JsonFactory;
use C0defusi0n\SecurityScanner\Helper\Webhook;

class Test extends Action
{
    /**
     * Authorization level
     */
    const ADMIN_RESOURCE = 'C0defusi0n_SecurityScanner::config';

    /**
     * @param Context $context
     * @param JsonFactory $resultJsonFactory
     * @param Webhook $webhookHelper
     */
    public function __construct(
        Context $context,
        protected JsonFactory $resultJsonFactory,
        protected Webhook $webhookHelper
    ) {
        parent::__construct($context);
    }

    /**
     * Test the configured webhook
     *
     * @return \Magento\Framework\Controller\Result\Json
     */
    public function execute()
    {
        $result = $this->resultJsonFactory->create();
        $url = $this->getRequest()->getParam('url');

        try {
            return $result->setData($this->webhookHelper->testConnection($url));
        } catch (\Exception $e) {
            return $result->setData(['success' => false, 'message' => $e->getMessage()]);
        }
    }
}
