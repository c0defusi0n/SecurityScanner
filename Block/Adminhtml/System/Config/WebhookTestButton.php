<?php
namespace C0defusi0n\SecurityScanner\Block\Adminhtml\System\Config;

use Magento\Config\Block\System\Config\Form\Field;
use Magento\Framework\Data\Form\Element\AbstractElement;

class WebhookTestButton extends Field
{
    /**
     * @var string
     */
    protected $_template = 'C0defusi0n_SecurityScanner::system/config/webhook_test_button.phtml';

    /**
     * @param AbstractElement $element
     * @return string
     */
    public function render(AbstractElement $element)
    {
        $element->unsScope()->unsCanUseWebsiteValue()->unsCanUseDefaultValue();
        return parent::render($element);
    }

    /**
     * @param AbstractElement $element
     * @return string
     */
    protected function _getElementHtml(AbstractElement $element)
    {
        return $this->_toHtml();
    }

    /**
     * @return string
     */
    public function getAjaxUrl()
    {
        return $this->getUrl('c0defusi0n_security/webhook/test');
    }

    /**
     * @return string
     */
    public function getButtonHtml()
    {
        return $this->getLayout()
            ->createBlock(\Magento\Backend\Block\Widget\Button::class)
            ->setData([
                'id' => 'webhook_test_button',
                'label' => __('Test Webhook'),
                'class' => 'webhook-test-button',
            ])
            ->toHtml();
    }
}
