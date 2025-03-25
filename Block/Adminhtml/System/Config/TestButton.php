<?php
namespace C0defusi0n\SecurityScanner\Block\Adminhtml\System\Config;

use Magento\Backend\Block\Template\Context;
use Magento\Config\Block\System\Config\Form\Field;
use Magento\Framework\Data\Form\Element\AbstractElement;

class TestButton extends Field
{
    /**
     * @var string
     */
    protected $_template = 'Retif_SecurityScanner::system/config/test_button.phtml';

    /**
     * Removes the scope
     *
     * @param AbstractElement $element
     * @return string
     */
    public function render(AbstractElement $element)
    {
        $element->unsScope()->unsCanUseWebsiteValue()->unsCanUseDefaultValue();
        return parent::render($element);
    }

    /**
     * Renders the HTML button
     *
     * @param AbstractElement $element
     * @return string
     */
    protected function _getElementHtml(AbstractElement $element)
    {
        return $this->_toHtml();
    }

    /**
     * Gets the controller URL
     *
     * @return string
     */
    public function getAjaxUrl()
    {
        return $this->getUrl('retif_security/telegram/test');
    }

    /**
     * Gets the HTML button
     *
     * @return string
     */
    public function getButtonHtml()
    {
        $button = $this->getLayout()->createBlock(
            \Magento\Backend\Block\Widget\Button::class
        )->setData([
            'id' => 'telegram_test_button',
            'label' => __('Test Connection'),
            'class' => 'telegram-test-button'
        ]);

        return $button->toHtml();
    }
}
