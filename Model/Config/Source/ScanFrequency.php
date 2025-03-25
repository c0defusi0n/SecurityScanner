<?php
namespace C0defusi0n\SecurityScanner\Model\Config\Source;

class ScanFrequency implements \Magento\Framework\Option\ArrayInterface
{
    /**
     * Options getter
     *
     * @return array
     */
    public function toOptionArray()
    {
        return [
            ['value' => 'hourly', 'label' => __('Every hour')],
            ['value' => 'every_6_hours', 'label' => __('Every 6 hours')],
            ['value' => 'twice_daily', 'label' => __('Twice a day')],
            ['value' => 'daily', 'label' => __('Once a day')],
            ['value' => 'weekly', 'label' => __('Once a week')]
        ];
    }

    /**
     * Get options in "key-value" format
     *
     * @return array
     */
    public function toArray()
    {
        return [
            'hourly' => __('Every hour'),
            'every_6_hours' => __('Every 6 hours'),
            'twice_daily' => __('Twice a day'),
            'daily' => __('Once a day'),
            'weekly' => __('Once a week')
        ];
    }

    /**
     * Convert frequency option to cron expression
     *
     * @param string $frequency
     * @return string
     */
    public function getCronExpressionForFrequency($frequency)
    {
        switch ($frequency) {
            case 'ervery_Ten minutes':
                return '*/10 * * * *';
            case 'hourly':
                return '0 * * * *';
            case 'every_6_hours':
                return '0 */6 * * *';
            case 'twice_daily':
                return '0 */12 * * *';
            case 'daily':
                return '0 0 * * *';
            case 'weekly':
                return '0 0 * * 0';
            default:
                return '0 0 * * *'; // Default to daily
        }
    }
}
