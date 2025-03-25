<?php
namespace C0defusi0n\SecurityScanner\Test\Unit\Model\Config\Source;

use C0defusi0n\SecurityScanner\Model\Config\Source\ScanFrequency;
use Magento\Framework\TestFramework\Unit\Helper\ObjectManager;
use PHPUnit\Framework\TestCase;

class ScanFrequencyTest extends TestCase
{
    /**
     * @var ScanFrequency
     */
    private $scanFrequency;

    /**
     * Set up the test
     */
    protected function setUp(): void
    {
        $objectManager = new ObjectManager($this);
        $this->scanFrequency = $objectManager->getObject(ScanFrequency::class);
    }

    /**
     * Test toOptionArray method
     */
    public function testToOptionArray()
    {
        $result = $this->scanFrequency->toOptionArray();
        
        $this->assertIsArray($result);
        $this->assertNotEmpty($result);
        
        // Check for required frequency options
        $foundOptions = [];
        foreach ($result as $option) {
            $this->assertArrayHasKey('value', $option);
            $this->assertArrayHasKey('label', $option);
            $foundOptions[] = $option['value'];
        }
        
        // Verify that common frequency options are present
        $expectedOptions = ['hourly', 'daily', 'weekly', 'monthly'];
        foreach ($expectedOptions as $expectedOption) {
            $this->assertContains($expectedOption, $foundOptions, "Option '$expectedOption' is missing");
        }
    }

    /**
     * Test toArray method
     */
    public function testToArray()
    {
        $result = $this->scanFrequency->toArray();
        
        $this->assertIsArray($result);
        $this->assertNotEmpty($result);
        
        // Verify that common frequency options are present as keys
        $expectedOptions = ['hourly', 'daily', 'weekly', 'monthly'];
        foreach ($expectedOptions as $expectedOption) {
            $this->assertArrayHasKey($expectedOption, $result, "Option '$expectedOption' is missing");
        }
    }
}
